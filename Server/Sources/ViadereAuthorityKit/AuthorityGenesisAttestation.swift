import Fluent
import Foundation
import Vapor
import ViadereCore
import ViadereServiceSupport

// App Attest at key-log genesis (ADR-0023 §4 `genesis`, ADR-0032 §1.3). The authority holds no attested App Attest key of its own before the account
// exists, and an App Attest key the **api** attested would be the api's word, so the device sends a fresh **attestation** whose `clientDataHash`
// binds the authority's single-use genesis nonce and every key of the entry (`AuthorityKeyLogFormat.genesisAttestationClientData`). The authority
// verifies it against Apple's root itself (`AppAttestAttestation`, the same checks as the api's enrollment), accepts each App Attest key once, and
// records the result in the genesis entries and on the keys (`hardware_attested`).

/// `integrity: {key_id, attestation}`: strict unpadded base64url, a 32-byte key id and a CBOR attestation object of at most 12 KiB.
struct GenesisIntegrity: Sendable {
    let keyId: Data
    let attestation: Data

    static func parse(_ value: JSONValue?) -> GenesisIntegrity?? {
        guard let value else { return .some(nil) }
        guard let o = value.objectValue, Set(o.keys) == ["key_id", "attestation"],
              let keyId = o["key_id"]?.stringValue.flatMap({ AuthorityKeyLogFormat.strictBytes($0, minBytes: 32, maxBytes: 32) }),
              let attestation = o["attestation"]?.stringValue.flatMap({ AuthorityKeyLogFormat.strictBytes($0, maxBytes: 12 * 1024) }) else { return nil }
        return .some(GenesisIntegrity(keyId: keyId, attestation: attestation))
    }
}

struct GenesisAttestation {
    let ctx: AuthorityContext
    let db: any Database

    struct Outcome: Sendable {
        let attested: Bool
        let reason: String
        let keyId: String?
    }

    /// The App Attest verifier of this deployment: Apple's root only, unless a development or test override supplied another.
    static func verifier(config: AuthorityConfig, override: AppAttestAttestation?) throws -> AppAttestAttestation {
        if let override {
            guard !config.deployment.isStrict else { throw AuthorityConfigError.refused("an App Attest root override in staging or production") }
            return override
        }
        return AppAttestAttestation(trustedRoots: [try AppleAppAttestRoot.certificate()],
                                    aaguid: config.appAttestProduction ? AppAttestAttestation.productionAAGUID : AppAttestAttestation.developmentAAGUID)
    }

    /// Verifies the genesis attestation (when sent; `off` and `report` accept a genesis without one). `require`: anything but a verified, unused
    /// attestation is `403 attestation_required`, audited with its reason.
    func check(_ value: JSONValue?, nonce: String, kids: [String], caller: AuthorityCaller?) async throws -> Outcome {
        let mode = ctx.config.appAttestMode
        func outcome(_ attested: Bool, _ reason: String, _ keyId: String? = nil) async throws -> Outcome {
            if !attested, mode == .require {
                await AuthorityAudit.record(db, "authority.genesis", outcome: "denied", reason: "attestation_\(reason)", caller: caller?.name, at: ctx.now)
                throw Abort(.forbidden, reason: "attestation_required")
            }
            return Outcome(attested: attested, reason: reason, keyId: keyId)
        }
        guard let parsed = GenesisIntegrity.parse(value) else { return try await outcome(false, AppAttestFailure.malformedObject.rawValue) }
        guard let integrity = parsed else { return try await outcome(false, AppAttestFailure.notProvided.rawValue) }
        guard let verifier = ctx.appAttest else { return try await outcome(false, "unavailable") }
        let clientDataHash = AuthorityKeyLogFormat.genesisAttestationClientDataHash(environment: ctx.environment, nonce: nonce, kids: kids)
        do {
            _ = try await verifier.verify(object: integrity.attestation, keyId: integrity.keyId, clientDataHash: clientDataHash,
                                          rpIdHash: AppAttestAttestation.rpIdHash(teamID: ctx.config.appleTeamID, bundleID: ctx.config.appBundleID), now: ctx.now)
        } catch let failure as AppAttestFailure {
            return try await outcome(false, failure.rawValue)
        } catch {
            return try await outcome(false, AppAttestFailure.malformedObject.rawValue)
        }
        let keyId = Hex.encode(integrity.keyId)
        // One genesis per App Attest key: a genuine device cannot vouch for a stream of accounts with one attestation key.
        guard try await AuthorityAppAttestKey.find(keyId, on: db) == nil else { return try await outcome(false, "key_reused") }
        return try await outcome(true, "verified", keyId)
    }

    /// Inside the genesis transaction: the App Attest key is taken (its primary key refuses a concurrent second genesis with it).
    static func record(_ tx: any Database, _ outcome: Outcome, accountRef: String, production: Bool, now: Date) async throws {
        guard outcome.attested, let keyId = outcome.keyId else { return }
        let row = AuthorityAppAttestKey()
        row.id = keyId
        row.accountRef = accountRef
        row.environment = production ? "production" : "development"
        row.createdAt = now
        try await row.create(on: tx)
    }
}

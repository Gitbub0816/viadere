@preconcurrency import Crypto
import _CryptoExtras
import Fluent
import Foundation
import SQLKit
import Vapor
import ViadereCore
import ViadereServiceSupport

// The two seal constructions behind one switch (ADR-0034): `hpke` (lean default, the seal private key unwrapped into memory at start, R-23) and
// `jwe-rsa` (§9: compact JWE `RSA-OAEP-256` + `A256GCM` to `recovery-seal-rsa`, decrypted by Key Vault, at most once per challenge). Only the
// configured construction is accepted; an envelope of the other one is malformed.

/// A parsed envelope of the configured construction, before anything is opened.
enum ParsedSeal: Sendable {
    case hpke(RecoverySealEnvelope)
    case jwe(RecoverySealJWE.Envelope)

    /// What the authorizing factor JWS (`envelope_digest`) or every new key's PoP commits to.
    var digest: String {
        switch self {
        case .hpke(let envelope): envelope.digest
        case .jwe(let envelope): envelope.digest
        }
    }
}

/// Why an envelope was refused (the audit reason; the caller always answers `401 evidence_invalid`).
struct SealRefusal: Error { let reason: String }

/// A plaintext and what opened it. `consumedFrom` is the challenge state the caller swaps to `used`: `pending` (HPKE opens in memory) or `opening`
/// (JWE: the challenge moved `pending → opening` before the one Key Vault `decrypt`).
struct OpenedSeal: Sendable {
    let plaintext: [String: JSONValue]
    let sealKid: String
    let consumedFrom: String
}

extension AuthorityRecoveryService {
    /// The configured construction has its key: an unwrapped, app-pinned HPKE key inside its lifetime, or the app-pinned `recovery-seal-rsa`.
    func requireSealAvailable() throws {
        guard ctx.config.recoveryEnabled else { throw Abort(.notFound) }
        switch ctx.config.recoverySeal {
        case .hpke: _ = try requireSeal()
        case .jweRSA: guard ctx.rsaSeal != nil else { throw Abort(.serviceUnavailable, reason: "recovery_unavailable") }
        }
    }

    /// The `kid` sets are sealed to now (heads: `recovery_set` is `active` only for sets under it).
    var activeSealKid: String? {
        switch ctx.config.recoverySeal {
        case .hpke: ctx.seal?.kid
        case .jweRSA: ctx.rsaSeal?.kid
        }
    }

    /// HPKE: the `{v, kid, enc, ct}` object. JWE: the compact serialization as a JSON string. Anything else (including the other construction) is `nil`.
    func parseSeal(_ value: JSONValue?) -> ParsedSeal? {
        switch ctx.config.recoverySeal {
        case .hpke:
            guard let value, let envelope = try? RecoverySealEnvelope.parse(value) else { return nil }
            return .hpke(envelope)
        case .jweRSA:
            guard case .string(let compact)? = value, let envelope = try? RecoverySealJWE.parse(compact) else { return nil }
            return .jwe(envelope)
        }
    }

    /// Opens a parsed envelope for `challenge` (its purpose, environment, id and nonce). JWE (ADR-0034 §9.3): every header check first, then the
    /// challenge moves `pending → opening` by compare-and-swap (so a second envelope for it is refused), a decrypt record `{ach, kid}` is written,
    /// and only then is the one Key Vault `decrypt` made. Every failure is the same refusal to the caller.
    func openSeal(_ parsed: ParsedSeal, purpose: RecoverySealPurpose, challenge: AuthorityChallenge) async throws -> OpenedSeal {
        switch parsed {
        case .hpke(let envelope):
            let seal = try requireSeal()
            guard ConstantTime.equals(envelope.kid, seal.kid) else { throw SealRefusal(reason: "seal_kid") }
            do {
                let plaintext = try RecoverySeal.open(envelope, with: seal.privateKey, purpose: purpose, environment: ctx.environment, challengeId: challenge.id!,
                                                      nonce: challenge.nonce)
                return OpenedSeal(plaintext: plaintext, sealKid: seal.kid, consumedFrom: "pending")
            } catch { throw SealRefusal(reason: "envelope_open_failed") }
        case .jwe(let envelope):
            guard let seal = ctx.rsaSeal else { throw Abort(.serviceUnavailable, reason: "recovery_unavailable") }
            do {
                try RecoverySealJWE.check(envelope, kid: seal.kid, purpose: purpose, environment: ctx.environment, challengeId: challenge.id!, nonce: challenge.nonce)
            } catch RecoverySealError.wrongKey {
                throw SealRefusal(reason: "seal_kid")
            } catch { throw SealRefusal(reason: "envelope_binding") }
            guard try await swapState(challenge.id!, from: "pending", to: "opening") else { throw SealRefusal(reason: "challenge_not_pending") }
            var contentKey: Data
            do { contentKey = try await seal.contentKey(of: envelope, challengeId: challenge.id!, through: ctx.kms) } catch {
                throw SealRefusal(reason: "envelope_open_failed")
            }
            defer { contentKey.resetBytes(in: 0..<contentKey.count) }
            do {
                return OpenedSeal(plaintext: try RecoverySealJWE.open(envelope, contentKey: contentKey), sealKid: seal.kid, consumedFrom: "opening")
            } catch { throw SealRefusal(reason: "envelope_open_failed") }
        }
    }

    /// `from → to`, exactly once.
    func swapState(_ id: String, from: String, to: String) async throws -> Bool {
        guard let sql = db as? any SQLDatabase else { return false }
        return try await sql.update(AuthorityChallenge.schema).set("state", to: to).set("used_at", to: ctx.now).where("id", .equal, id).where("state", .equal, from)
            .returning("id").all().count == 1
    }
}

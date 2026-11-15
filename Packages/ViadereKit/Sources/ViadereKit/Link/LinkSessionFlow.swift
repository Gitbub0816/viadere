import Crypto
import Foundation
import ViadereCore

/// The device side of business link sessions (`/v1/link-sessions/...`). Separate from `ApproveAPI` so existing fakes keep compiling.
public protocol LinkSessionAPI: Sendable {
    func lookupLink(code: String) async throws -> LinkSessionOffer
    func completeLink(id: UUID, request: CompleteLinkSessionRequest) async throws -> LinkSessionDeviceView
    func linkSession(id: UUID) async throws -> LinkSessionDeviceView
}

extension LiveApproveAPI: LinkSessionAPI {
    public func lookupLink(code: String) async throws -> LinkSessionOffer {
        try await client.call(APIRoutes.linkSessionLookup, body: LinkSessionLookupRequest(code: code))
    }
    public func completeLink(id: UUID, request: CompleteLinkSessionRequest) async throws -> LinkSessionDeviceView {
        try await client.call(APIRoutes.linkSessionComplete, params: ["sessionId": id.uuidString.lowercased()], body: request)
    }
    public func linkSession(id: UUID) async throws -> LinkSessionDeviceView {
        try await client.call(APIRoutes.linkSessionGet, params: ["sessionId": id.uuidString.lowercased()])
    }
}

public enum LinkError: Error, Equatable, Sendable {
    /// The build pins no `link-descriptor` key (or no transparency-log key): linking fails closed.
    case notConfigured
    /// Neither the QR's secret nor the business's check code: the business could not tell this phone's statement from a forged one.
    case secretRequired
    /// The descriptor is not signed by a pinned Viadere key, has expired, or does not match what the relay said around it.
    case descriptorInvalid(LinkSessionError)
    /// The business's key directory names another root than the descriptor, or has no confirmation key.
    case businessMismatch
    case businessNotReady
    case api(APIError)
    case directory(ApproveError)
    case deviceCannotSatisfy
    case userCancelled
    case keysUnavailable
    /// The business confirmed a statement that is not this phone's: the link and its key were removed.
    case substitutionDetected
    case expired
}

/// What the person sees before linking: **only values from the verified descriptor**, plus the account pseudonym and the warning.
public struct LinkOffer: Sendable, Equatable {
    public var offer: LinkSessionOffer
    public var descriptor: LinkSessionDescriptor
    public var descriptorDigest: String
    public var rootFingerprint: String
    public var secret: LinkSessionSecret?
    public var checkCode: String?

    public var businessName: String { descriptor.businessName }
    public var businessDomain: String { descriptor.businessDomain }
    public var capabilities: [Capability] { descriptor.capabilities }
    public var displayHint: String { descriptor.displayHint }
    /// "Your account at {business}": the same eight characters the business shows next to the six digits.
    public var pseudonym: String { LinkPseudonym.make(descriptor.subject) }
    public var requiredAssurance: ApprovalAMR? { LinkCapabilities.requiredAssurance(descriptor.capabilities) }
    /// Session swapping (§2.12): the person must only scan a code they opened themselves, in the business's own signed-in page.
    public var warning: String {
        let place = descriptor.businessDomain.isEmpty ? descriptor.businessName : descriptor.businessDomain
        return "Only scan a code you opened yourself, signed in on \(place). If someone sent you this code, stop."
    }

    public static func == (lhs: LinkOffer, rhs: LinkOffer) -> Bool { lhs.offer == rhs.offer && lhs.secret == rhs.secret && lhs.checkCode == rhs.checkCode }
}

/// A link this phone completed, kept until the business confirms (or the window ends).
public struct LocalLink: Codable, Sendable, Equatable, Identifiable {
    public enum Status: String, Codable, Sendable { case waiting, linked, ended }
    public var id: UUID { sessionId }
    public var sessionId: UUID
    public var businessId: BusinessID
    public var businessName: String
    public var subject: SubjectRef
    public var statement: SignedStatement
    /// The six digits the person compares or types in the business's page.
    public var sas: String?
    public var confirmBy: Date
    public var status: Status
}

/// What the person sees after linking: the six digits and the pseudonym to compare in the business's page.
public struct LinkCompletion: Sendable, Equatable {
    public var sessionId: UUID
    public var businessName: String
    public var sas: String?
    public var pseudonym: String
    public var confirmBy: Date
}

public enum LinkOutcome: Sendable, Equatable {
    case waiting
    case linked
    case expired
    case substitutionDetected
}

/// Produces an App Attest assertion (base64url) over client data, for a device enrolled with an attested key; `nil` when it cannot (Simulator,
/// no key). The server decides whether one is required (`APP_ATTEST_ASSERTION_MODE`).
public typealias AssertionSource = @Sendable (_ clientData: Data) async -> String?

/// Business link sessions on the device (WP-C1, `docs/SECURITY.md` §2.59).
///
/// 1. `lookup`: fetch the session's descriptor, **verify Viadere's signature with the pinned `link-descriptor` keys**, check it agrees with what
///    the relay said around it, and cross-check the business against its verified key directory (root key id, confirmation key).
/// 2. `link`: the person confirmed. For approval capabilities, create the pairwise approval and HPKE keys and sign the ordinary enrollment statement
///    (Face ID); sign the link statement with a fresh pairwise connection key; attach the binding tag (QR) and compute the SAS; complete.
/// 3. `refresh`: once the business confirmed, verify its confirmation against the directory and this phone's own statement. The approval key itself
///    is activated by `ApproveEnrollmentFlow.refreshConfirmations` (its enrollment id is the session id).
public struct LinkSessionFlow: Sendable {
    private let api: any LinkSessionAPI
    private let approve: ApproveEnvironment
    private let descriptorKeys: [DevicePublicKey]
    private let local: LinkLocalStore
    private let assertion: AssertionSource?
    private let clock: @Sendable () -> Date

    public init(api: any LinkSessionAPI, approve: ApproveEnvironment, descriptorKeys: [DevicePublicKey], secrets: any SecretStore = InMemorySecretStore(),
                assertion: AssertionSource? = nil, clock: @escaping @Sendable () -> Date = { Date() }) {
        self.api = api
        self.approve = approve
        self.descriptorKeys = descriptorKeys
        local = LinkLocalStore(secrets: secrets)
        self.assertion = assertion
        self.clock = clock
    }

    public var isConfigured: Bool { !descriptorKeys.isEmpty && approve.isConfigured }

    public func lookup(code: String, secret: LinkSessionSecret? = nil, checkCode: String? = nil) async throws -> LinkOffer {
        guard isConfigured else { throw LinkError.notConfigured }
        let canonicalCheck = checkCode.flatMap { LinkSessionCode.canonical($0) }
        guard secret != nil || canonicalCheck != nil else { throw LinkError.secretRequired }
        let offer: LinkSessionOffer
        do { offer = try await api.lookupLink(code: code) } catch let error as APIError { throw LinkError.api(error) }
        let descriptor: LinkSessionDescriptor
        do { descriptor = try LinkSessionDescriptor.verify(offer.descriptor, trustedKeys: descriptorKeys, now: clock()) } catch let error as LinkSessionError {
            throw LinkError.descriptorInvalid(error)
        }
        // The unsigned members around the descriptor must agree with it; only the descriptor is shown.
        guard descriptor.sessionId == offer.sessionId, descriptor.businessId == offer.business.id, descriptor.subject == offer.subjectRef,
              descriptor.capabilities.map(\.rawValue) == LinkCapabilities.canonical(offer.capabilities).map(\.rawValue) else {
            throw LinkError.descriptorInvalid(.statementMismatch)
        }
        // Cross-check with the business's own key directory: the root the descriptor names is the one the log shows, and the business can confirm.
        let check: DirectoryCheck
        do { check = try await approve.directory.verify(businessId: descriptor.businessId, expectedRootKid: descriptor.rootKid) } catch let error as ApproveError {
            if case .rootMismatchWithLink = error { throw LinkError.businessMismatch }
            throw LinkError.directory(error)
        }
        guard !check.state.validKeys(for: .approvalEnrollmentConfirmation, at: clock()).isEmpty else { throw LinkError.businessNotReady }
        return LinkOffer(offer: offer, descriptor: descriptor, descriptorDigest: LinkSessionDescriptor.digest(of: offer.descriptor), rootFingerprint: check.rootFingerprint,
                         secret: secret, checkCode: canonicalCheck)
    }

    @discardableResult
    public func link(_ offer: LinkOffer) async throws -> LinkCompletion {
        guard offer.secret != nil || offer.checkCode != nil else { throw LinkError.secretRequired }
        let d = offer.descriptor
        guard d.expiresAtDate > clock() else { throw LinkError.expired }
        var approvalSigned: SignedStatement?
        var approval: ApprovalEnrollmentStatement?
        if let assurance = offer.requiredAssurance {
            let key: any ManagedSigningKey
            do { key = try await approve.vault.createApprovalKey(enrollment: d.sessionId, assurance: assurance) } catch { throw LinkError.deviceCannotSatisfy }
            do {
                let hpke = try await approve.vault.createHPKEKey(enrollment: d.sessionId)
                let statement = try ApprovalEnrollmentStatement(businessId: d.businessId, subject: d.subject, enrollmentId: d.sessionId, publicKey: key.publicKey,
                                                                hpkePublicKey: hpke.publicKey, assurance: assurance, createdAt: clock())
                approvalSigned = try await statement.sign(with: PromptBoundKey(key, prompt: SigningPrompt(reason: "Link \(d.businessName) to Viadere")))
                approval = statement
            } catch {
                try? await approve.vault.delete(enrollment: d.sessionId)
                throw Self.mapKeyError(error)
            }
        }
        do {
            // A fresh pairwise connection key: never derived from a device or account key, so no two businesses can correlate it.
            let connection = SoftwareP256SigningKey()
            let statement = try LinkStatement(sessionId: d.sessionId, businessId: d.businessId, subject: d.subject, capabilities: d.capabilities,
                                              descriptorDigest: offer.descriptorDigest, publicKey: connection.publicKey, approvalStatement: approvalSigned, createdAt: clock())
            let signed = try await statement.sign(with: connection)
            let tag = offer.secret?.bindingTag(for: signed)
            let checkCode = offer.secret?.checkCode ?? offer.checkCode
            let sas = checkCode.flatMap { LinkSAS.compute(checkCode: $0, statement: signed) }
            let assertionValue = await assertion?(LinkAppAttest.clientData(sessionId: d.sessionId, statement: signed))
            let view: LinkSessionDeviceView
            do {
                view = try await api.completeLink(id: d.sessionId, request: CompleteLinkSessionRequest(statement: signed, bindingTag: tag, approvalStatement: approvalSigned,
                                                                                                       appAttestAssertion: assertionValue))
            } catch let error as APIError { throw LinkError.api(error) }
            let confirmBy = view.confirmBy
            if let approval, let approvalSigned {
                let pending = LocalApprovalKey(enrollmentId: d.sessionId, kid: approval.kid, hpkeKid: approval.hpkePublicKey.kid, businessId: d.businessId, businessName: d.businessName,
                                               relationshipId: view.connection?.relationshipId ?? RelationshipID(), subject: d.subject, assurance: approval.assurance,
                                               statement: approvalSigned, status: .pendingConfirmation, createdAt: clock(), confirmBy: confirmBy, verificationCode: nil)
                try await approve.store.update { $0.keys.removeAll { $0.enrollmentId == pending.enrollmentId }; $0.keys.append(pending) }
            }
            let link = LocalLink(sessionId: d.sessionId, businessId: d.businessId, businessName: d.businessName, subject: d.subject, statement: signed, sas: sas,
                                 confirmBy: confirmBy, status: .waiting)
            try await local.update { $0.removeAll { $0.sessionId == link.sessionId }; $0.append(link) }
            return LinkCompletion(sessionId: d.sessionId, businessName: d.businessName, sas: sas, pseudonym: offer.pseudonym, confirmBy: confirmBy)
        } catch {
            if approval != nil { try? await approve.vault.delete(enrollment: d.sessionId) }
            if let known = error as? LinkError { throw known }
            throw Self.mapKeyError(error)
        }
    }

    /// Checks the business's confirmation of one link against the directory and this phone's statement.
    public func refresh(sessionId: UUID) async throws -> LinkOutcome {
        guard let link = try await local.load().first(where: { $0.sessionId == sessionId }) else { return .expired }
        if link.status == .linked { return .linked }
        let view: LinkSessionDeviceView
        do { view = try await api.linkSession(id: sessionId) } catch let error as APIError {
            if error.code == .notFound { try await finish(link, as: .ended); return .expired }
            throw LinkError.api(error)
        }
        switch view.status {
        case .expired, .cancelled:
            try await finish(link, as: .ended)
            return .expired
        case .confirmed:
            guard let confirmation = view.confirmation else { return .waiting }
            do {
                let check = try await approve.directory.verify(businessId: link.businessId)
                guard let key = check.state.validKey(kid: confirmation.kid, purpose: .approvalEnrollmentConfirmation, at: clock())?.signingKey else { throw LinkSessionError.keyMismatch }
                let parsed = try LinkConfirmation.verify(confirmation, confirmationKey: key)
                try parsed.checkMatches(try LinkStatement.verify(link.statement), signed: link.statement)
            } catch is LinkSessionError {
                // The business confirmed something this phone did not sign: drop the link and the approval key it carried.
                try await finish(link, as: .ended)
                if let kid = try await approve.store.load().keys.first(where: { $0.enrollmentId == sessionId })?.kid { try? await approve.enrollment.revoke(kid: kid) }
                return .substitutionDetected
            } catch let error as ApproveError {
                throw LinkError.directory(error)
            }
            try await finish(link, as: .linked)
            return .linked
        default:
            if clock() > link.confirmBy { try await finish(link, as: .ended); return .expired }
            return .waiting
        }
    }

    public func pending() async throws -> [LocalLink] { try await local.load().filter { $0.status == .waiting } }

    private func finish(_ link: LocalLink, as status: LocalLink.Status) async throws {
        try await local.update { links in
            if let index = links.firstIndex(where: { $0.sessionId == link.sessionId }) { links[index].status = status; links[index].sas = nil }
            links = Array(links.suffix(50))
        }
    }

    static func mapKeyError(_ error: any Error) -> LinkError {
        if let keyError = error as? KeyStoreError {
            switch keyError {
            case .userCancelled: return .userCancelled
            default: return .keysUnavailable
            }
        }
        return .keysUnavailable
    }
}

/// Completed links kept on the device (statement for verifying the business's confirmation, the SAS to show). Never synced.
actor LinkLocalStore {
    private let slot: JSONSecretSlot<[LocalLink]>

    init(secrets: any SecretStore, account: String = "link.sessions.v1") { slot = JSONSecretSlot(secrets: secrets, account: account) }

    func load() throws -> [LocalLink] { try slot.load() ?? [] }

    func update(_ change: @Sendable (inout [LocalLink]) -> Void) throws {
        var links = try slot.load() ?? []
        change(&links)
        try slot.save(links)
    }
}

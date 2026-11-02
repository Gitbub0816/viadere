import Foundation
import ViadereCore

/// The device side of verification sessions — what happens when a business's "Verify with Viadere" button (QR, universal link or typed code)
/// opens the app (`docs/VERIFY-BUTTON.md`, `docs/SECURITY.md` §2.60). Separate from `VerifyAPI` so existing fakes keep compiling.
public protocol VerificationSessionAPI: Sendable {
    func lookupVerificationSession(code: String) async throws -> VerificationSessionOffer
    func acceptVerificationSession(id: UUID, request: VerificationSessionAcceptRequest) async throws -> VerificationSessionAccepted
}

extension LiveVerifyAPI: VerificationSessionAPI {
    public func lookupVerificationSession(code: String) async throws -> VerificationSessionOffer {
        try await client.call(APIRoutes.verificationSessionLookup, body: VerificationSessionLookupRequest(code: code))
    }
    public func acceptVerificationSession(id: UUID, request: VerificationSessionAcceptRequest) async throws -> VerificationSessionAccepted {
        try await client.call(APIRoutes.verificationSessionAccept, params: ["sessionId": id.uuidString.lowercased()], body: request)
    }
}

public enum VerificationSessionFlowError: Error, Equatable, Sendable {
    /// The build pins no `link-descriptor` key: the flow fails closed.
    case notConfigured
    /// The descriptor is not signed by a pinned key, expired, or its origin is not the business's verified domain.
    case descriptorInvalid(VerificationSessionError)
    /// What the relay said around the descriptor disagrees with it (another session, business or account).
    case mismatch
    /// The verification request the server opened is not the one the person accepted.
    case promptMismatch
    case expired
}

/// What the person sees before accepting: **only values from the verified descriptor**.
public struct VerificationSessionReview: Sendable, Equatable {
    public let offer: VerificationSessionOffer
    public let descriptor: VerificationSessionDescriptor
    public let descriptorDigest: String

    /// The verified business name ("Northwind Spirits").
    public var businessName: String { descriptor.businessName }
    /// Its verified domain ("northwind.example").
    public var businessDomain: String { descriptor.businessDomain }
    /// The site the request was started on ("shop.northwind.example"); always inside the verified domain.
    public var originHost: String { descriptor.originHost }
    public var capability: Capability { descriptor.capability }
    /// Exactly what the business would learn, and what it would not.
    public var disclosure: [VerificationDisclosureItem] { VerificationPromptContent.disclosure(for: descriptor.capability, parameters: descriptor.parameters) }
    public var notDisclosed: [String] { VerificationPromptContent.notDisclosed(for: descriptor.capability) }
    public var purpose: String { VerificationPromptContent.purposeText(descriptor.purposeCode) }
    /// Accepting connects this account to the business (it can then send you messages you allow; you can disconnect any time).
    public var connects: Bool { !offer.alreadyConnected }
    /// Real-time relay phishing (§2.60): the person must be on the business's own site, right now.
    public var warning: String {
        "Continue only if you are on \(originHost) right now and started this yourself. If someone sent you this code or link, stop."
    }
}

/// Looks the code up, verifies the descriptor against the pinned `link-descriptor` keys, and accepts exactly what was shown.
public struct VerificationSessionFlow: Sendable {
    let api: any VerificationSessionAPI
    let descriptorKeys: [DevicePublicKey]
    let clock: @Sendable () -> Date

    public init(api: any VerificationSessionAPI, descriptorKeys: [DevicePublicKey], clock: @escaping @Sendable () -> Date = { Date() }) {
        self.api = api
        self.descriptorKeys = descriptorKeys
        self.clock = clock
    }

    public func review(code: String) async throws -> VerificationSessionReview {
        guard !descriptorKeys.isEmpty else { throw VerificationSessionFlowError.notConfigured }
        let offer = try await api.lookupVerificationSession(code: code)
        let descriptor: VerificationSessionDescriptor
        do { descriptor = try VerificationSessionDescriptor.verify(offer.descriptor, trustedKeys: descriptorKeys, now: clock()) } catch let error as VerificationSessionError {
            throw error == .expired ? VerificationSessionFlowError.expired : VerificationSessionFlowError.descriptorInvalid(error)
        }
        guard descriptor.sessionId == offer.sessionId, descriptor.businessId == offer.business.id, descriptor.subject == offer.subjectRef else {
            throw VerificationSessionFlowError.mismatch
        }
        return VerificationSessionReview(offer: offer, descriptor: descriptor, descriptorDigest: VerificationSessionDescriptor.digest(of: offer.descriptor))
    }

    /// Accepts the reviewed session. The returned prompt goes through the ordinary Verify consent (its own display digest); the return URL is
    /// re-checked here, so the app never opens anything but the session's own origin.
    public func accept(_ review: VerificationSessionReview) async throws -> (prompt: VerificationPrompt, returnURL: URL?) {
        guard review.descriptor.expiresAtDate > clock() else { throw VerificationSessionFlowError.expired }
        let accepted = try await api.acceptVerificationSession(id: review.descriptor.sessionId,
                                                               request: VerificationSessionAcceptRequest(descriptorDigest: review.descriptorDigest))
        let prompt = accepted.prompt
        guard accepted.sessionId == review.descriptor.sessionId, prompt.businessId == review.descriptor.businessId,
              prompt.capability == review.descriptor.capability, prompt.purposeCode == review.descriptor.purposeCode,
              prompt.parameters == review.descriptor.parameters else { throw VerificationSessionFlowError.promptMismatch }
        let returnURL = accepted.returnURL.flatMap { VerificationSessionOrigin.validReturnURL($0, origin: review.descriptor.origin) }.flatMap(URL.init(string:))
        return (prompt, returnURL)
    }
}

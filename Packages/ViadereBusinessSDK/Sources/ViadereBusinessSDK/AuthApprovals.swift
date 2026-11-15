import Crypto
import Foundation
import ViadereCore

/// The keys the SDK derives from your SDK secret (ADR-0022 §5.2): the match-tag key (`K_match`) and the session-handle key (`K_sh`). Keep the secret
/// server-side; it never goes to Viadere.
public struct AuthApprovalKeys: Sendable {
    let matchKey: SymmetricKey
    let sessionHandleKey: SymmetricKey

    public init(sdkSecret: SymmetricKey) {
        matchKey = AuthSDKKeys.derive(secret: sdkSecret, label: AuthSDKKeys.matchTagLabel)
        sessionHandleKey = AuthSDKKeys.derive(secret: sdkSecret, label: AuthSDKKeys.sessionHandleLabel)
    }

    /// The **only** documented way to produce a `session_handle` (ADR-0022 §5.2 item 1): from your own id of the browser or app session that started this
    /// sign-in. Never from the customer, never a constant.
    public func sessionHandle(for initiatingSessionId: String) -> String {
        AuthSDKKeys.sessionHandle(key: sessionHandleKey, initiatingSessionId: initiatingSessionId)
    }
}

/// Who triggered a sign-in on **your** side: your account key and the client's IP address as you saw it.
public struct SignInRequester: Sendable, Hashable {
    public var account: String
    public var clientAddress: String
    public init(account: String, clientAddress: String) {
        self.account = account
        self.clientAddress = clientAddress
    }

    /// IPv4 → the /24; IPv6 → the /56 (the first 14 hex digits of the expanded address). Anything unparsable is its own bucket.
    public var networkPrefix: String {
        let address = clientAddress.trimmingCharacters(in: .whitespaces).lowercased()
        if !address.contains(":") {
            let parts = address.split(separator: ".")
            return parts.count == 4 ? "v4:" + parts.prefix(3).joined(separator: ".") : "raw:" + address
        }
        let halves = address.components(separatedBy: "::")
        guard halves.count <= 2 else { return "raw:" + address }
        let head = halves[0].isEmpty ? [] : halves[0].split(separator: ":").map(String.init)
        let tail = halves.count == 2 && !halves[1].isEmpty ? halves[1].split(separator: ":").map(String.init) : []
        let groups = head + Array(repeating: "0", count: max(0, 8 - head.count - tail.count)) + tail
        guard groups.count == 8 else { return "raw:" + address }
        let hex = groups.map { String(repeating: "0", count: max(0, 4 - $0.count)) + $0 }.joined()
        return "v6:" + hex.prefix(14)
    }
}

/// **Per-requester throttle, on by default (condition C-14, ADR-0022 §5.2 item 6).** At most `maxOpen` open sign-in triggers per (account, client network
/// prefix) inside `window`. Viadere cannot see who triggers a sign-in, so this belongs to the business: an attacker hammering a victim's account from one
/// network is stopped here, while the victim's own sign-in from another network is not. One process; give a shared store to a fleet.
public actor SignInTriggerThrottle {
    public static let standard = SignInTriggerThrottle()
    public nonisolated let maxOpen: Int
    public nonisolated let window: TimeInterval
    private var open: [String: [(id: String, at: Date)]] = [:]

    public init(maxOpen: Int = 3, window: TimeInterval = 600) {
        self.maxOpen = maxOpen
        self.window = window
    }

    /// Reserves a slot or throws `AuthApprovalError.throttled`. Returns the slot id to `release` when the sign-in ends (answered, cancelled, expired).
    public func acquire(_ requester: SignInRequester, now: Date) throws -> String {
        let key = requester.account + "|" + requester.networkPrefix
        var slots = (open[key] ?? []).filter { now.timeIntervalSince($0.at) < window }
        guard slots.count < maxOpen else { open[key] = slots; throw AuthApprovalError.throttled }
        let id = SecureToken.generate(byteCount: 12)
        slots.append((id, now))
        open[key] = slots
        return id
    }

    public func release(_ slot: String) {
        for key in open.keys { open[key]?.removeAll { $0.id == slot } }
    }
}

public enum AuthApprovalError: Error, Sendable, Equatable {
    /// More than `SignInTriggerThrottle.maxOpen` open sign-in triggers for this account from this network.
    case throttled
    /// No free code after 20 draws (`409 match_code_in_use` / `match_digits_required` every time), or `match_code_space_exhausted`.
    case noFreeCode
    /// An end-to-end request needs your request builder and at least one device.
    case endToEndNeedsDevices
}

/// What you asked for. `details` is what the customer sees on the phone; for an authentication the SDK sets `match_digits`.
public struct AuthApprovalDraft: Sendable {
    public var requestId: String
    public var subject: SubjectRef
    public var challenge: String
    public var details: ApprovalSubject
    public var risk: AuthApprovalRisk
    public var expiresIn: Int
    public var sessionHandle: String?
    public init(requestId: String = ApprovalRequestBuilder.newRequestId(), subject: SubjectRef, challenge: String = ApprovalRequestBuilder.newChallenge(),
                details: ApprovalSubject, risk: AuthApprovalRisk = .medium, expiresIn: Int = 120, sessionHandle: String? = nil) {
        self.requestId = requestId
        self.subject = subject
        self.challenge = challenge
        self.details = details
        self.risk = risk
        self.expiresIn = expiresIn
        self.sessionHandle = sessionHandle
    }
}

/// The created request: **show `code` on your sign-in or payment screen** (never send it to the customer's phone yourself), keep `pending` to verify the
/// result (it requires this code), and release `throttleSlot` when the sign-in ends.
public struct CreatedAuthApproval: Sendable {
    public var view: ApprovalRequestView
    public var code: String
    public var pending: PendingApproval
    public var throttleSlot: String
}

extension ViadereBusinessClient {
    /// `POST /v1/business/auth-approvals` with number matching. Draws the code (CSPRNG, rejection sampling), sends only its HMAC tags (plus the code itself
    /// for a server-visible request), and **redraws transparently** on `409 match_code_in_use` and `409 match_digits_required` (3 digits), at most 20 times,
    /// each with a new `Idempotency-Key`. Payments and `high`/`critical` requests use 3 digits and must be end to end (`builder` and `devices`).
    /// The per-requester throttle runs first and is on by default (`SignInTriggerThrottle.standard`).
    public func createAuthApproval(_ draft: AuthApprovalDraft, keys: AuthApprovalKeys, requester: SignInRequester,
                                   throttle: SignInTriggerThrottle = .standard, builder: ApprovalRequestBuilder? = nil, devices: [ApprovalDeviceTarget] = [],
                                   now: Date = Date(), random: @Sendable (Int) -> Data = { SecureToken.randomBytes($0) }) async throws -> CreatedAuthApproval {
        let slot = try await throttle.acquire(requester, now: now)
        do {
            let capability = draft.details.capability
            let risk = capability == .transactionApprove ? max(draft.risk, .high) : draft.risk
            let endToEnd = risk >= .high
            if endToEnd, builder == nil || devices.isEmpty { throw AuthApprovalError.endToEndNeedsDevices }
            var digits = ApprovalNumberMatch.requiredDigits(capability: capability, risk: risk)
            for _ in 0..<20 {
                let number = ApprovalNumberMatch.draw(digits: digits, random: random)
                guard let tags = AuthMatchTags.tags(key: keys.matchKey, subjectRef: draft.subject, code: number.code) else { continue }
                var details = draft.details
                if case .authentication(var a) = details { a.matchDigits = digits; details = .authentication(a) }
                let body: AuthApprovalCreateRequest
                if endToEnd, let builder {
                    let e2e = try await builder.endToEnd(requestId: draft.requestId, subject: draft.subject, challenge: draft.challenge, details: details, devices: devices,
                                                         expiresIn: draft.expiresIn, numberMatch: number)
                    body = AuthApprovalCreateRequest(requestId: draft.requestId, subjectRef: draft.subject, capability: capability, risk: risk, envelopes: e2e.envelopes,
                                                     expiresInSeconds: draft.expiresIn, numberMatch: AuthApprovalNumberMatch(digits: digits), matchTag: tags.tag,
                                                     matchPrefixTag: tags.prefixTag, sessionHandle: draft.sessionHandle)
                } else {
                    guard case .authentication(let a) = details else { throw AuthApprovalError.endToEndNeedsDevices }
                    body = AuthApprovalCreateRequest(requestId: draft.requestId, subjectRef: draft.subject, capability: capability, risk: risk, challenge: draft.challenge,
                                                     authentication: a, expiresInSeconds: draft.expiresIn, numberMatch: AuthApprovalNumberMatch(digits: digits, code: number.code),
                                                     matchTag: tags.tag, matchPrefixTag: tags.prefixTag, sessionHandle: draft.sessionHandle)
                }
                do {
                    let response = try await perform(APIRoutes.businessAuthApprovalCreate.descriptor, body: body, idempotencyKey: IdempotencyKey.generate(prefix: "authapproval"))
                    let view = try decode(ApprovalRequestView.self, response)
                    let pending = PendingApproval(requestId: draft.requestId, subject: draft.subject, challenge: draft.challenge, details: details,
                                                  numberMatch: .required(code: number.code), expiresAt: now.addingTimeInterval(TimeInterval(draft.expiresIn)))
                    return CreatedAuthApproval(view: view, code: number.code, pending: pending, throttleSlot: slot)
                } catch let error as ViadereAPIError where error.code == .matchCodeInUse {
                    continue
                } catch let error as ViadereAPIError where error.code == .matchDigitsRequired {
                    digits = 3
                    continue
                } catch let error as ViadereAPIError where error.code == .matchCodeSpaceExhausted {
                    throw AuthApprovalError.noFreeCode
                }
            }
            throw AuthApprovalError.noFreeCode
        } catch {
            await throttle.release(slot)
            throw error
        }
    }

    /// The relay's view of an auth approval. **Never authorize on `status`**: verify the signed result with `ApprovalVerifier` and `pending`.
    public func authApproval(requestId: String) async throws -> ApprovalRequestView {
        try decode(ApprovalRequestView.self, try await perform(APIRoutes.businessAuthApprovalGet.descriptor, parameters: ["requestId": requestId]))
    }
}

import Foundation
import ViadereCore

/// Why a code that claims to be a Safe Action was refused. Nothing ran and nothing was opened.
public enum SafeActionRejection: String, Sendable, Equatable, CaseIterable {
    /// Not a well-formed envelope.
    case malformed
    /// Addressed to another app.
    case wrongApp
    /// An action this app does not accept, or not from this issuer, or with the wrong scope or parameters.
    case notAccepted
    /// No pinned key for this issuer and key id.
    case unknownKey
    /// The signature does not match the pinned key.
    case signature
    /// Out of time, issued in the future, or valid for longer than a sign-in code may be.
    case expired
    /// This phone already accepted this code once.
    case alreadyUsed
    /// The issuer could not be reached, or did not answer with this request.
    case requestInfoUnavailable
    /// The issuer says the request is not waiting any more.
    case notPending
    /// The app is locked, not set up, or this build cannot read Safe Actions.
    case notReady

    /// Fixed sentence (spec step 4: say that it claims to be a Safe Action but could not be verified). It never repeats anything from the code.
    public static let sentence = "This code claims to be a Viadere sign-in but could not be verified. Nothing was opened."

    /// The reason, in fixed words.
    public var reason: String {
        switch self {
        case .malformed: "The code is damaged or incomplete."
        case .wrongApp: "It is meant for another app."
        case .notAccepted: "It asks for something Viadere doesn't accept from a code."
        case .unknownKey: "It isn't signed with a key this app trusts."
        case .signature: "Its signature doesn't match."
        case .expired: "It has expired. Refresh the sign-in page and scan again."
        case .alreadyUsed: "It was already scanned on this phone. Start the sign-in again on the website."
        case .requestInfoUnavailable: "Viadere couldn't confirm who is asking. Check your connection and start the sign-in again."
        case .notPending: "That sign-in is no longer waiting."
        case .notReady: "Open and unlock Viadere, then scan again."
        }
    }

    public var message: String { Self.sentence + " " + reason }
}

/// A verified cross-device sign-in request, with what the issuer says about who is asking. Opening the review is all it allows: the
/// authority-signed statement, the number on the page and the device-key signature are still required (`OIDCSignInViewModel`).
public struct VerifiedSafeActionRequest: Sendable, Equatable {
    /// The issuer whose pinned key signed the code.
    public var issuer: String
    /// The authority challenge id.
    public var requestId: String
    /// "Chrome on Windows": sanitized, at most 120 characters.
    public var device: String
    /// A coarse place, when the issuer has one.
    public var location: String?
    public var requestedAt: Date

    public init(issuer: String, requestId: String, device: String, location: String? = nil, requestedAt: Date) {
        self.issuer = issuer
        self.requestId = requestId
        self.device = device
        self.location = location
        self.requestedAt = requestedAt
    }
}

public enum SafeActionOutcome: Sendable, Equatable {
    /// No `ckey-action:1:` prefix: the ordinary scan rules apply (spec step 1).
    case notASafeAction
    case rejected(SafeActionRejection)
    /// Verified, cross-device: never automatic. The caller shows the confirmation; nothing has been approved.
    case needsConfirmation(VerifiedSafeActionRequest)
}

/// Viadere's own reader for CKey Safe Actions (spec "What a reader must do"; the spec's unofficial path: own verifier, own prompt, every
/// safeguard kept). One action is registered: `signin.request`, from this build's link-domain issuer, cross-device.
///
/// Steps, in order; the first failure ends it with a fixed reason and nothing runs:
/// 1. the text parses as an envelope (`CKeySafeAction.parse`);
/// 2. `app` is this app; `action` is registered, for this issuer, with the registered scope, a challenge id as `request_id`, no params;
/// 3. a **pinned** key exists for (`issuer`, `key_id`): no key is ever fetched;
/// 4. the signature verifies under the pinned key's algorithm (ES256: 1 ≤ r, s < n and low-S; Ed25519: canonical scalar), the lifetime is at most 120 s, and now is within it (120 s tolerance for a code issued
///    "in the future", none after expiry);
/// 5. this phone has not accepted the `request_id` before (remembered until expiry + 120 s, across restarts);
/// 6. the issuer's own host answers `request_info` over HTTPS with this `request_id` and `status: "pending"`.
///
/// The result is only ever a pending confirmation: no same-device action is registered, so nothing runs without a prompt.
public struct SafeActionReader: Sendable {
    public static let maxRequestInfoBytes = 2048

    let appId: String
    let issuer: String
    let keys: [PinnedSafeActionKey]
    let replay: any SafeActionReplayStore
    let transport: any HTTPTransport
    let clock: @Sendable () -> Date

    /// - Parameters:
    ///   - issuer: the only issuer registered for `signin.request` (the build's link-domain host).
    ///   - keys: pinned keys; entries for another issuer are ignored.
    public init(appId: String, issuer: String, keys: [PinnedSafeActionKey], replay: any SafeActionReplayStore, transport: any HTTPTransport,
                clock: @escaping @Sendable () -> Date = { Date() }) {
        self.appId = appId
        self.issuer = issuer
        self.keys = keys.filter { $0.issuer == issuer }
        self.replay = replay
        self.transport = transport
        self.clock = clock
    }

    public init(configuration: ViadereConfiguration, replay: any SafeActionReplayStore, transport: any HTTPTransport,
                clock: @escaping @Sendable () -> Date = { Date() }) {
        self.init(appId: configuration.bundleID, issuer: configuration.linkDomain.host, keys: configuration.safeActionKeys, replay: replay,
                  transport: transport, clock: clock)
    }

    public func read(_ text: String) async -> SafeActionOutcome {
        guard CKeySafeAction.isSafeAction(text) else { return .notASafeAction }
        guard let claimed = try? CKeySafeAction.parse(text: text) else { return .rejected(.malformed) }
        // The receiving app's id is compared with this app's own (the spec's envelope `app`), not with anything in the code.
        guard claimed.app == appId, appId == ViadereSignInSafeAction.appId else { return .rejected(.wrongApp) }
        // Registered: `signin.request`, from the link-domain issuer only, cross-device, a challenge id, no parameters.
        guard claimed.action == ViadereSignInSafeAction.action, claimed.issuer == issuer, claimed.scope == .crossDevice,
              AuthorityChallengeID.isValid(claimed.requestId), claimed.params.isEmpty else { return .rejected(.notAccepted) }
        guard let key = keys.first(where: { $0.issuer == claimed.issuer && $0.keyId == claimed.keyId }) else { return .rejected(.unknownKey) }
        let action: CKeySafeAction
        switch CKeySafeAction.verify(text: text, key: key.publicKey, now: clock(), maxLifetime: ViadereSignInSafeAction.lifetimeSeconds) {
        case .ok(let verified): action = verified
        case .invalid: return .rejected(.malformed)
        case .integrity: return .rejected(.signature)
        case .expired: return .rejected(.expired)
        }
        // Only the verified fields are used from here on (they equal the claimed ones, or the signature would not have matched).
        guard action == claimed else { return .rejected(.malformed) }
        let now = clock()
        let until = Date(timeIntervalSince1970: TimeInterval(action.expiresAt) + TimeInterval(CKeySafeAction.clockToleranceSeconds))
        guard replay.claim(requestId: action.requestId, until: until, now: now) else { return .rejected(.alreadyUsed) }
        return await confirm(action)
    }

    /// Step 6: who is asking, from the issuer's own host. A failure of any kind means the action does not run.
    private func confirm(_ action: CKeySafeAction) async -> SafeActionOutcome {
        guard let url = ViadereSignInSafeAction.requestInfoURL(issuer: action.issuer, requestId: action.requestId), url.scheme == "https",
              url.host == action.issuer else { return .rejected(.requestInfoUnavailable) }
        // No session, no device signature, no cookie: the request names the challenge and nothing about this phone or account.
        guard let response = try? await transport.send(HTTPRequest(method: .GET, url: url, headers: ["Accept": "application/json"])),
              response.status == 200, response.body.count <= Self.maxRequestInfoBytes,
              let info = try? JSONDecoder().decode(CKeySafeActionRequestInfo.self, from: response.body),
              info.requestId == action.requestId else { return .rejected(.requestInfoUnavailable) }
        guard info.status == CKeySafeActionRequestInfo.pending else { return .rejected(.notPending) }
        // The confirmation must say who is asking: a device line and a time are required; the place is optional. Over-long values are
        // refused, not cut, and everything shown is sanitized as untrusted text.
        guard let rawDevice = info.device, rawDevice.count <= CKeySafeActionRequestInfo.maxDeviceCharacters,
              let device = UntrustedText.optionalLine(rawDevice, max: CKeySafeActionRequestInfo.maxDeviceCharacters),
              let rawTime = info.requestedAt, rawTime.count <= CKeySafeActionRequestInfo.maxRequestedAtCharacters,
              let requestedAt = ViadereDate.parse(rawTime) else { return .rejected(.requestInfoUnavailable) }
        var location: String?
        if let rawLocation = info.location {
            guard rawLocation.count <= CKeySafeActionRequestInfo.maxLocationCharacters else { return .rejected(.requestInfoUnavailable) }
            location = UntrustedText.optionalLine(rawLocation, max: CKeySafeActionRequestInfo.maxLocationCharacters)
        }
        return .needsConfirmation(VerifiedSafeActionRequest(issuer: action.issuer, requestId: action.requestId, device: device, location: location,
                                                            requestedAt: requestedAt))
    }
}

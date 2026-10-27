import Foundation

/// User-verification level asserted by the device when signing a decision. The claim is
/// made cryptographically meaningful by the key used: `.biometric` decisions must verify
/// against the device's biometric-gated key (see `DeviceKeyPurpose`).
public enum DecisionAssurance: String, Sendable, Codable, CaseIterable, Comparable {
    /// Device-bound key, no user verification at signing time.
    case none
    /// Device passcode or biometrics (`.userPresence` access control).
    case devicePasscode
    /// Current-enrolled biometrics (`.biometryCurrentSet`).
    case biometric

    var rank: Int {
        switch self {
        case .none: 0
        case .devicePasscode: 1
        case .biometric: 2
        }
    }

    public static func < (lhs: Self, rhs: Self) -> Bool { lhs.rank < rhs.rank }
}

/// What evidence a decision arrived with.
public enum ProvidedAssurance: Sendable, Hashable {
    /// A plain text reply on SMS/RCS/AMB, or an unsigned tap. Identifies a phone number at best.
    case unauthenticatedReply
    /// A WebAuthn/passkey assertion with user verification on the secure web flow.
    /// Phishing-resistant, but possibly a synced (not device-bound) credential.
    case passkeyAssertion
    /// A `DecisionPayload` signed by an enrolled device key at the given level.
    case deviceSignature(DecisionAssurance)
}

/// The minimum assurance a decision must carry, ordered weakest → strongest.
public enum RequiredAssurance: Int, Sendable, Codable, Comparable, CaseIterable {
    /// Any channel reply is acceptable (including SMS text).
    case channelReply = 0
    /// A signature from an enrolled device key.
    case deviceSignature = 1
    /// A device signature with user verification (passcode or biometric), or a passkey assertion.
    case userVerified = 2
    /// A device-bound biometric signature. Passkeys (possibly synced) and SMS never qualify.
    case deviceBoundBiometric = 3

    public static func < (lhs: Self, rhs: Self) -> Bool { lhs.rawValue < rhs.rawValue }
}

/// Pure policy deciding which channel/assurance combinations may satisfy an interaction.
///
/// | kind                       | low             | standard     | high                 | critical             |
/// |----------------------------|-----------------|--------------|----------------------|----------------------|
/// | authenticate / authorize   | deviceSignature | userVerified | deviceBoundBiometric | deviceBoundBiometric |
/// | unknown kinds              | deviceBoundBiometric (always)                                                 |
/// | all other kinds            | channelReply    | channelReply | userVerified         | deviceBoundBiometric |
///
/// Additionally, `purpose == .security` raises any kind to at least `deviceSignature`.
/// Authenticate/authorize can **never** be satisfied by a text-messaging channel.
public enum AssurancePolicy {
    /// The minimum assurance for `interaction`.
    public static func requiredAssurance(for interaction: Interaction) -> RequiredAssurance {
        requiredAssurance(kind: interaction.kind, sensitivity: interaction.sensitivity, purpose: interaction.purpose)
    }

    /// The minimum assurance for a kind/sensitivity/purpose triple.
    public static func requiredAssurance(kind: InteractionKind, sensitivity: Sensitivity, purpose: InteractionPurpose) -> RequiredAssurance {
        var required: RequiredAssurance
        switch kind {
        case .unknown:
            return .deviceBoundBiometric
        case .authenticate, .authorize:
            switch sensitivity {
            case .low: required = .deviceSignature
            case .standard: required = .userVerified
            case .high, .critical: required = .deviceBoundBiometric
            }
        default:
            switch sensitivity {
            case .low, .standard: required = .channelReply
            case .high: required = .userVerified
            case .critical: required = .deviceBoundBiometric
            }
        }
        if purpose == .security { required = max(required, .deviceSignature) }
        return required
    }

    /// The assurance level a piece of evidence actually achieves.
    public static func achievedAssurance(_ provided: ProvidedAssurance) -> RequiredAssurance {
        switch provided {
        case .unauthenticatedReply: .channelReply
        case .passkeyAssertion: .userVerified
        case .deviceSignature(.none): .deviceSignature
        case .deviceSignature(.devicePasscode): .userVerified
        case .deviceSignature(.biometric): .deviceBoundBiometric
        }
    }

    /// Which evidence a channel can physically carry. Text-messaging channels can only carry
    /// unauthenticated replies; `web` carries passkey assertions; app channels carry device signatures.
    public static func channel(_ channel: Channel, canCarry provided: ProvidedAssurance) -> Bool {
        switch (channel, provided) {
        case (.sms, .unauthenticatedReply), (.rcs, .unauthenticatedReply), (.appleMessagesForBusiness, .unauthenticatedReply):
            true
        case (.sms, _), (.rcs, _), (.appleMessagesForBusiness, _):
            false
        case (.web, .passkeyAssertion), (.web, .unauthenticatedReply):
            true
        case (.web, .deviceSignature):
            false
        case (.nativePush, _), (.inApp, _):
            true
        }
    }

    /// Whether a decision received on `channel` with `provided` evidence may satisfy `interaction`.
    ///
    /// Requires: the channel is allowed (`nativePush` and `inApp` count as one app family, since
    /// a push can be acted on inside the app), the channel can carry the evidence,
    /// security-sensitive kinds never arrive via text messaging, and the achieved assurance meets
    /// `requiredAssurance(for:)`.
    public static func canSatisfy(_ interaction: Interaction, channel: Channel, provided: ProvidedAssurance) -> Bool {
        let appFamily: Set<Channel> = [.nativePush, .inApp]
        let allowed = interaction.allowedChannels.contains(channel)
            || (appFamily.contains(channel) && !appFamily.isDisjoint(with: interaction.allowedChannels))
        guard allowed else { return false }
        guard self.channel(channel, canCarry: provided) else { return false }
        if interaction.kind.isSecuritySensitive && channel.isTextMessaging { return false }
        return achievedAssurance(provided) >= requiredAssurance(for: interaction)
    }

    /// Whether `channel` can present `interaction` *inline* (actionable in place). If not,
    /// the channel must render a secure handoff instead (never a downgraded YES/NO).
    public static func canPresentInline(_ interaction: Interaction, on channel: Channel) -> Bool {
        let required = requiredAssurance(for: interaction)
        switch channel {
        case .sms, .rcs, .appleMessagesForBusiness:
            return required == .channelReply && !interaction.kind.isSecuritySensitive
        case .web:
            return required <= .userVerified
        case .nativePush, .inApp:
            return !interaction.kind.isUnknown
        }
    }
}

import Foundation
import ViadereCore

/// Which kind of optical code the camera read.
public enum ScannedSymbology: String, Sendable, Equatable {
    /// A QR code, read by the system's own detector.
    case qr
    /// A CKey (the Viadere code on "Sign in with Viadere"), read by the CKey scanner.
    case ckey
}

/// What the app does with a scanned code. A scan never approves or opens a web page by itself: the most it does is open the same review
/// screen a tapped Viadere link opens.
public enum ScannedCodeDecision: Sendable, Equatable {
    /// A Viadere link on this build's link domain: open its review screen.
    case open(DeepLink)
    /// A well-formed CKey Safe Action envelope (`ckey-action:1:…`). **Not yet trusted**: `SafeActionReader` verifies it (pinned key,
    /// signature, app, action, time, single use, the issuer's request information) and the most it then does is open the sign-in review.
    case safeAction(String)
    /// A business handle or permanent code printed as plain text: look it up in Add business.
    case lookup(String)
    case rejected(ScanRejection)
}

public enum ScanRejection: Sendable, Equatable {
    /// Not a Viadere link, handle or code (any other website, any other scheme, free text, binary data).
    case notViadere
    /// An old text-message link (`/l/`, `/h/`): never read or redeemed.
    case retired
    /// Something spelled like a CKey Safe Action (`ckey-action:` in any letter case) that is not a well-formed version 1 envelope of a
    /// sign-in's size. Viadere never lets a code act by itself; a well-formed one still has to verify (`SafeActionReader`).
    case unverifiedAction
    /// Longer than any Viadere code, or carrying control characters.
    case malformed
    /// A pairing code's QR (`/p/…`) scanned on a device that is already enrolled: it only ever adds a *new* device (SECURITY.md §2.107).
    case pairingOnEnrolledDevice
    /// Anything other than a pairing code's QR, scanned in a new device's pairing entry.
    case notAPairingCode

    /// What the scanner tells the person. It never repeats the scanned text.
    public var message: String {
        switch self {
        case .notViadere: "That code isn't from Viadere. Nothing was opened."
        case .retired: "This code is no longer used. Nothing was opened."
        case .unverifiedAction: SafeActionRejection.malformed.message
        case .malformed: "That code can't be read as a Viadere code. Nothing was opened."
        case .pairingOnEnrolledDevice: "This code adds a new device to an account. Scan it with the device you're adding. Nothing was opened."
        case .notAPairingCode: "That isn't a code for adding this device. Scan the code on your other device's screen."
        }
    }
}

/// The one gate between the camera and the app. The camera sees whatever is put in front of it, so every scanned payload is hostile until
/// it parses as one of a few exact Viadere forms. Stricter than a tapped link on purpose:
///
/// - only `https` universal links on the build's link domain (the `viadere://` scheme is refused: nothing printed needs it);
/// - only link kinds that are shown as codes (connect, business link session, verification session, sign-in, Approve enrollment, Loop
///   install), each of which opens a review screen and decides nothing;
/// - a CKey Safe Action (`ckey-action:`) is never acted on here: only an exact, well-formed version 1 envelope no longer than a sign-in
///   envelope for this link domain is handed on, unverified, to `SafeActionReader`; every other spelling is refused;
/// - bounded length and no control characters, checked before any parser sees the text;
/// - a pairing code's QR (`/p/{code}`, exact form) is accepted only in `ScanContext.newDevicePairing`, and that context accepts nothing else.
/// Where the scanner was opened. The pairing code's QR is read only in a new device's pairing entry; everywhere else it is refused.
public enum ScanContext: Sendable, Equatable {
    /// The app's scanner (Alerts, Businesses, Add business): an enrolled device.
    case app
    /// The new device's pairing entry (onboarding, "I already use Viadere"): only `/p/{code}` is accepted.
    case newDevicePairing
}

public enum ScannedCodePolicy {
    /// The longest Viadere link is an Approve enrollment link with its fragment secret, well under this.
    public static let maxPayloadBytes = 512
    static let safeActionPrefix = "ckey-action:"

    /// The byte cap for a Safe Action only: the longest sign-in envelope this link domain's issuer can sign (`ViadereSignInSafeAction`;
    /// 264 for `viadere.com`, above 512 only for a link domain of 198 characters or more). Everything else keeps `maxPayloadBytes`.
    public static func maxSafeActionBytes(domain: LinkDomain) -> Int { ViadereSignInSafeAction.maxTextBytes(issuer: domain.host) }

    public static func evaluate(_ payload: String, symbology: ScannedSymbology, domain: LinkDomain = .current, context: ScanContext = .app) -> ScannedCodeDecision {
        let decision = evaluateCode(payload, symbology: symbology, domain: domain)
        switch (context, decision) {
        case (.app, .open(.devicePairing)): return .rejected(.pairingOnEnrolledDevice)
        case (.app, _): return decision
        case (.newDevicePairing, .open(.devicePairing)): return decision
        case (.newDevicePairing, .rejected(.malformed)): return decision
        case (.newDevicePairing, _): return .rejected(.notAPairingCode)
        }
    }

    private static func evaluateCode(_ payload: String, symbology: ScannedSymbology, domain: LinkDomain) -> ScannedCodeDecision {
        let safeActionCap = maxSafeActionBytes(domain: domain)
        guard !payload.isEmpty, payload.utf8.count <= max(maxPayloadBytes, safeActionCap),
              payload.unicodeScalars.allSatisfy({ $0.value >= 0x20 && $0.value != 0x7F && !(0x80...0x9F).contains($0.value) }) else {
            return .rejected(.malformed)
        }
        if payload.lowercased().hasPrefix(safeActionPrefix) {
            // Exactly `ckey-action:1:` in lower case, within the sign-in size, and a parseable envelope. Nothing is trusted yet and nothing
            // runs: the reader verifies it after the scanner has closed. A QR code carrying one is treated the same as a CKey.
            guard payload.utf8.count <= safeActionCap, (try? CKeySafeAction.parse(text: payload)) != nil else { return .rejected(.unverifiedAction) }
            return .safeAction(payload)
        }
        guard payload.utf8.count <= maxPayloadBytes else { return .rejected(.malformed) }

        if payload.contains(":") {
            // A link. Exactly `https://`, in lower case as Viadere writes it, with no surrounding space to trim away.
            guard payload.hasPrefix("https://"), let url = URL(string: payload), url.absoluteString == payload,
                  let link = DeepLinkRouter.route(url, domain: domain) else { return .rejected(.notViadere) }
            switch link {
            case .connect, .linkSession, .verificationSession, .oidcSignIn, .approveEnrollment, .loopInstall, .devicePairing:
                return .open(link)
            case .retiredLink:
                return .rejected(.retired)
            case .business, .interaction, .conversation, .settings, .authDelivery, .approveRequest:
                // Reachable only through the custom scheme or a push, which a scan never is.
                return .rejected(.notViadere)
            }
        }

        // A handle (`@northwind`) or a permanent code (`AF2345`) printed as text. QR only: a CKey from Viadere always carries a link.
        guard symbology == .qr else { return .rejected(.notViadere) }
        let state = ConnectInputClassifier.evaluate(payload)
        if state.canSubmit, state.kind == .handle || state.kind == .code { return .lookup(payload) }
        return .rejected(.notViadere)
    }
}

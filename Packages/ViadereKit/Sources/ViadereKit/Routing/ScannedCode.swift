import Foundation
import ViadereCore

/// Which kind of optical code the camera read.
public enum ScannedSymbology: String, Sendable, Equatable {
    /// A QR code, read by the system's own detector.
    case qr
    /// A CKey (the Viadere code on "Sign in with Viadere"), read by the CKey scanner.
    case ckey
}

/// What the app does with a scanned code. A scan never approves, opens a web page or contacts a server by itself: the most it does is open
/// the same review screen a tapped Viadere link opens.
public enum ScannedCodeDecision: Sendable, Equatable {
    /// A Viadere link on this build's link domain: open its review screen.
    case open(DeepLink)
    /// A business handle or permanent code printed as plain text: look it up in Add business.
    case lookup(String)
    case rejected(ScanRejection)
}

public enum ScanRejection: Sendable, Equatable {
    /// Not a Viadere link, handle or code (any other website, any other scheme, free text, binary data).
    case notViadere
    /// An old text-message link (`/l/`, `/h/`): never read or redeemed.
    case retired
    /// A signed "act without asking" code (`ckey-action:`). Viadere never lets a code act by itself; every request is reviewed on screen.
    case automaticAction
    /// Longer than any Viadere code, or carrying control characters.
    case malformed

    /// What the scanner tells the person. It never repeats the scanned text.
    public var message: String {
        switch self {
        case .notViadere: "That code isn't from Viadere. Nothing was opened."
        case .retired: "This code is no longer used. Nothing was opened."
        case .automaticAction: "This code asks the app to act without showing you first. Viadere doesn't accept those."
        case .malformed: "That code can't be read as a Viadere code. Nothing was opened."
        }
    }
}

/// The one gate between the camera and the app. The camera sees whatever is put in front of it, so every scanned payload is hostile until
/// it parses as one of a few exact Viadere forms. Stricter than a tapped link on purpose:
///
/// - only `https` universal links on the build's link domain (the `viadere://` scheme is refused: nothing printed needs it);
/// - only link kinds that are shown as codes (connect, business link session, verification session, sign-in, Approve enrollment, Loop
///   install), each of which opens a review screen and decides nothing;
/// - no CKey Safe Actions (`ckey-action:`), which exist to run without a prompt;
/// - bounded length and no control characters, checked before any parser sees the text.
public enum ScannedCodePolicy {
    /// The longest Viadere link is an Approve enrollment link with its fragment secret, well under this.
    public static let maxPayloadBytes = 512
    static let safeActionPrefix = "ckey-action:"

    public static func evaluate(_ payload: String, symbology: ScannedSymbology, domain: LinkDomain = .current) -> ScannedCodeDecision {
        guard !payload.isEmpty, payload.utf8.count <= maxPayloadBytes,
              payload.unicodeScalars.allSatisfy({ $0.value >= 0x20 && $0.value != 0x7F && !(0x80...0x9F).contains($0.value) }) else {
            return .rejected(.malformed)
        }
        if payload.lowercased().hasPrefix(safeActionPrefix) { return .rejected(.automaticAction) }

        if payload.contains(":") {
            // A link. Exactly `https://`, in lower case as Viadere writes it, with no surrounding space to trim away.
            guard payload.hasPrefix("https://"), let url = URL(string: payload), url.absoluteString == payload,
                  let link = DeepLinkRouter.route(url, domain: domain) else { return .rejected(.notViadere) }
            switch link {
            case .connect, .linkSession, .verificationSession, .oidcSignIn, .approveEnrollment, .loopInstall:
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

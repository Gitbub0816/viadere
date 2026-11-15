import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

/// Linking a phone number by sending one text from it (ADR-0027, owner decisions 1 and 9; copy: UX_COPY S-PH-01 to S-PH-06).
///
/// The app asks the server for a challenge, then opens the system compose sheet pre-filled with a text the **person sends themselves**
/// (iOS: `MFMessageComposeViewController`, never an `sms:` URL, and no silent sending exists). The server binds the number when an inbound text
/// from it carries the nonce within ten minutes. Viadere never texts the phone a code or a link, so there is nothing to type back. The proof is
/// control of the number only: it is not a sign-in factor, a number linked this way waits out a cool-down, and a trusted-device confirmation
/// does not shorten it.
///
/// The compose sheet reports only `.sent` (queued), `.cancelled` or `.failed`, never the text, so the screen never decides the text was
/// not sent: it polls the server until the link is `verified` or the challenge expires, and only then says "We didn't receive your text".
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class PhoneLinkViewModel {
    /// What the screen needs while it waits for the person's text.
    public struct Challenge: Equatable, Sendable {
        public var phoneLinkId: PhoneLinkID
        public var maskedNumber: String
        /// The Viadere number to text, E.164.
        public var sendTo: String
        /// The text to put in the compose sheet.
        public var prefill: String
        public var expiresAt: Date
    }

    public enum Stage: Equatable, Sendable {
        case entry
        case waiting(Challenge)
        case linked(PhoneLink)
        /// The challenge expired without a matching text from that number.
        case notReceived(maskedNumber: String)
    }

    /// What the compose sheet should be opened with: one recipient, one body. The person taps Send.
    public struct ComposeRequest: Equatable, Sendable {
        public var recipient: String
        public var body: String
    }

    // MARK: Copy (UX_COPY)

    /// S-PH-01.
    public static let introText = "Link your number to your Viadere account on this phone by sending one text from it. We never send you codes by text."
    /// S-PH-01 button.
    public static let writeTextTitle = "Write text"
    /// S-PH-06 button.
    public static let copyTextTitle = "Copy text"
    /// E-05: an old build calls a retired route.
    public static let updateNeededText = "Update Viadere to link your number."

    public static func waitingText(masked: String) -> String { "Waiting for your text from \(masked)…" }
    public static func notReceivedText(masked: String) -> String {
        "We didn't receive your text from \(masked). Make sure you send it from that phone line."
    }
    /// S-PH-06: no compose sheet (iPad without cellular or relay, Mac, Simulator, no SIM).
    public static func manualText(prefill: String, sendTo: String) -> String {
        "Send this text from the phone with that number: \"\(prefill)\" to \(sendTo)."
    }

    // MARK: State

    public private(set) var stage: Stage = .entry
    public private(set) var raw = ""
    public private(set) var isWorking = false
    public private(set) var errorMessage: String?
    /// The compose sheet could not be opened (or the device cannot send texts): show the text and number to copy instead.
    public private(set) var showCopyInstead = false

    /// Called once when the number is linked (the owner refreshes its own list).
    public var onLinked: (@MainActor (PhoneLink) -> Void)?

    private let services: ViadereServices
    private let sleep: @Sendable (TimeInterval) async -> Void
    /// How often the status is fetched while waiting.
    public static let pollInterval: TimeInterval = 3

    public init(services: ViadereServices,
                sleep: @escaping @Sendable (TimeInterval) async -> Void = { try? await Task.sleep(for: .seconds($0)) }) {
        self.services = services
        self.sleep = sleep
    }

    public var phoneNumber: PhoneNumber? { PhoneInput.normalize(raw) }
    public var canBegin: Bool { phoneNumber != nil && !isWorking }
    public func setPhone(_ value: String) { raw = PhoneInput.displayFormat(value) }

    /// The compose request while waiting, else `nil`.
    public var composeRequest: ComposeRequest? {
        guard case .waiting(let challenge) = stage else { return nil }
        return ComposeRequest(recipient: challenge.sendTo, body: challenge.prefill)
    }

    /// S-PH-06 wording for the current challenge, else `nil`.
    public var manualInstructions: String? {
        guard case .waiting(let challenge) = stage else { return nil }
        return Self.manualText(prefill: challenge.prefill, sendTo: challenge.sendTo)
    }

    /// Waiting (S-PH-03), not received (S-PH-04), linked (S-PH-05): the line the screen shows for the current stage, else `nil`.
    public var statusText: String? {
        switch stage {
        case .entry: nil
        case .waiting(let challenge): Self.waitingText(masked: challenge.maskedNumber)
        case .notReceived(let masked): Self.notReceivedText(masked: masked)
        case .linked(let link): linkedText(link)
        }
    }

    /// S-PH-05: "Number linked. Businesses can reach you by text there from {date}. Approvals never happen by text."
    public func linkedText(_ link: PhoneLink) -> String {
        let now = services.clock()
        if let until = link.usableFrom, until > now {
            return "Number linked. Businesses can reach you by text there from \(CoolDownPolicy.timeText(until, now: now)). Approvals never happen by text."
        }
        return "Number linked. Approvals never happen by text."
    }

    // MARK: Actions

    /// "Write text": asks the server for a challenge. Nothing is sent to the phone.
    public func begin() async {
        guard let phone = phoneNumber, !isWorking else { return }
        isWorking = true
        errorMessage = nil
        defer { isWorking = false }
        do {
            let response = try await services.api.beginPhoneLink(phone: phone)
            showCopyInstead = false
            stage = .waiting(Challenge(phoneLinkId: response.phoneLinkId, maskedNumber: phone.masked, sendTo: response.sendTo,
                                       prefill: response.prefill, expiresAt: response.expiresAt))
        } catch let error as APIError {
            errorMessage = error.code == .gone ? Self.updateNeededText : error.userMessage
        } catch {
            errorMessage = "Something went wrong. Please try again."
        }
    }

    /// The system compose sheet could not be shown (`canSendText()` is false, an OEM app dropped the body, or it failed): S-PH-06.
    public func composeUnavailable() { showCopyInstead = true }

    /// The compose sheet was dismissed. Nothing is concluded from it (`.sent` only means queued): keep waiting for the server.
    public func composeDismissed(sent: Bool) { if !sent { errorMessage = nil } }

    /// One status check. A verified link ends the wait; an expired challenge says the text was not received; anything else keeps waiting.
    public func poll() async {
        guard case .waiting(let challenge) = stage else { return }
        do {
            let status = try await services.api.phoneLinkStatus(challenge.phoneLinkId)
            switch status.state {
            case .verified:
                if let link = status.link {
                    stage = .linked(link)
                    onLinked?(link)
                    return
                }
            case .expired:
                stage = .notReceived(maskedNumber: challenge.maskedNumber)
                return
            case .pending:
                break
            }
        } catch {
            // A failed poll is not "not received": try again until the challenge's own clock runs out.
        }
        if services.clock() >= challenge.expiresAt.addingTimeInterval(Self.pollInterval) {
            stage = .notReceived(maskedNumber: challenge.maskedNumber)
        }
    }

    /// Polls until the number is linked or the challenge expires (or the task is cancelled).
    public func waitForText() async {
        while case .waiting = stage, !Task.isCancelled {
            await poll()
            guard case .waiting = stage else { return }
            await sleep(Self.pollInterval)
        }
    }

    /// "Use a different number" / "Try again": back to entry, keeping what was typed.
    public func startOver() {
        stage = .entry
        errorMessage = nil
        showCopyInstead = false
    }

    /// Leaves the flow (the challenge simply expires on the server).
    public func cancel() {
        stage = .entry
        raw = ""
        errorMessage = nil
        showCopyInstead = false
    }
}

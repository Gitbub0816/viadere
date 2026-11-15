import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

/// The "Save your recovery codes" screen's state. The codes arrive **once** (at registration, after a recovery completes, or after
/// regeneration), live only in this object's memory, and are released as soon as the person confirms they saved them (or the screen
/// goes away). They are never written to the Keychain, defaults, disk or a log, and never put in a notification, a deep link or a
/// restorable scene state.
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class RecoveryCodesViewModel {
    public private(set) var codes: RecoveryCodeSet?
    /// The person ticked "I saved these". Continuing needs it.
    public var confirmedSaved = false
    /// A screenshot was taken while the codes were visible: a screenshot lands in Photos and iCloud, so they should save the codes
    /// properly and may want to regenerate them.
    public private(set) var screenshotTaken = false
    /// The display is being recorded or mirrored: the codes are hidden meanwhile.
    public var isScreenBeingCaptured = false
    public private(set) var hasCopied = false
    public private(set) var isFinished = false
    public var onFinished: (@MainActor () -> Void)?

    public init(codes: RecoveryCodeSet) { self.codes = codes }

    public var recoveryId: String? { codes?.recoveryId }
    /// What the screen shows: `nil` while the screen is captured or after the codes were released.
    public var visibleCodes: [String]? { isScreenBeingCaptured ? nil : codes?.codes }
    public var canContinue: Bool { confirmedSaved && codes != nil }

    /// The plain text for Copy and Save to Files. Built on demand from memory; nothing keeps it.
    public var exportText: String? {
        guard let codes else { return nil }
        return Self.exportText(for: codes)
    }

    public static func exportText(for set: RecoveryCodeSet) -> String {
        var lines = ["Viadere recovery codes", "", "Recovery ID: \(set.recoveryId)", ""]
        for (index, code) in set.codes.enumerated() { lines.append("\(index + 1). \(code)") }
        lines += ["", "Each code works once. Anyone with the recovery ID and a code can start recovering your account, so keep this somewhere private."]
        return lines.joined(separator: "\n")
    }

    public func noteCopied() { hasCopied = true }
    public func noteScreenshot() { screenshotTaken = true }

    /// "Continue": allowed only after the confirmation. Releases the codes.
    @discardableResult
    public func finish() -> Bool {
        guard canContinue else { return false }
        release()
        isFinished = true
        onFinished?()
        return true
    }

    /// Drops the codes from memory (the screen went away, the app locked, the app was backgrounded). They cannot be shown again:
    /// the person generates new ones in Settings.
    public func release() {
        codes = nil
        confirmedSaved = false
        screenshotTaken = false
    }

    public static let screenshotNotice = "A screenshot was taken. It may be saved to Photos or iCloud, so keep it private, or generate new codes later in Settings."
    public static let copyNotice = "Copied. It clears from your clipboard shortly. Paste it somewhere private."
}

import Foundation
import ViadereCore

/// What the unified connect field currently holds.
public enum ConnectInputKind: Sendable, Equatable { case empty, handle, code, name, link }

public struct ConnectInputState: Sendable, Equatable {
    public enum Validation: Sendable, Equatable {
        case none
        /// Still typing: show a quiet hint.
        case incomplete(String)
        case valid
        case invalid(String)
    }

    public var kind: ConnectInputKind
    /// The text to show in the field. Code input is auto-formatted (`AF-2345`) and normalized (I→1, O→0).
    public var text: String
    public var validation: Validation
    /// An all-letters 6-character entry is treated as a name, but may also be a code.
    public var alsoCode: BusinessCode?

    public var canSubmit: Bool {
        switch kind {
        case .empty: false
        case .name: text.trimmingCharacters(in: .whitespaces).count >= 2
        default: validation == .valid
        }
    }
}

/// The unified entry field accepts `@handle`, a permanent code, a Viadere link or a business name.
/// Mirrors `DirectoryInput`'s order (link → handle → code → name) but classifies while the person types.
public enum ConnectInputClassifier {
    public static func evaluate(_ raw: String) -> ConnectInputState {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return ConnectInputState(kind: .empty, text: "", validation: .none, alsoCode: nil) }

        if trimmed.lowercased().hasPrefix("http") {
            if (try? ConnectLink.parse(trimmed)) != nil {
                return ConnectInputState(kind: .link, text: trimmed, validation: .valid, alsoCode: nil)
            }
            let looksComplete = trimmed.lowercased().hasPrefix("https://") && trimmed.count > 12
            return ConnectInputState(kind: .link, text: trimmed,
                                     validation: looksComplete ? .invalid("That isn't a Viadere link.") : .incomplete("Paste a viadere.com link"),
                                     alsoCode: nil)
        }

        if trimmed.hasPrefix("@") {
            let lowered = trimmed.lowercased()
            do {
                _ = try BusinessHandle(lowered)
                return ConnectInputState(kind: .handle, text: lowered, validation: .valid, alsoCode: nil)
            } catch let error as BusinessHandle.ValidationError {
                switch error {
                case .empty, .tooShort:
                    return ConnectInputState(kind: .handle, text: lowered, validation: .incomplete("Handles have at least 3 characters."), alsoCode: nil)
                case .nonASCII, .invalidCharacter:
                    return ConnectInputState(kind: .handle, text: lowered, validation: .invalid("Handles use letters, numbers and underscores."), alsoCode: nil)
                case .mustStartWithLetter:
                    return ConnectInputState(kind: .handle, text: lowered, validation: .invalid("A handle starts with a letter."), alsoCode: nil)
                case .invalidUnderscore:
                    return ConnectInputState(kind: .handle, text: lowered, validation: .incomplete("Handles can't end with or double an underscore."), alsoCode: nil)
                case .tooLong:
                    return ConnectInputState(kind: .handle, text: lowered, validation: .invalid("That handle is too long."), alsoCode: nil)
                default:
                    return ConnectInputState(kind: .handle, text: lowered, validation: .invalid("That isn't a valid handle."), alsoCode: nil)
                }
            } catch {
                return ConnectInputState(kind: .handle, text: lowered, validation: .invalid("That isn't a valid handle."), alsoCode: nil)
            }
        }

        // Code mode: short, code-shaped, and contains a digit (so names like "Costco" stay names).
        let stripped = trimmed.filter { !BusinessCode.separators.contains($0) }
        let codeShaped = !stripped.isEmpty && stripped.count <= BusinessCode.length + 1
            && stripped.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber) }
            && !trimmed.contains(where: { $0.isWhitespace && trimmed.split(whereSeparator: \.isWhitespace).count > 2 })
        if codeShaped, stripped.contains(where: { $0.isNumber }) {
            let formatted = CodeEntryFormatter.format(trimmed)
            switch formatted.state {
            case .valid:
                return ConnectInputState(kind: .code, text: formatted.display, validation: .valid, alsoCode: nil)
            case .incomplete(let remaining):
                return ConnectInputState(kind: .code, text: formatted.display,
                                         validation: .incomplete(remaining == 1 ? "1 more character" : "\(remaining) more characters"), alsoCode: nil)
            case .invalid:
                return ConnectInputState(kind: .code, text: formatted.display, validation: .invalid("Codes use letters and numbers."), alsoCode: nil)
            case .empty:
                break
            }
        }

        var alsoCode: BusinessCode?
        if stripped.count == BusinessCode.length, stripped.allSatisfy({ $0.isASCII && $0.isLetter }) { alsoCode = BusinessCode(parsing: stripped) }
        return ConnectInputState(kind: .name, text: raw, validation: .none, alsoCode: alsoCode)
    }
}

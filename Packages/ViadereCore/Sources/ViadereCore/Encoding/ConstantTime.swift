import Foundation

/// Constant-time comparison helpers. Use for every secret, MAC, or token-hash comparison.
public enum ConstantTime {
    /// Compares two byte sequences in time that depends only on their lengths.
    public static func equals<A: DataProtocol, B: DataProtocol>(_ a: A, _ b: B) -> Bool {
        let lhs = Array(a)
        let rhs = Array(b)
        var difference: UInt8 = lhs.count == rhs.count ? 0 : 1
        let count = max(lhs.count, rhs.count)
        for index in 0..<count {
            let x = index < lhs.count ? lhs[index] : 0
            let y = index < rhs.count ? rhs[index] : 0
            difference |= x ^ y
        }
        return difference == 0
    }

    /// Compares the UTF-8 bytes of two strings in constant time.
    public static func equals(_ a: String, _ b: String) -> Bool {
        equals(Array(a.utf8), Array(b.utf8))
    }
}

extension String {
    /// Trims only ASCII whitespace (space, tab, CR, LF). Unicode "whitespace" such as zero-width
    /// or non-breaking spaces is deliberately preserved so validators can reject it.
    var asciiTrimmed: String {
        let isSpace: (Unicode.Scalar) -> Bool = { $0 == " " || $0 == "\t" || $0 == "\n" || $0 == "\r" }
        let scalars = Array(unicodeScalars)
        guard let start = scalars.firstIndex(where: { !isSpace($0) }), let end = scalars.lastIndex(where: { !isSpace($0) }) else {
            return ""
        }
        var view = String.UnicodeScalarView()
        view.append(contentsOf: scalars[start...end])
        return String(view)
    }
}

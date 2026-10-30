import Foundation

/// Where a brand asset may be used, with its normalized size ceiling (plan section 4.6, O4: initial values, revisited after profiling).
public enum BrandAssetSlot: String, Sendable, Codable, CaseIterable, Hashable {
    case logo, mark, background, art

    /// Longest side after re-encoding, in pixels.
    public var maxDimension: Int {
        switch self {
        case .logo: 512
        case .mark: 256
        case .background, .art: 1600
        }
    }

    /// Largest stored (re-encoded PNG) size.
    public var maxStoredBytes: Int {
        switch self {
        case .logo, .mark: 256 * 1024
        case .background, .art: 1024 * 1024
        }
    }
}

/// A content-addressed, already re-encoded brand asset: what a manifest references. The device fetches
/// `https://{ASSET_DOMAIN}/b/{sha256}.png` and checks the bytes hash to `sha256` before use, so a stale or hostile URL cannot change content.
public struct BrandAssetRef: Sendable, Hashable {
    public var sha256: String
    public var width: Int
    public var height: Int
    public var bytes: Int

    public init(sha256: String, width: Int, height: Int, bytes: Int) {
        self.sha256 = sha256
        self.width = width
        self.height = height
        self.bytes = bytes
    }

    public var jsonValue: JSONValue {
        .object(["sha256": .string(sha256), "w": .integer(Int64(width)), "h": .integer(Int64(height)), "bytes": .integer(Int64(bytes))])
    }

    /// The only URL form an asset has. `assetHost` must be a plain DNS name (the dedicated asset domain, never the API or link host).
    public func url(assetHost: String) -> URL? {
        guard LinkDomain(assetHost) != nil, ContractHash.isLowerHex64(sha256) else { return nil }
        return URL(string: "https://\(assetHost.lowercased())/b/\(sha256).png")
    }

    /// Whether this reference fits `slot`.
    public func fits(_ slot: BrandAssetSlot) -> Bool {
        ContractHash.isLowerHex64(sha256) && width >= 1 && height >= 1 && max(width, height) <= slot.maxDimension
            && bytes >= 1 && bytes <= slot.maxStoredBytes
    }
}

/// The ingestion policy for uploaded brand media (ADR-0017). Pure decisions the server's worker applies **before** decoding; the decoder,
/// re-encoder and scanner are server code (WP-2.2).
///
/// * Accepted inputs: **PNG and JPEG only**. SVG, HTML, XML, PDF, GIF, WebP, HEIC and everything unrecognized are refused; SVG with a
///   clear reason (`svg_refused`).
/// * The declared `Content-Type` and the magic bytes must agree.
/// * Size is capped before the body is read; dimensions are capped **before** any pixel buffer is allocated (decompression-bomb guard).
/// * Output is always a freshly encoded PNG (drops EXIF, ICC, text chunks and trailing bytes), stored and served by its SHA-256.
public enum BrandAssetPolicy {
    public static let maxUploadBytes = 2 * 1024 * 1024
    /// Largest accepted `width × height` of the decoded source.
    public static let maxSourcePixels = 25_000_000
    public static let maxSourceDimension = 8192
    public static let outputContentType = "image/png"

    public enum DetectedFormat: String, Sendable, Codable, Hashable {
        case png, jpeg, gif, webp, svg, html, xml, pdf, heic, unknown
    }

    public enum Rejection: String, Sendable, Codable, Hashable, Error {
        case tooLarge = "too_large"
        case empty
        case unsupportedFormat = "unsupported_format"
        case svgRefused = "svg_refused"
        case markupRefused = "markup_refused"
        case contentTypeMismatch = "content_type_mismatch"
        case dimensionsTooLarge = "dimensions_too_large"
        case dimensionsInvalid = "dimensions_invalid"
    }

    /// Format from the first bytes. Markup is detected after skipping a UTF-8 BOM and whitespace, case-insensitively.
    public static func sniff(_ prefix: Data) -> DetectedFormat {
        let b = [UInt8](prefix.prefix(64))
        if b.starts(with: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) { return .png }
        if b.starts(with: [0xFF, 0xD8, 0xFF]) { return .jpeg }
        if b.starts(with: Array("GIF8".utf8)) { return .gif }
        if b.count >= 12, b.starts(with: Array("RIFF".utf8)), Array(b[8..<12]) == Array("WEBP".utf8) { return .webp }
        if b.starts(with: Array("%PDF".utf8)) { return .pdf }
        if b.count >= 12, Array(b[4..<8]) == Array("ftyp".utf8) { return .heic }
        var start = 0
        if b.starts(with: [0xEF, 0xBB, 0xBF]) { start = 3 }
        while start < b.count, [0x20, 0x09, 0x0A, 0x0D].contains(b[start]) { start += 1 }
        let text = String(decoding: b[start...], as: UTF8.self).lowercased()
        if text.hasPrefix("<svg") || text.contains("<svg") { return .svg }
        if text.hasPrefix("<!doctype html") || text.hasPrefix("<html") || text.hasPrefix("<script") || text.hasPrefix("<body") { return .html }
        if text.hasPrefix("<?xml") || text.hasPrefix("<!doctype") || text.hasPrefix("<") { return text.contains("svg") ? .svg : .xml }
        return .unknown
    }

    /// Checks done before decoding: size, declared type, magic bytes and their agreement.
    public static func precheck(declaredContentType: String, byteCount: Int, prefix: Data) -> Result<DetectedFormat, Rejection> {
        guard byteCount > 0 else { return .failure(.empty) }
        guard byteCount <= maxUploadBytes else { return .failure(.tooLarge) }
        let detected = sniff(prefix)
        let declared = declaredContentType.split(separator: ";").first.map { $0.trimmingCharacters(in: .whitespaces).lowercased() } ?? ""
        switch detected {
        case .svg: return .failure(.svgRefused)
        case .html, .xml: return .failure(.markupRefused)
        case .png: return declared == "image/png" ? .success(.png) : .failure(.contentTypeMismatch)
        case .jpeg: return declared == "image/jpeg" ? .success(.jpeg) : .failure(.contentTypeMismatch)
        case .gif, .webp, .pdf, .heic, .unknown:
            return .failure(declared == "image/svg+xml" ? .svgRefused : .unsupportedFormat)
        }
    }

    /// Dimension guard, run on the header's declared size **before** allocating pixels.
    public static func checkSourceDimensions(width: Int, height: Int) -> Rejection? {
        guard width >= 1, height >= 1 else { return .dimensionsInvalid }
        guard width <= maxSourceDimension, height <= maxSourceDimension, width.multipliedReportingOverflow(by: height).partialValue <= maxSourcePixels,
              !width.multipliedReportingOverflow(by: height).overflow else { return .dimensionsTooLarge }
        return nil
    }

    /// Target size for `slot`, keeping aspect ratio (never upscales).
    public static func targetSize(width: Int, height: Int, slot: BrandAssetSlot) -> (width: Int, height: Int) {
        let longest = max(width, height)
        guard longest > slot.maxDimension else { return (width, height) }
        let scale = Double(slot.maxDimension) / Double(longest)
        return (max(1, Int((Double(width) * scale).rounded(.down))), max(1, Int((Double(height) * scale).rounded(.down))))
    }
}

import Crypto
import Foundation

/// One image attached to a conversation message (SECURITY.md §2.113). This is metadata only: the bytes are never inlined, never in a webhook
/// and never behind a public URL. They are fetched by id from the conversation's attachment route by a participant of that conversation.
///
/// Wire form (camelCase like every DTO): `{"id","sessionId","mediaType","byteSize","width","height","sha256","state","expiresAt"}`.
public struct MessageAttachment: Codable, Sendable, Hashable, Identifiable {
    public enum State: String, Codable, Sendable, Hashable {
        /// Uploaded to the conversation, not yet sent with a message. Expires at `expiresAt`.
        case pending
        /// Part of a sent message.
        case attached
    }

    public var id: AttachmentID
    /// The one conversation this image belongs to. It can only be sent, and fetched, there.
    public var sessionId: SessionID
    /// The type of the **stored, re-encoded** bytes: `image/png` or `image/jpeg` (never what the uploader declared).
    public var mediaType: String
    /// Size of the stored image in bytes.
    public var byteSize: Int
    public var width: Int
    public var height: Int
    /// Lowercase hex SHA-256 of the stored image bytes (what the download returns). A client can check what it received.
    public var sha256: String
    public var state: State
    /// When a pending upload stops being usable. `nil` once attached.
    public var expiresAt: Date?

    public init(id: AttachmentID, sessionId: SessionID, mediaType: String, byteSize: Int, width: Int, height: Int, sha256: String,
                state: State, expiresAt: Date? = nil) {
        self.id = id
        self.sessionId = sessionId
        self.mediaType = mediaType
        self.byteSize = byteSize
        self.width = width
        self.height = height
        self.sha256 = sha256
        self.state = state
        self.expiresAt = expiresAt
    }

    /// Whether `data` is exactly the image this reference describes (size and digest), as a client checks a download.
    public func matches(_ data: Data) -> Bool {
        data.count == byteSize && Hex.encode(Data(SHA256.hash(data: data))) == sha256
    }
}

/// The limits and pure decisions for message images (SECURITY.md §2.113). The server applies them with the Brand Kit decoder front end
/// (`BrandImagePipeline`, ADR-0017); the app applies `precheck` before it uploads so a refusal is explained without a round trip.
///
/// * **Images only in this pass:** PNG and JPEG in; SVG, HTML, GIF, WebP, HEIC, PDF and everything unrecognized refused.
/// * **2 MiB per upload**, the pipeline's existing cap (`BrandAssetPolicy.maxUploadBytes`), refused from `Content-Length` before the body is
///   read. A phone photo fits because the app re-encodes it on the device (longest side `maxStoredDimension`, JPEG) before upload.
/// * **Source dimensions** at most 8192 px per side and 25 megapixels (the pipeline's decompression-bomb guard, checked from the header
///   before any pixel buffer exists).
/// * **Stored image** at most 2048 px on the longest side (never upscaled) and 3 MiB, always freshly encoded: JPEG for opaque images, PNG
///   when the image has transparency. Nothing of the uploaded file but its pixels survives (no EXIF/GPS, ICC, XMP, text, comments).
/// * **At most 4 images per message**; at most 8 unsent uploads per conversation at a time; an unsent upload expires after 1 hour.
public enum MessageAttachmentPolicy {
    public static let maxPerMessage = 4
    public static let maxUploadBytes = BrandAssetPolicy.maxUploadBytes
    public static let maxSourceDimension = BrandAssetPolicy.maxSourceDimension
    public static let maxSourcePixels = BrandAssetPolicy.maxSourcePixels
    public static let maxStoredDimension = 2048
    public static let maxStoredBytes = 3 * 1024 * 1024
    public static let maxPendingPerSession = 8
    public static let pendingLifetime: TimeInterval = 3600
    /// The only types a stored attachment has (and the only types an upload may declare).
    public static let storedMediaTypes: Set<String> = ["image/png", "image/jpeg"]

    public typealias Rejection = BrandAssetPolicy.Rejection

    /// Size, declared type and magic bytes, before anything is decoded (the same rules as brand images).
    public static func precheck(declaredContentType: String, byteCount: Int, prefix: Data) -> Result<BrandAssetPolicy.DetectedFormat, Rejection> {
        BrandAssetPolicy.precheck(declaredContentType: declaredContentType, byteCount: byteCount, prefix: prefix)
    }

    /// The stored size for a decoded source, keeping aspect ratio and never upscaling.
    public static func targetSize(width: Int, height: Int) -> (width: Int, height: Int) {
        let longest = max(width, height)
        guard longest > maxStoredDimension else { return (width, height) }
        let scale = Double(maxStoredDimension) / Double(longest)
        return (max(1, Int((Double(width) * scale).rounded(.down))), max(1, Int((Double(height) * scale).rounded(.down))))
    }

    /// The ids a message may carry: 1…`maxPerMessage`, no duplicates. `nil` or empty is a text-only message.
    public static func validate(_ ids: [AttachmentID]?) -> Bool {
        guard let ids, !ids.isEmpty else { return true }
        return ids.count <= maxPerMessage && Set(ids).count == ids.count
    }

    /// What a person reads for a refusal (the app and the console; the reason code is what is counted).
    public static func message(_ rejection: Rejection) -> String {
        switch rejection {
        case .tooLarge: "That image is larger than 2 MB."
        case .empty: "That file is empty."
        case .unsupportedFormat, .svgRefused, .markupRefused: "Send a photo or a PNG or JPEG image."
        case .contentTypeMismatch: "The file's type does not match its contents. Send a real PNG or JPEG."
        case .dimensionsTooLarge: "That image is too large (at most 8192 pixels per side and 25 megapixels)."
        case .dimensionsInvalid: "That image has no valid size."
        case .truncated: "That file is incomplete."
        case .malformed, .trailingData, .decodeFailed: "That image could not be read."
        case .animated: "Animated images are not supported."
        case .outputTooLarge: "That image is too detailed to send. Try a smaller one."
        }
    }
}

/// Approved copy for images on channels that cannot carry them (docs/product/UX_COPY.md SMS-09, SMS-10, MSG-ATT-*). SMS and RCS never carry an
/// image and never a link to one: the text says that something is waiting in the app.
public enum MessageAttachmentCopy {
    /// SMS-09 (no message text) and SMS-10 (appended to the business's text). `business` is the verified display name.
    public static func smsNotice(business: String, count: Int) -> String {
        count == 1 ? "Viadere: \(business) sent you an image. Open the Viadere app to see it."
            : "Viadere: \(business) sent you \(count) images. Open the Viadere app to see them."
    }

    /// The text an SMS thread receives for a business message with `count` images.
    public static func smsText(body: String, business: String, count: Int) -> String {
        guard count > 0 else { return body }
        let notice = smsNotice(business: business, count: count)
        return body.isEmpty ? notice : body + "\n\n" + notice
    }

    /// MSG-ATT-01: the preview line of an image-only message in a thread list.
    public static func preview(count: Int) -> String { count == 1 ? "Image" : "\(count) images" }
}

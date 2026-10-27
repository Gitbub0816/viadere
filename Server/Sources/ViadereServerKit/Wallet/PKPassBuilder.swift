@preconcurrency import Crypto
import Foundation
import ViadereCore

/// Builds a `.pkpass`: `pass.json`, icons, `manifest.json` (SHA-1 of every file, Apple's format) and a detached `signature`.
enum PKPassBuilder {
    enum Failure: Error { case tooLarge }
    /// Wallet rejects anything near this size; the contract promises under 5 MB.
    static let maxBytes = 5 * 1024 * 1024

    /// The fixed icon set: `icon.png` is required for a pass to be valid.
    static func icons() -> [ZipArchive.Entry] {
        // Viadere champagne (#C9A96E) square; businesses get their own artwork later.
        [("icon.png", 29), ("icon@2x.png", 58), ("icon@3x.png", 87)].map { name, size in
            ZipArchive.Entry(name: name, data: MinimalPNG.solid(width: size, height: size, red: 0xC9, green: 0xA9, blue: 0x6E))
        }
    }

    /// `manifest.json`: file name → lowercase hex SHA-1, sorted so the bytes are deterministic.
    static func manifest(for files: [ZipArchive.Entry]) throws -> Data {
        var object: [String: String] = [:]
        for file in files { object[file.name] = Hex.encode(Insecure.SHA1.hash(data: file.data)) }
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    }

    static func build(passJSON: Data, signer: any PassSigner, at date: Date) throws -> Data {
        var files = [ZipArchive.Entry(name: "pass.json", data: passJSON)] + icons()
        let manifest = try manifest(for: files)
        let signature = try signer.sign(manifest: manifest, at: date)
        files.append(ZipArchive.Entry(name: "manifest.json", data: manifest))
        files.append(ZipArchive.Entry(name: "signature", data: signature))
        let archive = try ZipArchive.build(files)
        guard archive.count <= maxBytes else { throw Failure.tooLarge }
        return archive
    }
}

/// The pieces of `pass.json` the server controls. Contains no secrets beyond the per-pass `authenticationToken`, and no
/// personal data other than what the person's own pass shows (points, titles).
struct PassDescriptor {
    struct Field {
        enum Value { case text(String), number(Int) }
        var key: String
        var label: String
        var value: Value
    }

    var kind: WalletPassKind
    var passTypeIdentifier: String
    var teamIdentifier: String
    var serialNumber: String
    var authenticationToken: String
    var webServiceURL: String
    var organizationName: String
    var description: String
    var logoText: String?
    var primary: [Field] = []
    var secondary: [Field] = []
    var auxiliary: [Field] = []
    var back: [Field] = []
    var relevantDate: Date?
    var expirationDate: Date?
    var barcodeMessage: String?
    var voided = false

    /// Wallet's `pass.json` style key for each kind.
    static func styleKey(_ kind: WalletPassKind) -> String {
        switch kind {
        case .storeCard: "storeCard"
        case .coupon: "coupon"
        case .eventTicket: "eventTicket"
        case .boardingPass: "boardingPass"
        case .generic: "generic"
        }
    }

    func json() throws -> Data {
        func fields(_ list: [Field]) -> JSONValue {
            .array(list.map { field in
                var object: [String: JSONValue] = ["key": .string(field.key), "label": .string(field.label)]
                switch field.value {
                case .text(let text): object["value"] = .string(text)
                case .number(let number):
                    object["value"] = .integer(Int64(number))
                    object["numberStyle"] = .string("PKNumberStyleDecimal")
                }
                return .object(object)
            })
        }
        var style: [String: JSONValue] = [
            "primaryFields": fields(primary), "secondaryFields": fields(secondary),
            "auxiliaryFields": fields(auxiliary), "backFields": fields(back),
        ]
        if kind == .boardingPass { style["transitType"] = .string("PKTransitTypeAir") }
        var root: [String: JSONValue] = [
            "formatVersion": .integer(1),
            "passTypeIdentifier": .string(passTypeIdentifier),
            "teamIdentifier": .string(teamIdentifier),
            "serialNumber": .string(serialNumber),
            "organizationName": .string(organizationName),
            "description": .string(description),
            "authenticationToken": .string(authenticationToken),
            "webServiceURL": .string(webServiceURL),
            "backgroundColor": .string("rgb(31, 31, 31)"),
            "foregroundColor": .string("rgb(247, 243, 235)"),
            "labelColor": .string("rgb(201, 169, 110)"),
            Self.styleKey(kind): .object(style),
        ]
        if let logoText { root["logoText"] = .string(logoText) }
        if let relevantDate { root["relevantDate"] = .string(Self.wallet(relevantDate)) }
        if let expirationDate { root["expirationDate"] = .string(Self.wallet(expirationDate)) }
        if voided { root["voided"] = .bool(true) }
        if let barcodeMessage {
            let barcode: JSONValue = .object(["format": .string("PKBarcodeFormatQR"), "message": .string(barcodeMessage),
                                              "messageEncoding": .string("iso-8859-1")])
            root["barcodes"] = .array([barcode])
        }
        return try CanonicalJSON.serialize(.object(root))
    }

    /// W3C date-time without fractional seconds, UTC.
    static func wallet(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        formatter.timeZone = TimeZone(identifier: "UTC")
        return formatter.string(from: date)
    }
}

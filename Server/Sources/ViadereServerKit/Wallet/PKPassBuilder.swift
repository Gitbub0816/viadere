@preconcurrency import Crypto
import Foundation
import ViadereCore

/// Builds a `.pkpass`: `pass.json`, icons, localized `pass.strings`, `manifest.json` (SHA-1 of every file, Apple's format) and a
/// detached `signature`.
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

    static func build(passJSON: Data, signer: any PassSigner, at date: Date, localizations: [ZipArchive.Entry] = PassStrings.files()) throws -> Data {
        var files = [ZipArchive.Entry(name: "pass.json", data: passJSON)] + icons() + localizations
        let manifest = try manifest(for: files)
        let signature = try signer.sign(manifest: manifest, at: date)
        files.append(ZipArchive.Entry(name: "manifest.json", data: manifest))
        files.append(ZipArchive.Entry(name: "signature", data: signature))
        let archive = try ZipArchive.build(files)
        guard archive.count <= maxBytes else { throw Failure.tooLarge }
        return archive
    }
}

/// The fixed texts of a pass (labels, the beta note, change notices), localized through `<language>.lproj/pass.strings`.
///
/// The key **is** the English text, so a device whose language has no folder still shows English rather than a raw key. Business
/// content (names, offer titles, venues) is never in this table: it is shown as the business wrote it. Apple asks for UTF-16 files
/// when the text is not ASCII (checked 2026-10-31, "Creating the source for a pass"); every file is UTF-16LE with a byte-order mark.
enum PassStrings {
    static let languages = ["en", "es", "fr"]

    static let points = "POINTS", status = "STATUS", program = "PROGRAM", offer = "OFFER", details = "DETAILS", event = "EVENT"
    static let flight = "FLIGHT", reservation = "RESERVATION", venue = "VENUE", seat = "SEAT", starts = "STARTS", reward = "REWARD"
    static let issuedBy = "ISSUED BY", deliveredBy = "DELIVERED BY", entry = "ENTRY", checkedIn = "Checked in", about = "ABOUT"
    static let beta = "Wallet passes from Viadere are in beta."
    static let venueChanged = "Venue changed to %@", seatChanged = "Seat changed to %@", startChanged = "Start time changed to %@"

    /// English key → [es, fr].
    static let table: [(String, String, String)] = [
        (points, "PUNTOS", "POINTS"),
        (status, "NIVEL", "STATUT"),
        (program, "PROGRAMA", "PROGRAMME"),
        (offer, "OFERTA", "OFFRE"),
        (details, "DETALLES", "DÉTAILS"),
        (event, "EVENTO", "ÉVÉNEMENT"),
        (flight, "VUELO", "VOL"),
        (reservation, "RESERVA", "RÉSERVATION"),
        (venue, "LUGAR", "LIEU"),
        (seat, "ASIENTO", "PLACE"),
        (starts, "COMIENZA", "DÉBUT"),
        (reward, "RECOMPENSA", "RÉCOMPENSE"),
        (issuedBy, "EMITIDO POR", "ÉMIS PAR"),
        (deliveredBy, "ENVIADO POR", "TRANSMIS PAR"),
        (entry, "ENTRADA", "ENTRÉE"),
        (checkedIn, "Registrado", "Enregistré"),
        (about, "ACERCA DE", "À PROPOS"),
        (beta, "Los pases de Wallet de Viadere están en fase beta.", "Les cartes Wallet de Viadere sont en version bêta."),
        (venueChanged, "Lugar cambiado a %@", "Nouveau lieu : %@"),
        (seatChanged, "Asiento cambiado a %@", "Nouvelle place : %@"),
        (startChanged, "Nueva hora de inicio: %@", "Nouvel horaire : %@"),
    ]

    static func strings(for language: String) -> String {
        let column: (String, String, String) -> String = switch language {
        case "es": { _, es, _ in es }
        case "fr": { _, _, fr in fr }
        default: { en, _, _ in en }
        }
        func quoted(_ text: String) -> String {
            "\"" + text.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
        }
        return table.map { row in "\(quoted(row.0)) = \(quoted(column(row.0, row.1, row.2)));" }.joined(separator: "\n") + "\n"
    }

    /// UTF-16 little-endian with a BOM.
    static func utf16(_ text: String) -> Data {
        var data = Data([0xFF, 0xFE])
        for unit in text.utf16 { data.append(UInt8(unit & 0xFF)); data.append(UInt8(unit >> 8)) }
        return data
    }

    static func files() -> [ZipArchive.Entry] {
        languages.map { ZipArchive.Entry(name: "\($0).lproj/pass.strings", data: utf16(strings(for: $0))) }
    }
}

/// The pieces of `pass.json` the server controls. Contains no secrets beyond the per-pass `authenticationToken`, and no
/// personal data other than what the person's own pass shows (points, titles, their ticket's venue and seat).
struct PassDescriptor {
    struct Field {
        enum Value { case text(String), number(Int), date(Date) }
        var key: String
        /// A `PassStrings` key (English text).
        var label: String
        var value: Value
        /// A `PassStrings` change notice (`… %@`). Only operational fields (venue, seat, start time) have one: pass updates are never
        /// used to put marketing text on someone's lock screen.
        var changeMessage: String?

        init(key: String, label: String, value: Value, changeMessage: String? = nil) {
            self.key = key
            self.label = label
            self.value = value
            self.changeMessage = changeMessage
        }
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
    /// iOS 18+ relevance interval (`relevantDates`); `relevantDate` stays for iOS 17.
    var relevantInterval: (start: Date, end: Date)?
    var expirationDate: Date?
    /// The signed presentation code (`WalletScanCode`). Absent on a void pass, so a void pass shows nothing to scan.
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
                case .date(let date):
                    object["value"] = .string(Self.wallet(date))
                    object["dateStyle"] = .string("PKDateStyleMedium")
                    object["timeStyle"] = .string("PKDateStyleShort")
                }
                if let message = field.changeMessage { object["changeMessage"] = .string(message) }
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
            // A pass is personal (a single-use coupon, a ticket): Wallet hides its Share button.
            "sharingProhibited": .bool(true),
            Self.styleKey(kind): .object(style),
        ]
        if let logoText { root["logoText"] = .string(logoText) }
        if let relevantDate { root["relevantDate"] = .string(Self.wallet(relevantDate)) }
        if let relevantInterval {
            root["relevantDates"] = .array([.object(["startDate": .string(Self.wallet(relevantInterval.start)),
                                                     "endDate": .string(Self.wallet(relevantInterval.end))])])
        }
        if let expirationDate { root["expirationDate"] = .string(Self.wallet(expirationDate)) }
        if voided { root["voided"] = .bool(true) }
        if let barcodeMessage, !voided {
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

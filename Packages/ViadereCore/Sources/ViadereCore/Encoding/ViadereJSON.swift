import Foundation

/// The shared JSON configuration for every Viadere wire type.
///
/// - Dates: `ViadereDate` ISO-8601 UTC with milliseconds.
/// - Keys: camelCase, sorted on output; no slash escaping.
/// - Typed IDs encode as lowercase UUID strings.
///
/// Encoders/decoders are created per call because `JSONEncoder` is a reference type.
public enum ViadereJSON {
    /// A freshly configured encoder.
    public static var encoder: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .custom { date, encoder in
            var container = encoder.singleValueContainer()
            try container.encode(ViadereDate.format(date))
        }
        return encoder
    }

    /// A freshly configured decoder.
    public static var decoder: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom { decoder in
            let container = try decoder.singleValueContainer()
            let string = try container.decode(String.self)
            guard let date = ViadereDate.parse(string) else {
                throw DecodingError.dataCorruptedError(in: container, debugDescription: "Invalid ISO-8601 date: \(string)")
            }
            return date
        }
        return decoder
    }

    /// Encodes `value` with the shared configuration.
    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        try encoder.encode(value)
    }

    /// Decodes `type` with the shared configuration.
    public static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        try decoder.decode(type, from: data)
    }
}

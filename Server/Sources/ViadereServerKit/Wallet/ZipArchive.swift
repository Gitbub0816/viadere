import Foundation

/// CRC-32 (IEEE 802.3), as used by ZIP and PNG.
enum CRC32 {
    private static let table: [UInt32] = (0..<256).map { index in
        var value = UInt32(index)
        for _ in 0..<8 { value = (value & 1) == 1 ? (0xEDB8_8320 ^ (value >> 1)) : (value >> 1) }
        return value
    }

    static func checksum(_ data: some Sequence<UInt8>) -> UInt32 {
        var crc: UInt32 = 0xFFFF_FFFF
        for byte in data { crc = table[Int((crc ^ UInt32(byte)) & 0xFF)] ^ (crc >> 8) }
        return ~crc
    }
}

/// Writes a ZIP archive using only the "stored" method (no compression). A `.pkpass` is a small ZIP of tiny files, so
/// storing is fine, the output is byte-for-byte deterministic, and there is no decompression attack surface.
/// Timestamps are fixed (1980-01-01) so the same input always produces the same bytes.
enum ZipArchive {
    struct Entry {
        var name: String
        var data: Data
    }

    enum Failure: Error { case tooLarge, badName }

    static func build(_ entries: [Entry]) throws -> Data {
        guard entries.count < 0xFFFF else { throw Failure.tooLarge }
        var out = Data()
        var central = Data()
        for entry in entries {
            let name = Data(entry.name.utf8)
            // Flat names only: no directories, no traversal, no absolute paths.
            guard !name.isEmpty, name.count < 256, !entry.name.contains("/"), !entry.name.contains("\\"), !entry.name.hasPrefix(".") else {
                throw Failure.badName
            }
            guard entry.data.count < 0x7FFF_FFFF, out.count < 0x7FFF_FFFF else { throw Failure.tooLarge }
            let crc = CRC32.checksum(entry.data)
            let offset = UInt32(out.count)
            // Local file header.
            out.append(le32: 0x0403_4B50)
            out.append(le16: 20)          // version needed
            out.append(le16: 0)           // flags
            out.append(le16: 0)           // method: stored
            out.append(le16: 0)           // mod time 00:00:00
            out.append(le16: 0x0021)      // mod date 1980-01-01
            out.append(le32: crc)
            out.append(le32: UInt32(entry.data.count))
            out.append(le32: UInt32(entry.data.count))
            out.append(le16: UInt16(name.count))
            out.append(le16: 0)           // extra length
            out.append(name)
            out.append(entry.data)
            // Central directory header.
            central.append(le32: 0x0201_4B50)
            central.append(le16: 20)      // version made by
            central.append(le16: 20)      // version needed
            central.append(le16: 0)
            central.append(le16: 0)
            central.append(le16: 0)
            central.append(le16: 0x0021)
            central.append(le32: crc)
            central.append(le32: UInt32(entry.data.count))
            central.append(le32: UInt32(entry.data.count))
            central.append(le16: UInt16(name.count))
            central.append(le16: 0)       // extra
            central.append(le16: 0)       // comment
            central.append(le16: 0)       // disk number
            central.append(le16: 0)       // internal attributes
            central.append(le32: 0)       // external attributes
            central.append(le32: offset)
            central.append(name)
        }
        let centralOffset = UInt32(out.count)
        out.append(central)
        out.append(le32: 0x0605_4B50)
        out.append(le16: 0)
        out.append(le16: 0)
        out.append(le16: UInt16(entries.count))
        out.append(le16: UInt16(entries.count))
        out.append(le32: UInt32(central.count))
        out.append(le32: centralOffset)
        out.append(le16: 0)
        return out
    }

    /// Reads a stored-only archive (as written by `build`). Verifies the central directory, bounds and CRC of every entry.
    /// Used by tests and by `PKPassVerifier`.
    static func read(_ data: Data) throws -> [Entry] {
        let bytes = [UInt8](data)
        guard bytes.count >= 22 else { throw Failure.badName }
        // End of central directory is the last 22 bytes (we never write a comment).
        let end = bytes.count - 22
        guard le32(bytes, end) == 0x0605_4B50 else { throw Failure.badName }
        let count = Int(le16(bytes, end + 10))
        var cursor = Int(le32(bytes, end + 16))
        var entries: [Entry] = []
        for _ in 0..<count {
            guard cursor + 46 <= bytes.count, le32(bytes, cursor) == 0x0201_4B50 else { throw Failure.badName }
            let method = le16(bytes, cursor + 10)
            let crc = le32(bytes, cursor + 16)
            let size = Int(le32(bytes, cursor + 24))
            let nameLength = Int(le16(bytes, cursor + 28))
            let extra = Int(le16(bytes, cursor + 30))
            let comment = Int(le16(bytes, cursor + 32))
            let local = Int(le32(bytes, cursor + 42))
            guard method == 0, cursor + 46 + nameLength <= bytes.count, local + 30 <= bytes.count, le32(bytes, local) == 0x0403_4B50 else {
                throw Failure.badName
            }
            let name = String(decoding: bytes[(cursor + 46)..<(cursor + 46 + nameLength)], as: UTF8.self)
            let start = local + 30 + Int(le16(bytes, local + 26)) + Int(le16(bytes, local + 28))
            guard start + size <= bytes.count else { throw Failure.badName }
            let body = Data(bytes[start..<(start + size)])
            guard CRC32.checksum(body) == crc else { throw Failure.badName }
            entries.append(Entry(name: name, data: body))
            cursor += 46 + nameLength + extra + comment
        }
        return entries
    }

    private static func le16(_ b: [UInt8], _ i: Int) -> UInt16 { UInt16(b[i]) | UInt16(b[i + 1]) << 8 }
    private static func le32(_ b: [UInt8], _ i: Int) -> UInt32 {
        UInt32(b[i]) | UInt32(b[i + 1]) << 8 | UInt32(b[i + 2]) << 16 | UInt32(b[i + 3]) << 24
    }
}

private extension Data {
    mutating func append(le16 value: UInt16) { append(contentsOf: [UInt8(value & 0xFF), UInt8(value >> 8)]) }
    mutating func append(le32 value: UInt32) {
        append(contentsOf: [UInt8(value & 0xFF), UInt8((value >> 8) & 0xFF), UInt8((value >> 16) & 0xFF), UInt8(value >> 24)])
    }
}

/// A solid-colour PNG, written without a compressor (stored deflate blocks). Wallet requires `icon.png`; this keeps the
/// pass valid without shipping binary assets in the repository.
enum MinimalPNG {
    static func solid(width: Int, height: Int, red: UInt8, green: UInt8, blue: UInt8) -> Data {
        var raw = Data()
        let row = Data([0] + (0..<width).flatMap { _ in [red, green, blue] })
        for _ in 0..<height { raw.append(row) }
        // zlib stream: header, stored blocks, Adler-32.
        var z = Data([0x78, 0x01])
        var offset = 0
        while offset < raw.count || offset == 0 {
            let length = min(65_535, raw.count - offset)
            let final: UInt8 = offset + length >= raw.count ? 1 : 0
            z.append(final)
            z.append(contentsOf: [UInt8(length & 0xFF), UInt8(length >> 8), UInt8(~length & 0xFF), UInt8((~length >> 8) & 0xFF)])
            z.append(raw[offset..<(offset + length)])
            offset += length
            if final == 1 { break }
        }
        z.append(be32: adler32(raw))
        var png = Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
        var header = Data()
        header.append(be32: UInt32(width))
        header.append(be32: UInt32(height))
        header.append(contentsOf: [8, 2, 0, 0, 0])
        png.append(chunk: "IHDR", header)
        png.append(chunk: "IDAT", z)
        png.append(chunk: "IEND", Data())
        return png
    }

    private static func adler32(_ data: Data) -> UInt32 {
        var a: UInt32 = 1, b: UInt32 = 0
        for byte in data {
            a = (a + UInt32(byte)) % 65_521
            b = (b + a) % 65_521
        }
        return (b << 16) | a
    }
}

private extension Data {
    mutating func append(be32 value: UInt32) {
        append(contentsOf: [UInt8(value >> 24), UInt8((value >> 16) & 0xFF), UInt8((value >> 8) & 0xFF), UInt8(value & 0xFF)])
    }

    mutating func append(chunk type: String, _ body: Data) {
        append(be32: UInt32(body.count))
        let typed = Data(type.utf8) + body
        append(typed)
        append(be32: CRC32.checksum(typed))
    }
}

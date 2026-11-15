import Crypto
import Foundation
import Testing
@testable import ViadereCore

/// CKey Safe Actions against the CKey conformance vectors (`docs/protocol/vectors/ckey-safe-actions-v1.json`, copied unchanged from
/// clearkeysolutions/ckey `tests/vectors/safe-actions-v1.json`) and the attacks the envelope rules exist for.
@Suite struct CKeySafeActionTests {
    struct Vectors: Decodable {
        struct Fields: Decodable {
            let scope: UInt8, issuer: String, app: String, action: String, key_id: String, request_id: String
            let issued_at: UInt64, expires_at: UInt64, params: String
        }
        struct Vector: Decodable {
            let name: String, payload: String, public_key: String, now: Double, max_lifetime: Int, expect: String
            let fields: Fields?
        }
        let vectors: [Vector]
    }

    static func load() throws -> [Vectors.Vector] {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { url.deleteLastPathComponent() }
        return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: url.appendingPathComponent("docs/protocol/vectors/ckey-safe-actions-v1.json"))).vectors
    }

    static func hex(_ text: String) -> Data { Data(CKeySymbolTests.bytes(text)) }

    // RFC 8032 §7.1 test 1: the key the vectors use.
    static let seed = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    static let publicKey = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    static let now = Date(timeIntervalSince1970: 1_794_000_000)

    static func action(scope: CKeySafeAction.Scope = .crossDevice, issuer: String = "viadere.com", app: String = "com.viadere.app", action: String = "signin.request",
                       keyId: String = "2026-11", requestId: String = "ach_AAECAwQFBgcICQoLDA0ODw", issuedAt: UInt64 = 1_794_000_000,
                       expiresAt: UInt64 = 1_794_000_120, params: Data = Data()) -> CKeySafeAction {
        CKeySafeAction(scope: scope, issuer: issuer, app: app, action: action, keyId: keyId, requestId: requestId, issuedAt: issuedAt, expiresAt: expiresAt, params: params)
    }

    /// Re-encodes an envelope after changing its bytes (the signature is left as it was unless the closure touches it).
    static func mutate(_ text: String, _ change: (inout [UInt8]) -> Void) -> String {
        var bytes = CKeySafeAction.base64URLDecode(Array(text.utf8)[CKeySafeAction.prefix.utf8.count...])!
        change(&bytes)
        return CKeySafeAction.prefix + CKeySafeAction.base64URLEncode(bytes)
    }

    static func verdictName(_ verdict: CKeySafeAction.Verdict) -> String {
        switch verdict {
        case .ok: "ok"
        case .invalid: "invalid"
        case .integrity: "integrity"
        case .expired: "expired"
        }
    }

    @Test func everyConformanceVectorReachesItsVerdict() throws {
        let vectors = try Self.load()
        #expect(vectors.count == 22)
        #expect(Set(vectors.map(\.expect)) == ["ok", "integrity", "expired", "invalid", "invalid_or_integrity"])
        for vector in vectors {
            let verdict = CKeySafeAction.verify(text: vector.payload, publicKey: Self.hex(vector.public_key), now: Date(timeIntervalSince1970: vector.now),
                                                maxLifetime: vector.max_lifetime)
            let name = Self.verdictName(verdict)
            if vector.expect == "invalid_or_integrity" {
                #expect(name == "invalid" || name == "integrity", "\(vector.name)")
            } else {
                #expect(name == vector.expect, "\(vector.name)")
            }
            guard case .ok(let action) = verdict else { #expect(vector.expect != "ok", "\(vector.name)"); continue }
            let fields = try #require(vector.fields, "\(vector.name)")
            #expect(action == CKeySafeAction(scope: CKeySafeAction.Scope(rawValue: fields.scope)!, issuer: fields.issuer, app: fields.app, action: fields.action,
                                             keyId: fields.key_id, requestId: fields.request_id, issuedAt: fields.issued_at, expiresAt: fields.expires_at,
                                             params: Data(fields.params.utf8)), "\(vector.name)")
            #expect(try CKeySafeAction.parse(text: vector.payload) == action)
        }
    }

    @Test func aSignedEnvelopeVerifiesAndReproducesTheReferenceBytes() throws {
        // The vectors' cross-device sign-in, signed again here from its fields with the same key: Ed25519 is deterministic on Linux, so the
        // text must be the reference's byte for byte.
        let vector = try #require(try Self.load().first { $0.name == "valid cross-device sign-in, no params" })
        let fields = try #require(vector.fields)
        let action = CKeySafeAction(scope: .crossDevice, issuer: fields.issuer, app: fields.app, action: fields.action, keyId: fields.key_id,
                                    requestId: fields.request_id, issuedAt: fields.issued_at, expiresAt: fields.expires_at)
        let text = try action.signed(seed: Self.seed)
        #expect(CKeySafeAction.verify(text: text, publicKey: Self.publicKey, now: Self.now) == .ok(action))
        #if os(Linux)
        #expect(text == vector.payload)
        #endif
        #expect(try Curve25519.Signing.PrivateKey(rawRepresentation: Self.seed).publicKey.rawRepresentation == Self.publicKey)
    }

    @Test func aViadereSignInEnvelopeRoundTrips() throws {
        let action = Self.action()
        let text = try action.signed(seed: Self.seed)
        #expect(CKeySafeAction.isSafeAction(text))
        #expect(try CKeySafeAction.parse(text: text) == action)
        #expect(CKeySafeAction.verify(text: text, publicKey: Self.publicKey, now: Self.now, maxLifetime: 120) == .ok(action))
    }

    @Test func aWrongKeyOrAnyChangedByteFailsIntegrity() throws {
        let text = try Self.action().signed(seed: Self.seed)
        let other = Curve25519.Signing.PrivateKey().publicKey.rawRepresentation
        #expect(CKeySafeAction.verify(text: text, publicKey: other, now: Self.now) == .integrity)
        #expect(CKeySafeAction.verify(text: text, publicKey: Data(Self.publicKey.prefix(31)), now: Self.now) == .integrity)
        #expect(CKeySafeAction.verify(text: text, publicKey: Data(), now: Self.now) == .integrity)
        let envelope = CKeySafeAction.base64URLDecode(Array(text.utf8)[CKeySafeAction.prefix.utf8.count...])!
        // Every single-bit change either breaks the form or the signature; none verifies.
        for index in envelope.indices {
            let changed = Self.mutate(text) { $0[index] ^= 0x01 }
            let verdict = CKeySafeAction.verify(text: changed, publicKey: Self.publicKey, now: Self.now)
            #expect(verdict == .invalid || verdict == .integrity, "byte \(index)")
        }
        // Scope flipped from cross-device to same-device after signing: the dangerous downgrade.
        #expect(CKeySafeAction.verify(text: Self.mutate(text) { $0[1] = 0 }, publicKey: Self.publicKey, now: Self.now) == .integrity)
    }

    @Test func aNonCanonicalScalarIsRefusedBeforeTheLibrarySeesIt() throws {
        let text = try Self.action().signed(seed: Self.seed)
        // S + L: the same point equation holds, so a lax verifier accepts a second signature for the same message.
        var carried = -1
        let malleable = Self.mutate(text) { bytes in
            var carry = 0
            for index in 0..<32 {
                let sum = Int(bytes[bytes.count - 32 + index]) + Int(CKeySafeAction.groupOrder[index]) + carry
                bytes[bytes.count - 32 + index] = UInt8(sum & 0xFF)
                carry = sum >> 8
            }
            carried = carry
        }
        #expect(carried == 0)
        #expect(malleable != text)
        #expect(CKeySafeAction.verify(text: malleable, publicKey: Self.publicKey, now: Self.now) == .integrity)
        // The scalar check itself: L and above are out, L - 1 and zero are in.
        let order = CKeySafeAction.groupOrder
        #expect(!CKeySafeAction.isCanonicalScalar(order[...]))
        var below = order; below[0] -= 1
        #expect(CKeySafeAction.isCanonicalScalar(below[...]))
        var above = order; above[0] += 1
        #expect(!CKeySafeAction.isCanonicalScalar(above[...]))
        #expect(!CKeySafeAction.isCanonicalScalar([UInt8](repeating: 0xFF, count: 32)[...]))
        #expect(CKeySafeAction.isCanonicalScalar([UInt8](repeating: 0, count: 32)[...]))
        #expect(!CKeySafeAction.isCanonicalScalar([UInt8](repeating: 0, count: 31)[...]))
    }

    @Test func theTextFormHasExactlyOneSpelling() throws {
        let text = try Self.action().signed(seed: Self.seed)
        let key = Self.publicKey
        func invalid(_ candidate: String, _ note: String) {
            #expect(CKeySafeAction.verify(text: candidate, publicKey: key, now: Self.now) == .invalid, "\(note)")
            #expect(throws: CKeySafeAction.ParseError.self, "\(note)") { try CKeySafeAction.parse(text: candidate) }
        }
        invalid(text + "=", "padding")
        invalid(text + "==", "padding")
        invalid(text + "A", "trailing character")
        invalid(text + "AAAA", "three bytes after the signature")
        invalid(text + " ", "trailing space")
        invalid(" " + text, "leading space")
        invalid(text + "\n", "trailing newline")
        invalid(text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/") + "+", "the standard alphabet")
        invalid("CKEY-ACTION:1:" + text.dropFirst(14), "upper-case prefix")
        invalid("ckey-action:2:" + text.dropFirst(14), "another version")
        invalid("ckey-action:1:", "nothing after the prefix")
        invalid("ckey-action:1", "no envelope")
        invalid("", "empty")
        invalid(String(text.dropLast()), "one character short")
        invalid(Self.mutate(text) { $0.append(0) }, "a byte after the signature")
        invalid(Self.mutate(text) { $0.removeLast() }, "63 signature bytes")
        invalid(Self.mutate(text) { $0.removeLast(64) }, "no signature")
        invalid(Self.mutate(text) { $0[0] = 2 }, "envelope version 2")
        invalid(Self.mutate(text) { $0[0] = 0 }, "envelope version 0")
        invalid(Self.mutate(text) { $0[1] = 2 }, "scope byte 2")
        invalid(Self.mutate(text) { $0[1] = 0xFF }, "scope byte 255")
        invalid(CKeySafeAction.prefix + String(repeating: "A", count: 4097), "longer than the reference accepts")
        // Non-zero unused bits in the last character: the same bytes spelled differently.
        let odd = try Self.action(keyId: "2026-1").signed(seed: Self.seed)
        #expect((odd.utf8.count - CKeySafeAction.prefix.utf8.count) % 4 != 0, "the test envelope must leave unused bits")
        #expect(CKeySafeAction.verify(text: odd, publicKey: key, now: Self.now) == .ok(Self.action(keyId: "2026-1")))
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        let last = try #require(odd.last)
        let index = try #require(alphabet.firstIndex(of: last))
        invalid(String(odd.dropLast()) + String(alphabet[index ^ 1]), "non-canonical tail")
    }

    @Test func everyFieldRuleOfTheEnvelopeTableIsEnforced() throws {
        func refused(_ action: CKeySafeAction, _ field: CKeySafeAction.Field, _ note: String) {
            #expect(throws: CKeySafeAction.SigningError.invalidFields(.field(field)), "\(note)") { try action.signed(seed: Self.seed) }
        }
        func accepted(_ action: CKeySafeAction, _ note: String) throws {
            let text = try action.signed(seed: Self.seed)
            #expect(CKeySafeAction.verify(text: text, publicKey: Self.publicKey, now: Self.now) == .ok(action), "\(note)")
        }
        // issuer: a lower-case DNS name with a dot, 1 to 253 bytes.
        for bad in ["", "localhost", "Viadere.com", "viadere.com.", ".viadere.com", "viadere..com", "viadere_x.com", "viadere.com/x", "viadere.com:443",
                    "viad\u{0435}re.com", "viadere com", "*.viadere.com", String(repeating: "a", count: 250) + ".com"] {
            refused(Self.action(issuer: bad), .issuer, "issuer \(bad.prefix(20))")
        }
        try accepted(Self.action(issuer: String(repeating: "a", count: 249) + ".com"), "253-byte issuer")
        try accepted(Self.action(issuer: "a.b"), "shortest issuer")
        // app: letters, digits, `.`, `_`, `-`; 1 to 255.
        for bad in ["", "com.viadere app", "com.viadere/app", "com.viadere.app\u{0}", "com.viad\u{00E8}re.app", String(repeating: "a", count: 256)] {
            refused(Self.action(app: bad), .app, "app \(bad.prefix(20))")
        }
        try accepted(Self.action(app: String(repeating: "A", count: 255)), "255-byte app")
        // action: lower case only; 1 to 64.
        for bad in ["", "Signin.request", "signin request", "signin:request", "signin/request", String(repeating: "a", count: 65)] {
            refused(Self.action(action: bad), .action, "action \(bad.prefix(20))")
        }
        try accepted(Self.action(action: String(repeating: "a", count: 64)), "64-byte action")
        // key_id: 1 to 32.
        for bad in ["", "2026 11", "2026/11", "2026:11", String(repeating: "k", count: 33)] {
            refused(Self.action(keyId: bad), .keyId, "key id \(bad.prefix(20))")
        }
        try accepted(Self.action(keyId: String(repeating: "K", count: 32)), "32-byte key id")
        // request_id: no dot; 8 to 64.
        for bad in ["", "1234567", "ach.AAECAwQFBgc", "ach AAECAwQFBgc", "ach/AAECAwQFBgc", "ach+AAECAwQFBgc", String(repeating: "r", count: 65)] {
            refused(Self.action(requestId: bad), .requestId, "request id \(bad.prefix(20))")
        }
        try accepted(Self.action(requestId: "12345678"), "8-byte request id")
        try accepted(Self.action(requestId: String(repeating: "r", count: 64)), "64-byte request id")
        // params: at most 1024 bytes.
        try accepted(Self.action(params: Data(repeating: 0x7B, count: 1024)), "1024-byte params")
        #expect(throws: CKeySafeAction.SigningError.invalidFields(.paramsTooLong)) { try Self.action(params: Data(repeating: 0x7B, count: 1025)).signed(seed: Self.seed) }
        // An issuer never signs a lifetime that is not positive, and a bad seed signs nothing.
        #expect(throws: CKeySafeAction.SigningError.invalidFields(.lifetime)) { try Self.action(issuedAt: 10, expiresAt: 10).signed(seed: Self.seed) }
        #expect(throws: CKeySafeAction.SigningError.invalidSeed) { try Self.action().signed(seed: Data(repeating: 1, count: 31)) }
    }

    @Test func aChangedByteInsideAFieldNeverParsesAsAnotherAction() throws {
        let text = try Self.action().signed(seed: Self.seed)
        // The issuer's first letter in upper case (as the vectors do), without going through the signer.
        let upper = Self.mutate(text) { $0[3] = UInt8(ascii: "V") }
        #expect(throws: CKeySafeAction.ParseError.field(.issuer)) { try CKeySafeAction.parse(text: upper) }
        #expect(CKeySafeAction.verify(text: upper, publicKey: Self.publicKey, now: Self.now) == .invalid)
        // The params length claims more bytes than there are.
        let long = Self.mutate(text) { $0[$0.count - 65] = 0xFF }
        #expect(CKeySafeAction.verify(text: long, publicKey: Self.publicKey, now: Self.now) == .invalid)
    }

    @Test func timeRulesMatchTheReference() throws {
        let key = Self.publicKey
        func at(_ seconds: TimeInterval, issued: UInt64 = 1_794_000_000, expires: UInt64 = 1_794_000_120, max: Int = 120) throws -> CKeySafeAction.Verdict {
            // Built without the signer's lifetime check so "expires before issued" can be signed for the test.
            let action = Self.action(issuedAt: issued, expiresAt: expires)
            var body: [UInt8] = [1, 1]
            for value in [action.issuer, action.app, action.action, action.keyId, action.requestId] { body += [UInt8(value.utf8.count)] + Array(value.utf8) }
            body += CKeySafeAction.bigEndian(issued) + CKeySafeAction.bigEndian(expires) + [0, 0]
            let signature = try Curve25519.Signing.PrivateKey(rawRepresentation: Self.seed).signature(for: Data(CKeySafeAction.signingContext + body))
            return CKeySafeAction.verify(text: CKeySafeAction.prefix + CKeySafeAction.base64URLEncode(body + signature), publicKey: key,
                                         now: Date(timeIntervalSince1970: seconds), maxLifetime: max)
        }
        func ok(_ verdict: CKeySafeAction.Verdict) -> Bool { if case .ok = verdict { return true } else { return false } }
        #expect(ok(try at(1_794_000_000)))
        #expect(ok(try at(1_794_000_119)))
        // Dead at expires_at: no grace after expiry.
        #expect(try at(1_794_000_120) == .expired)
        #expect(try at(1_794_000_121) == .expired)
        // Issued up to 120 s in the future is tolerated (a slow phone clock), one second more is not.
        #expect(ok(try at(1_793_999_880)))
        #expect(try at(1_793_999_879) == .expired)
        // Lifetime against the app's limit.
        #expect(ok(try at(1_794_000_000, expires: 1_794_000_120, max: 120)))
        #expect(try at(1_794_000_000, expires: 1_794_000_121, max: 120) == .expired)
        #expect(try at(1_794_000_000, expires: 1_794_003_601, max: 3600) == .expired)
        #expect(try at(1_794_000_000, expires: 1_794_000_000) == .expired)
        #expect(try at(1_794_000_000, expires: 1_793_999_999) == .expired)
        #expect(try at(1_794_000_000, issued: 0, expires: UInt64.max, max: 3600) == .expired)
        #expect(try at(-1) == .expired)
        // The app's limit itself must be 1...3600.
        #expect(try at(1_794_000_000, max: 0) == .invalid)
        #expect(try at(1_794_000_000, max: 3601) == .invalid)
        #expect(try at(1_794_000_000, max: -5) == .invalid)
        #expect(ok(try at(1_794_000_000, expires: 1_794_000_001, max: 1)))
        // A public `parse` refuses a non-positive lifetime outright.
        let reversed = try #require(try Self.load().first { $0.name == "expires before it is issued" })
        #expect(throws: CKeySafeAction.ParseError.lifetime) { try CKeySafeAction.parse(text: reversed.payload) }
    }

    // MARK: ES256 (CKey 0.1.0-build.118+, `docs/protocol/vectors/ckey-safe-actions-es256-v1.json` copied unchanged from the CKey scratch branch)

    struct ES256Vectors: Decodable {
        struct Vector: Decodable {
            let name: String, alg: String, payload: String, public_key: String, now: Double, max_lifetime: Int, expect: String
            let fields: Vectors.Fields?
        }
        let vectors: [Vector]
    }

    static func loadES256() throws -> [ES256Vectors.Vector] {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { url.deleteLastPathComponent() }
        return try JSONDecoder().decode(ES256Vectors.self, from: Data(contentsOf: url.appendingPathComponent("docs/protocol/vectors/ckey-safe-actions-es256-v1.json"))).vectors
    }

    /// A key that cannot be made is `invalid` (the vectors' verdict for an off-curve point or a wrong length); otherwise `verify` decides.
    static func verdict(alg: String, publicKeyHex: String, payload: String, now: Double, maxLifetime: Int) -> String {
        guard let key = try? CKeySafeAction.PublicKey(alg: alg, hex: publicKeyHex) else { return "invalid" }
        return verdictName(CKeySafeAction.verify(text: payload, key: key, now: Date(timeIntervalSince1970: now), maxLifetime: maxLifetime))
    }

    @Test func everyES256ConformanceVectorReachesItsVerdict() throws {
        let vectors = try Self.loadES256()
        #expect(vectors.count == 9)
        #expect(Set(vectors.map(\.expect)) == ["ok", "integrity", "expired", "invalid"])
        for vector in vectors {
            #expect(vector.alg == "ES256")
            let name = Self.verdict(alg: vector.alg, publicKeyHex: vector.public_key, payload: vector.payload, now: vector.now, maxLifetime: vector.max_lifetime)
            #expect(name == vector.expect, "\(vector.name)")
            guard vector.expect == "ok", let fields = vector.fields else { continue }
            let key = try CKeySafeAction.PublicKey(alg: "ES256", hex: vector.public_key)
            #expect(CKeySafeAction.verify(text: vector.payload, key: key, now: Date(timeIntervalSince1970: vector.now), maxLifetime: vector.max_lifetime)
                    == .ok(CKeySafeAction(scope: CKeySafeAction.Scope(rawValue: fields.scope)!, issuer: fields.issuer, app: fields.app, action: fields.action,
                                          keyId: fields.key_id, requestId: fields.request_id, issuedAt: fields.issued_at, expiresAt: fields.expires_at,
                                          params: Data(fields.params.utf8))), "\(vector.name)")
        }
        // The Ed25519 vectors under the typed key reach the same verdicts as before.
        for vector in try Self.load() where vector.expect != "invalid_or_integrity" {
            #expect(Self.verdict(alg: "Ed25519", publicKeyHex: vector.public_key, payload: vector.payload, now: vector.now, maxLifetime: vector.max_lifetime)
                    == vector.expect || vector.public_key.count != 64, "\(vector.name)")
        }
    }

    @Test func es256KeysParseFromSEC1AndRefuseAnythingElse() throws {
        let key = P256.Signing.PrivateKey().publicKey
        func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
        let compressed = try CKeySafeAction.PublicKey(alg: "ES256", hex: hex(key.compressedRepresentation))
        let uncompressed = try CKeySafeAction.PublicKey(alg: "ES256", hex: hex(key.x963Representation).uppercased())
        #expect(compressed == uncompressed)
        #expect(compressed.alg == "ES256")
        #expect(compressed.hex == hex(key.compressedRepresentation))
        #expect(compressed != .ed25519(Self.publicKey))
        var offCurve = key.x963Representation
        offCurve[64] ^= 0x01
        let refused: [(String, String, CKeySafeAction.PublicKey.KeyError)] = [
            ("ES256", hex(offCurve), .invalidKey),                                    // a point off the curve
            ("ES256", hex(key.rawRepresentation), .invalidKey),                       // 64 bytes: no SEC 1 prefix
            ("ES256", "05" + hex(key.compressedRepresentation.dropFirst()), .invalidKey),
            ("ES256", "04" + hex(key.compressedRepresentation.dropFirst()), .invalidKey), // 33 bytes with the uncompressed prefix
            ("ES256", hex(key.compressedRepresentation) + "00", .invalidKey),
            ("ES256", "", .invalidKey),
            ("ES256", "0g" + String(repeating: "0", count: 64), .invalidKey),
            ("Ed25519", hex(key.compressedRepresentation), .invalidKey),
            ("es256", hex(key.compressedRepresentation), .unknownAlgorithm),         // exact spelling only
            ("ES384", hex(key.compressedRepresentation), .unknownAlgorithm),
            ("", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", .unknownAlgorithm),
        ]
        for (alg, text, error) in refused {
            #expect(throws: error, "\(alg) \(text)") { try CKeySafeAction.PublicKey(alg: alg, hex: text) }
        }
        #expect(try CKeySafeAction.PublicKey(alg: "Ed25519", hex: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a") == .ed25519(Self.publicKey))
    }

    @Test func es256SigningInputAssemblyAndTheSignatureRules() throws {
        let privateKey = P256.Signing.PrivateKey()
        let key = CKeySafeAction.PublicKey.es256(privateKey.publicKey)
        let action = Self.action()
        // In process: always low-S, always verifies.
        for _ in 0..<16 {
            let text = try action.signed(with: privateKey)
            #expect(CKeySafeAction.verify(text: text, key: key, now: Self.now, maxLifetime: 120) == .ok(action))
            let raw = Data(CKeySafeAction.base64URLDecode(Array(text.utf8)[CKeySafeAction.prefix.utf8.count...])!.suffix(64))
            #expect(CKeySafeAction.isCanonicalES256(raw))
            // An Ed25519 key never accepts it, nor another P-256 key.
            #expect(CKeySafeAction.verify(text: text, key: .ed25519(Self.publicKey), now: Self.now) == .integrity)
            #expect(CKeySafeAction.verify(text: text, key: .es256(P256.Signing.PrivateKey().publicKey), now: Self.now) == .integrity)
        }
        // A key service path: sign the SHA-256 digest of the signing input elsewhere, fold to low-S, assemble.
        let input = try action.signingInput()
        #expect(input.prefix(20) == Data("CKey Safe Action v1".utf8 + [0]))
        let raw = try privateKey.signature(for: input).rawRepresentation
        let low = CKeySafeAction.lowS(raw)
        let text = try action.assembled(signature: low)
        #expect(CKeySafeAction.verify(text: text, key: key, now: Self.now, maxLifetime: 120) == .ok(action))
        #expect(throws: CKeySafeAction.SigningError.invalidSignature) { try action.assembled(signature: low.prefix(63)) }

        // The high-S twin of a valid signature verifies in swift-crypto, and is refused here.
        let r = Data(low.prefix(32)), s = [UInt8](low.suffix(32))
        let high = r + Self.subtract(CKeySafeAction.p256Order, s)
        #expect(high != low)
        #expect(privateKey.publicKey.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: high), for: input))
        #expect(CKeySafeAction.verify(text: try action.assembled(signature: high), key: key, now: Self.now, maxLifetime: 120) == .integrity)
        // r or s zero, r = n, s = n, s = n/2 + 1: refused before the library; s = n/2 itself is low.
        let zero = Data(repeating: 0, count: 32)
        for bad in [zero + Data(s), r + zero, Data(CKeySafeAction.p256Order) + Data(s), r + Data(CKeySafeAction.p256Order),
                    r + Self.add1(CKeySafeAction.p256HalfOrder), Data(repeating: 0xFF, count: 64)] {
            #expect(!CKeySafeAction.isCanonicalES256(bad))
            #expect(CKeySafeAction.verify(text: try action.assembled(signature: bad), key: key, now: Self.now, maxLifetime: 120) == .integrity)
        }
        #expect(CKeySafeAction.isCanonicalES256(r + Data(CKeySafeAction.p256HalfOrder)))
        #expect(!CKeySafeAction.isCanonicalES256(low.prefix(63)))
    }

    static func subtract(_ a: [UInt8], _ b: [UInt8]) -> Data {
        var out = [UInt8](repeating: 0, count: 32), borrow = 0
        for i in stride(from: 31, through: 0, by: -1) {
            var d = Int(a[i]) - Int(b[i]) - borrow
            if d < 0 { d += 256; borrow = 1 } else { borrow = 0 }
            out[i] = UInt8(d)
        }
        return Data(out)
    }

    static func add1(_ a: [UInt8]) -> Data {
        var out = a
        for i in stride(from: 31, through: 0, by: -1) {
            if out[i] == 0xFF { out[i] = 0 } else { out[i] += 1; break }
        }
        return Data(out)
    }
}

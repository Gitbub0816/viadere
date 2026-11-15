@preconcurrency import Crypto
@preconcurrency import _CryptoExtras
import Fluent
import Foundation
import NIOHTTP1
import SwiftASN1
import Vapor
import ViadereCore
import XCTest
@_spi(CMS) @testable import X509
@testable import ViadereServerKit

/// A throwaway PKI: a root standing in for Apple's WWDR intermediate and a leaf standing in for the Pass Type ID certificate.
struct TestPKI {
    var rootPEM: String
    var leafPEM: String
    var leafKeyPEM: String
    var root: Certificate
    var leaf: Certificate

    enum KeyKind { case p256, rsa }

    static func make(_ kind: KeyKind = .p256, leafNotAfter: Date = Date().addingTimeInterval(86_400 * 300), wrongKeyPEM: Bool = false) throws -> TestPKI {
        let rootKey = P256.Signing.PrivateKey()
        let rootName = try DistinguishedName { CommonName("Test WWDR Intermediate") }
        let root = try Certificate(
            version: .v3, serialNumber: .init(), publicKey: .init(rootKey.publicKey), notValidBefore: Date().addingTimeInterval(-86_400),
            notValidAfter: Date().addingTimeInterval(86_400 * 360), issuer: rootName, subject: rootName, signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions { Critical(BasicConstraints.isCertificateAuthority(maxPathLength: nil)) },
            issuerPrivateKey: .init(rootKey))
        let leafName = try DistinguishedName { CommonName("Pass Type ID: pass.com.viadere.test"); OrganizationalUnitName("TEAMID1234") }
        let leafPrivate: Certificate.PrivateKey
        let leafKeyPEM: String
        switch kind {
        case .p256:
            let key = P256.Signing.PrivateKey()
            leafPrivate = .init(key)
            leafKeyPEM = key.pemRepresentation
        case .rsa:
            let key = try _RSA.Signing.PrivateKey(keySize: .bits2048)
            leafPrivate = .init(key)
            leafKeyPEM = key.pkcs8PEMRepresentation
        }
        let leaf = try Certificate(
            version: .v3, serialNumber: .init(), publicKey: leafPrivate.publicKey, notValidBefore: Date().addingTimeInterval(-86_400),
            notValidAfter: leafNotAfter, issuer: rootName, subject: leafName, signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions { Critical(BasicConstraints.notCertificateAuthority) }, issuerPrivateKey: .init(rootKey))
        let otherKey = P256.Signing.PrivateKey().pemRepresentation
        return TestPKI(rootPEM: try root.serializeAsPEM().pemString, leafPEM: try leaf.serializeAsPEM().pemString,
                       leafKeyPEM: wrongKeyPEM ? otherKey : leafKeyPEM, root: root, leaf: leaf)
    }

    var config: PassConfig {
        PassConfig(passTypeIdentifier: "pass.com.viadere.test", certificatePEM: leafPEM, privateKeyPEM: leafKeyPEM, wwdrCertificatePEM: rootPEM)
    }
}

final class PassSigningTests: XCTestCase {
    private let manifest = Data(#"{"pass.json":"da39a3ee5e6b4b0d3255bfef95601890afd80709"}"#.utf8)

    private func inspect(_ signature: Data, expectCertificates: Int = 2) throws -> CMSSignedData {
        let info = try CMSContentInfo(berEncoded: ArraySlice(signature))
        let signed = try XCTUnwrap(try info.signedData)
        XCTAssertEqual(signed.signerInfos.count, 1)
        XCTAssertEqual(signed.certificates?.count, expectCertificates, "signer certificate plus the WWDR intermediate")
        XCTAssertNil(signed.encapContentInfo.eContent, "the signature is detached")
        XCTAssertEqual(signed.encapContentInfo.eContentType, .cmsData)
        XCTAssertEqual(signed.digestAlgorithms.count, 1)
        return signed
    }

    func testSignatureIsADetachedCMSSignedDataWithBothCertificatesAndSHA256SignedAttributes() throws {
        let pki = try TestPKI.make()
        let signer = try X509PassSigner(config: pki.config, teamIdentifier: "TEAMID1234")
        let signingTime = Date()
        let der = try signer.sign(manifest: manifest, at: signingTime)
        let signed = try inspect(der)
        let signerInfo = signed.signerInfos[0]
        XCTAssertTrue(signerInfo.digestAlgorithm == .sha256 || signerInfo.digestAlgorithm == .sha256UsingNil, "SHA-256 digest")
        // Signed attributes: content type, signing time, message digest = SHA-256 of the manifest.
        let attrs = try XCTUnwrap(signerInfo.signedAttrs)
        XCTAssertEqual(Set(attrs.map(\.attrType)), [.contentType, .signingTime, .messageDigest])
        let digestAttr = try XCTUnwrap(attrs.first { $0.attrType == .messageDigest })
        let digest = try ASN1OctetString(asn1Any: try XCTUnwrap(digestAttr.attrValues.first))
        XCTAssertEqual(Array(digest.bytes), Array(SHA256.hash(data: manifest)))
        // The leaf and intermediate are both included, leaf identified by issuer + serial.
        let subjects = Set((signed.certificates ?? []).map { String(describing: $0.subject) })
        XCTAssertEqual(subjects.count, 2)
        XCTAssertEqual(signer.passTypeIdentifier, "pass.com.viadere.test")
        XCTAssertEqual(signer.teamIdentifier, "TEAMID1234")
        XCTAssertGreaterThan(signer.certificateNotValidAfter, Date())
        // Deterministic structure, fresh signature each time (ECDSA is randomized) but always verifiable.
        XCTAssertEqual(der.first, 0x30, "DER SEQUENCE")
    }

    func testSignatureVerifiesAgainstTheTrustRootAndFailsForAnyChange() async throws {
        for kind in [TestPKI.KeyKind.p256, .rsa] {
            let pki = try TestPKI.make(kind)
            let signer = try X509PassSigner(config: pki.config, teamIdentifier: "TEAMID1234")
            let der = try signer.sign(manifest: manifest, at: Date())
            let good = await CMS.isValidSignature(dataBytes: manifest, signatureBytes: der, trustRoots: CertificateStore([pki.root])) { RFC5280Policy() }
            guard case .success = good else { return XCTFail("\(kind): expected a valid signature, got \(good)") }
            var tampered = manifest
            tampered[tampered.startIndex] ^= 0x01
            let bad = await CMS.isValidSignature(dataBytes: tampered, signatureBytes: der, trustRoots: CertificateStore([pki.root])) { RFC5280Policy() }
            if case .success = bad { XCTFail("\(kind): a changed manifest must not verify") }
            // Not trusted by an unrelated root.
            let stranger = try TestPKI.make(kind)
            let untrusted = await CMS.isValidSignature(dataBytes: manifest, signatureBytes: der, trustRoots: CertificateStore([stranger.root])) { RFC5280Policy() }
            if case .success = untrusted { XCTFail("\(kind): an unrelated root must not trust it") }
        }
    }

    func testOpenSSLAgreesTheSignatureIsValidForTheManifest() throws {
        let openssl = "/usr/bin/openssl"
        guard FileManager.default.isExecutableFile(atPath: openssl) else { throw XCTSkip("openssl is not installed") }
        let pki = try TestPKI.make()
        let signer = try X509PassSigner(config: pki.config, teamIdentifier: "TEAMID1234")
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("viadere-pass-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try manifest.write(to: directory.appendingPathComponent("manifest.json"))
        try signer.sign(manifest: manifest, at: Date()).write(to: directory.appendingPathComponent("signature"))
        try pki.rootPEM.write(to: directory.appendingPathComponent("root.pem"), atomically: true, encoding: .utf8)
        func run(_ arguments: [String]) throws -> (Int32, String) {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: openssl)
            process.arguments = arguments
            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = pipe
            try process.run()
            process.waitUntilExit()
            return (process.terminationStatus, String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self))
        }
        let path = { (name: String) in directory.appendingPathComponent(name).path }
        // Same check Apple's tooling effectively performs: a detached DER PKCS#7 over manifest.json, chained to a trusted root.
        let ok = try run(["smime", "-verify", "-binary", "-inform", "DER", "-in", path("signature"), "-content", path("manifest.json"),
                          "-CAfile", path("root.pem"), "-purpose", "any", "-out", "/dev/null"])
        XCTAssertEqual(ok.0, 0, ok.1)
        try Data(#"{"pass.json":"0000"}"#.utf8).write(to: directory.appendingPathComponent("other.json"))
        let bad = try run(["smime", "-verify", "-binary", "-inform", "DER", "-in", path("signature"), "-content", path("other.json"),
                           "-CAfile", path("root.pem"), "-purpose", "any", "-out", "/dev/null"])
        XCTAssertNotEqual(bad.0, 0, "a different manifest must not verify")
    }

    func testBadCertificateMaterialFailsAtStartup() throws {
        let good = try TestPKI.make()
        func attempt(_ config: PassConfig) -> PassSignerError? {
            do { _ = try X509PassSigner(config: config, teamIdentifier: "TEAMID1234"); return nil } catch { return error as? PassSignerError }
        }
        XCTAssertNil(attempt(good.config))
        var garbageCertificate = good.config
        garbageCertificate.certificatePEM = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"
        XCTAssertEqual(attempt(garbageCertificate), .invalidCertificate)
        var garbageWWDR = good.config
        garbageWWDR.wwdrCertificatePEM = "nonsense"
        XCTAssertEqual(attempt(garbageWWDR), .invalidCertificate)
        var garbageKey = good.config
        garbageKey.privateKeyPEM = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"
        XCTAssertEqual(attempt(garbageKey), .invalidPrivateKey)
        XCTAssertEqual(attempt(try TestPKI.make(wrongKeyPEM: true).config), .keyDoesNotMatchCertificate)
        XCTAssertEqual(attempt(try TestPKI.make(leafNotAfter: Date().addingTimeInterval(-60)).config), .certificateExpired)
        // The encrypted-key case is also a clean failure rather than a crash.
        var encrypted = good.config
        encrypted.privateKeyPEM = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----"
        XCTAssertEqual(attempt(encrypted), .invalidPrivateKey)
    }

    func testPassEnvironmentIsAllOrNothing() throws {
        let pki = try TestPKI.make()
        let base = ["ENVIRONMENT": "development"]
        XCTAssertNil(try ServerConfig.fromEnvironment(base).passes)
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(base.merging(["PASS_TYPE_IDENTIFIER": "pass.com.viadere.test"]) { $1 }))
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(base.merging(["PASS_CERTIFICATE_PEM": pki.leafPEM]) { $1 }), "a certificate without an identifier")
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(base.merging(["PASS_TYPE_IDENTIFIER": "com.not.a.pass", "PASS_CERTIFICATE_PEM": pki.leafPEM,
                                                                           "PASS_PRIVATE_KEY_PEM": pki.leafKeyPEM, "PASS_WWDR_CERTIFICATE_PEM": pki.rootPEM]) { $1 }))
        let full = try ServerConfig.fromEnvironment(base.merging([
            "PASS_TYPE_IDENTIFIER": "pass.com.viadere.test", "PASS_CERTIFICATE_PEM": pki.leafPEM.replacingOccurrences(of: "\n", with: "\\n"),
            "PASS_PRIVATE_KEY_PEM": pki.leafKeyPEM, "PASS_WWDR_CERTIFICATE_PEM": pki.rootPEM]) { $1 })
        let passes = try XCTUnwrap(full.passes)
        XCTAssertEqual(passes.passTypeIdentifier, "pass.com.viadere.test")
        XCTAssertNoThrow(try X509PassSigner(config: passes, teamIdentifier: "TEAMID1234"), "escaped newlines are restored")
        // Files work as well as inline values.
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("viadere-env-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        try pki.leafPEM.write(to: dir.appendingPathComponent("c.pem"), atomically: true, encoding: .utf8)
        try pki.leafKeyPEM.write(to: dir.appendingPathComponent("k.pem"), atomically: true, encoding: .utf8)
        try pki.rootPEM.write(to: dir.appendingPathComponent("w.pem"), atomically: true, encoding: .utf8)
        let byPath = try ServerConfig.fromEnvironment(base.merging(["PASS_TYPE_IDENTIFIER": "pass.com.viadere.test", "PASS_CERTIFICATE_PATH": dir.appendingPathComponent("c.pem").path,
                                                                    "PASS_PRIVATE_KEY_PATH": dir.appendingPathComponent("k.pem").path,
                                                                    "PASS_WWDR_CERTIFICATE_PATH": dir.appendingPathComponent("w.pem").path]) { $1 })
        XCTAssertNotNil(byPath.passes)
    }
}

final class PKPassFormatTests: XCTestCase {
    func testZipRoundTripsAndRejectsTraversalAndCorruption() throws {
        let entries = [ZipArchive.Entry(name: "pass.json", data: Data("{}".utf8)), ZipArchive.Entry(name: "icon.png", data: Data(repeating: 7, count: 5_000))]
        let zip = try ZipArchive.build(entries)
        XCTAssertEqual(try ZipArchive.read(zip).map(\.name), ["pass.json", "icon.png"])
        XCTAssertEqual(try ZipArchive.read(zip).map(\.data), entries.map(\.data))
        XCTAssertEqual(try ZipArchive.build(entries), zip, "deterministic bytes")
        XCTAssertEqual(zip.prefix(4), Data([0x50, 0x4B, 0x03, 0x04]))
        for bad in ["../evil", "/abs", "dir/file", "a\\b", ".hidden", "", "../x.lproj/pass.strings", "en.lproj/../pass.json", "en.lproj/sub/x",
                    "en.lproj/.x", ".lproj/pass.strings", "e n.lproj/pass.strings", "en.lproj/", "fr.lproj\\pass.strings"] {
            XCTAssertThrowsError(try ZipArchive.build([ZipArchive.Entry(name: bad, data: Data())]), bad)
        }
        // One level of Apple's localization folders is allowed.
        for good in ["en.lproj/pass.strings", "zh-Hans.lproj/pass.strings", "fr.lproj/logo@2x.png"] {
            XCTAssertNoThrow(try ZipArchive.build([ZipArchive.Entry(name: good, data: Data())]), good)
        }
        var corrupt = zip
        corrupt[40] ^= 0xFF
        XCTAssertThrowsError(try ZipArchive.read(corrupt), "a flipped byte fails the CRC")
        XCTAssertEqual(CRC32.checksum(Data("123456789".utf8)), 0xCBF4_3926, "the standard CRC-32 check value")
    }

    func testSystemUnzipAcceptsTheArchive() throws {
        guard FileManager.default.isExecutableFile(atPath: "/usr/bin/unzip") else { throw XCTSkip("unzip is not installed") }
        let zip = try ZipArchive.build([ZipArchive.Entry(name: "pass.json", data: Data("{}".utf8)), ZipArchive.Entry(name: "icon.png", data: MinimalPNG.solid(width: 29, height: 29, red: 1, green: 2, blue: 3))])
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("viadere-\(UUID().uuidString).pkpass")
        try zip.write(to: file)
        defer { try? FileManager.default.removeItem(at: file) }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/unzip")
        process.arguments = ["-t", file.path]
        let pipe = Pipe()
        process.standardOutput = pipe
        try process.run()
        process.waitUntilExit()
        let output = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        XCTAssertEqual(process.terminationStatus, 0, output)
        XCTAssertTrue(output.contains("No errors detected"), output)
    }

    func testPNGIsStructurallyValid() throws {
        let png = MinimalPNG.solid(width: 29, height: 29, red: 0xC9, green: 0xA9, blue: 0x6E)
        XCTAssertEqual(png.prefix(8), Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]))
        var cursor = 8
        var types: [String] = []
        while cursor < png.count {
            let length = Int(png[cursor]) << 24 | Int(png[cursor + 1]) << 16 | Int(png[cursor + 2]) << 8 | Int(png[cursor + 3])
            let type = String(decoding: png[(cursor + 4)..<(cursor + 8)], as: UTF8.self)
            let body = png[(cursor + 4)..<(cursor + 8 + length)]
            let crc = png[(cursor + 8 + length)..<(cursor + 12 + length)].reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
            XCTAssertEqual(CRC32.checksum(body), crc, "\(type) CRC")
            types.append(type)
            cursor += 12 + length
        }
        XCTAssertEqual(types, ["IHDR", "IDAT", "IEND"])
        // IHDR: 29×29, 8-bit RGB.
        XCTAssertEqual(Array(png[16..<24]), [0, 0, 0, 29, 0, 0, 0, 29])
        XCTAssertEqual(Array(png[24..<29]), [8, 2, 0, 0, 0])
    }

    func testManifestListsEverySHA1AndPassJSONIsCanonical() throws {
        let files = [ZipArchive.Entry(name: "pass.json", data: Data("{\"a\":1}".utf8)), ZipArchive.Entry(name: "icon.png", data: Data("png".utf8))]
        let manifest = try JSONSerialization.jsonObject(with: PKPassBuilder.manifest(for: files)) as? [String: String]
        XCTAssertEqual(manifest, ["pass.json": Hex.encode(Insecure.SHA1.hash(data: files[0].data)), "icon.png": Hex.encode(Insecure.SHA1.hash(data: files[1].data))])
        XCTAssertEqual(Hex.encode(Insecure.SHA1.hash(data: Data("abc".utf8))), "a9993e364706816aba3e25717850c26c9cd0d89d", "SHA-1 test vector")
        var descriptor = PassDescriptor(kind: .coupon, passTypeIdentifier: "pass.x", teamIdentifier: "T", serialNumber: "S", authenticationToken: "tokentokentokentoken",
                                        webServiceURL: "https://viadere.com/wallet", organizationName: "Org", description: "Desc")
        descriptor.primary = [.init(key: "offer", label: "OFFER", value: .text("Free coffee"))]
        let json = try descriptor.json()
        XCTAssertEqual(try descriptor.json(), json, "stable bytes")
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: json) as? [String: Any])
        XCTAssertEqual(object["formatVersion"] as? Int, 1)
        XCTAssertNotNil(object["coupon"])
        XCTAssertNil(object["voided"])
        descriptor.voided = true
        XCTAssertEqual((try JSONSerialization.jsonObject(with: descriptor.json()) as? [String: Any])?["voided"] as? Bool, true)
    }
}

final class WalletFlowTests: XCTestCase {
    private struct Scene {
        var business: TestBusiness
        var consumer: TestConsumer
        var relationship: Relationship
    }

    private func scene(_ h: TestHarness) async throws -> Scene {
        let business = try await h.makeBusiness(name: "Juniper Coffee", handle: "junipercoffee")
        try await h.saveProgram(business)
        let consumer = try await h.readyConsumer()
        let relationship = try await h.connect(consumer, to: business)
        return Scene(business: business, consumer: consumer, relationship: relationship)
    }

    private func issuePass(_ h: TestHarness, _ s: Scene, kind: WalletPassKind = .storeCard, rewardId: RewardID? = nil, interactionId: InteractionID? = nil) async throws -> HTTPResult {
        try await h.signedPost(s.consumer, "/v1/wallet/passes", WalletPassIssueRequest(kind: kind, businessId: s.business.id, rewardId: rewardId, interactionId: interactionId))
    }

    private func download(_ h: TestHarness, _ consumer: TestConsumer, _ id: WalletPassID) async throws -> HTTPResult {
        try await h.signed(consumer, .GET, "/v1/wallet/passes/\(id)")
    }

    private func record(_ h: TestHarness, _ id: WalletPassID) async throws -> WalletPassRecord {
        try await WalletPassRecord.find(id.uuid, on: h.db).unwrap()
    }

    private func token(_ h: TestHarness, _ pass: WalletPassRecord) -> String {
        WalletService(db: h.db, ctx: h.ctx).authenticationToken(id: pass.id!, salt: pass.authSalt)
    }

    // MARK: Issue and download

    func testStoreCardPassIsIssuedSignedAndMatchesItsMetadata() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            try await eq(try await issuePass(h, s).status, .conflict, "join the program first")
            try await h.enroll(s.consumer, s.business)
            try await h.adjustPoints(s.business, s.relationship, 120)
            let issued = try await issuePass(h, s)
            XCTAssertEqual(issued.status, .created, issued.text)
            let metadata = try issued.json(WalletPassMetadata.self)
            XCTAssertEqual(metadata.passTypeIdentifier, "pass.com.viadere.test")
            XCTAssertTrue(metadata.serialNumber.hasPrefix("VP-"))
            XCTAssertEqual(metadata.kind, .storeCard)
            XCTAssertEqual(metadata.businessId, s.business.id)
            XCTAssertFalse(metadata.voided)
            // One pass per subject: asking again returns the same pass.
            let again = try await issuePass(h, s).json(WalletPassMetadata.self)
            XCTAssertEqual(again.id, metadata.id)
            let listed = try await h.signed(s.consumer, .GET, "/v1/wallet/passes").json([WalletPassMetadata].self)
            XCTAssertEqual(listed.map(\.id), [metadata.id])

            let response = try await download(h, s.consumer, metadata.id)
            XCTAssertEqual(response.status, .ok)
            XCTAssertEqual(response.headers.first(name: .contentType), "application/vnd.apple.pkpass")
            XCTAssertLessThan(response.body.count, 5 * 1024 * 1024)
            XCTAssertNotNil(response.headers.first(name: .lastModified))
            let pass = try PKPassContents(response.body)
            XCTAssertEqual(Set(pass.files.keys), ["pass.json", "manifest.json", "signature", "icon.png", "icon@2x.png", "icon@3x.png",
                                                  "en.lproj/pass.strings", "es.lproj/pass.strings", "fr.lproj/pass.strings"])
            // pass.json identity matches the metadata the app was promised.
            XCTAssertEqual(pass.passJSON["passTypeIdentifier"] as? String, metadata.passTypeIdentifier)
            XCTAssertEqual(pass.passJSON["serialNumber"] as? String, metadata.serialNumber)
            XCTAssertEqual(pass.passJSON["teamIdentifier"] as? String, "TEAMID1234")
            XCTAssertEqual(pass.passJSON["formatVersion"] as? Int, 1)
            XCTAssertEqual(pass.passJSON["organizationName"] as? String, "Juniper Coffee")
            XCTAssertEqual(pass.passJSON["webServiceURL"] as? String, "https://viadere.com/wallet")
            XCTAssertGreaterThanOrEqual((pass.passJSON["authenticationToken"] as? String)?.count ?? 0, 16)
            XCTAssertNil(pass.passJSON["voided"])
            let card = try XCTUnwrap(pass.passJSON["storeCard"] as? [String: Any])
            let primary = try XCTUnwrap(card["primaryFields"] as? [[String: Any]])
            XCTAssertEqual(primary.first?["value"] as? Int, 120)
            let secondary = try XCTUnwrap(card["secondaryFields"] as? [[String: Any]])
            XCTAssertEqual(secondary.first?["value"] as? String, "Silver")
            // The manifest is Apple's: a SHA-1 for every file except itself and the signature.
            XCTAssertEqual(Set(pass.manifest.keys), ["pass.json", "icon.png", "icon@2x.png", "icon@3x.png",
                                                     "en.lproj/pass.strings", "es.lproj/pass.strings", "fr.lproj/pass.strings"])
            for (name, hash) in pass.manifest { XCTAssertEqual(hash, pass.sha1(name), name) }
            XCTAssertTrue(pass.manifest.values.allSatisfy { $0.count == 40 })
            // The signature was made over exactly that manifest.
            XCTAssertEqual(pass.files["signature"], FakePassSigner.prefix + Data(SHA256.hash(data: try XCTUnwrap(pass.files["manifest.json"]))))
            XCTAssertEqual(h.signer.signedManifests.last, pass.files["manifest.json"])
            // The auth token embedded in the pass is stable across downloads, and stored only as a keyed hash.
            let second = try PKPassContents(try await download(h, s.consumer, metadata.id).body)
            XCTAssertEqual(second.passJSON["authenticationToken"] as? String, pass.passJSON["authenticationToken"] as? String)
            let stored = try await record(h, metadata.id)
            let embedded = try XCTUnwrap(pass.passJSON["authenticationToken"] as? String)
            XCTAssertNotEqual(stored.authTokenHash, embedded)
            XCTAssertEqual(stored.authTokenHash.count, 64)
            XCTAssertFalse(stored.authSalt.contains(embedded))
        }
    }

    func testPassesAreScopedToTheirOwnerAndVoidedPassesAreGone() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            try await h.enroll(s.consumer, s.business)
            let metadata = try await issuePass(h, s).json(WalletPassMetadata.self)
            let other = try await h.readyConsumer(name: "Other")
            try await eq(try await download(h, other, metadata.id).status, .notFound)
            let theirList = try await h.signed(other, .GET, "/v1/wallet/passes").json([WalletPassMetadata].self)
            XCTAssertEqual(theirList.count, 0)
            // Not connected to the business → 404; unknown business → 404.
            let stranger = try await h.makeBusiness(name: "Stranger Shop", handle: "strangershop")
            let foreign = try await h.signedPost(s.consumer, "/v1/wallet/passes", WalletPassIssueRequest(kind: .storeCard, businessId: stranger.id))
            XCTAssertEqual(foreign.status, .notFound)
            // Void it (a revoked coupon, say): the download is 410 and the metadata says voided.
            let pass = try await record(h, metadata.id)
            try await WalletService(db: h.db, ctx: h.ctx).void(pass)
            try await eq(try await download(h, s.consumer, metadata.id).status, .gone)
            let listed = try await h.signed(s.consumer, .GET, "/v1/wallet/passes").json([WalletPassMetadata].self)
            XCTAssertTrue(listed.first?.voided == true)
        }
    }

    func testCouponAndTicketPassesComeFromRewardsAndInteractionsTheConsumerOwns() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            let reward = try await h.reward(s.business, title: "10% off", kind: .coupon, validUntil: h.clock.now().addingTimeInterval(86_400 * 10))
            try await eq(try await issuePass(h, s, kind: .coupon).status, .notFound, "a coupon pass needs a reward")
            let coupon = try await issuePass(h, s, kind: .coupon, rewardId: reward.id)
            XCTAssertEqual(coupon.status, .created, coupon.text)
            let couponPass = try PKPassContents(try await download(h, s.consumer, coupon.json(WalletPassMetadata.self).id).body)
            let offer = try XCTUnwrap((couponPass.passJSON["coupon"] as? [String: Any])?["primaryFields"] as? [[String: Any]])
            XCTAssertEqual(offer.first?["value"] as? String, "10% off")
            XCTAssertNotNil(couponPass.passJSON["expirationDate"])
            // Another business's reward is not available to this business's pass.
            let rival = try await h.makeBusiness(name: "Rival Roasters", handle: "rivalroasters")
            let foreignReward = try await h.reward(rival, title: "Rival deal", kind: .coupon)
            try await eq(try await issuePass(h, s, kind: .coupon, rewardId: foreignReward.id).status, .notFound)

            // A ticket interaction becomes an event-ticket pass with venue, seat and start time.
            let starts = h.clock.now().addingTimeInterval(3 * 86_400)
            let ticket = TicketPayload(title: "Jazz Night", ticketType: "event", holderName: "Sam", validFrom: h.clock.now(), validUntil: starts.addingTimeInterval(4 * 3600),
                                       venue: "Orpheum Theatre", seat: "Row F · Seat 12", startsAt: starts)
            let issuedTicket = try await h.issue(s.business, relationship: s.relationship, payload: .ticket(ticket), purpose: .transactional, ttl: 86_400)
            XCTAssertEqual(issuedTicket.status, .created, issuedTicket.text)
            let ticketId = try issuedTicket.json(Interaction.self).id
            let pass = try await issuePass(h, s, kind: .eventTicket, interactionId: ticketId)
            XCTAssertEqual(pass.status, .created, pass.text)
            let content = try PKPassContents(try await download(h, s.consumer, pass.json(WalletPassMetadata.self).id).body)
            let style = try XCTUnwrap(content.passJSON["eventTicket"] as? [String: Any])
            let secondary = try XCTUnwrap(style["secondaryFields"] as? [[String: Any]])
            XCTAssertEqual(secondary.compactMap { $0["value"] as? String }, ["Orpheum Theatre", "Row F · Seat 12"])
            XCTAssertEqual(content.passJSON["relevantDate"] as? String, PassDescriptor.wallet(starts))
            let barcode = try XCTUnwrap((content.passJSON["barcodes"] as? [[String: Any]])?.first?["message"] as? String)
            XCTAssertTrue(WalletScanCode.isWellFormed(barcode), "the QR is the signed presentation code")
            XCTAssertEqual(barcode, try pass.json(WalletPassMetadata.self).scanCode)
            // Someone else's ticket, or an interaction that is not a ticket, cannot become a pass.
            let other = try await h.readyConsumer(name: "Other")
            _ = try await h.connect(other, to: s.business)
            let theirs = try await h.signedPost(other, "/v1/wallet/passes", WalletPassIssueRequest(kind: .eventTicket, businessId: s.business.id, interactionId: ticketId))
            XCTAssertEqual(theirs.status, .notFound)
            let confirm = try await h.issue(s.business, relationship: s.relationship, payload: .confirm(ConfirmPayload(title: "Confirm?")), purpose: .transactional)
            let confirmId = try confirm.json(Interaction.self).id
            try await eq(try await issuePass(h, s, kind: .eventTicket, interactionId: confirmId).status, .conflict)
        }
    }

    func testWalletIsUnavailableWithoutACertificate() async throws {
        try await withHarness(passes: false) { h in
            let s = try await scene(h)
            try await h.enroll(s.consumer, s.business)
            let response = try await issuePass(h, s)
            XCTAssertEqual(response.status, .notImplemented)
            XCTAssertEqual(response.errorCode, .unavailable)
            let list = try await h.signed(s.consumer, .GET, "/v1/wallet/passes")
            XCTAssertEqual(list.status, .ok, "listing still works")
            let count = try await WalletPassRecord.query(on: h.db).count()
            XCTAssertEqual(count, 0, "no unusable pass is created")
        }
    }

    // MARK: PassKit web service

    private func headers(_ token: String?) -> [String: String] {
        token.map { ["Authorization": "ApplePass \($0)"] } ?? [:]
    }

    private func register(_ h: TestHarness, _ pass: WalletPassRecord, device: String = "device-abc123", pushToken: String = String(repeating: "ab", count: 32),
                          token: String?, type: String? = nil) async throws -> HTTPResult {
        let body = try ViadereJSON.encode(["pushToken": pushToken])
        return try await h.request(.POST, "/wallet/v1/devices/\(device)/registrations/\(type ?? pass.passTypeIdentifier)/\(pass.serialNumber)", headers: headers(token), body: body)
    }

    func testPassKitRegistrationRequiresThePerPassTokenInConstantTimeAndHashedAtRest() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            try await h.enroll(s.consumer, s.business)
            let metadata = try await issuePass(h, s).json(WalletPassMetadata.self)
            let pass = try await record(h, metadata.id)
            let good = token(h, pass)
            // No token, a wrong token, a token for another pass, a wrong pass type: all the same 401.
            try await eq(try await register(h, pass, token: nil).status, .unauthorized)
            try await eq(try await register(h, pass, token: "wrong-token-wrong-token-wrong").status, .unauthorized)
            try await eq(try await register(h, pass, token: String(good.dropLast()) + (good.last == "A" ? "B" : "A")).status, .unauthorized)
            try await eq(try await register(h, pass, token: good, type: "pass.com.someone.else").status, .unauthorized)
            let other = try await h.makeBusiness(name: "Other Cafe", handle: "othercafe")
            let otherConsumer = try await h.readyConsumer(name: "Other")
            _ = try await h.connect(otherConsumer, to: other)
            try await h.saveProgram(other)
            try await h.enroll(otherConsumer, other)
            let otherPass = try await record(h, try await h.signedPost(otherConsumer, "/v1/wallet/passes", WalletPassIssueRequest(kind: .storeCard, businessId: other.id)).json(WalletPassMetadata.self).id)
            try await eq(try await register(h, pass, token: token(h, otherPass)).status, .unauthorized, "another pass's token is no good here")
            let none = try await WalletRegistrationRecord.query(on: h.db).count()
            XCTAssertEqual(none, 0)
            // The right token registers: 201 first, 200 for a repeat (updating the push token).
            try await eq(try await register(h, pass, token: good).status, .created)
            try await eq(try await register(h, pass, pushToken: String(repeating: "cd", count: 32), token: good).status, .ok)
            let rows = try await WalletRegistrationRecord.query(on: h.db).all()
            XCTAssertEqual(rows.count, 1)
            XCTAssertEqual(rows[0].pushToken, String(repeating: "cd", count: 32))
            // Bad registrations are rejected.
            try await eq(try await register(h, pass, device: "bad device!", token: good).status, .badRequest)
            try await eq(try await register(h, pass, pushToken: "not hex", token: good).status, .badRequest)
            // The token itself is never stored.
            XCTAssertNotEqual(pass.authTokenHash, good)
            XCTAssertEqual(pass.authTokenHash, WalletService(db: h.db, ctx: h.ctx).tokenHash(good))
            XCTAssertTrue(WalletService(db: h.db, ctx: h.ctx).verify(token: good, for: pass))
            XCTAssertFalse(WalletService(db: h.db, ctx: h.ctx).verify(token: "short", for: pass))
            XCTAssertFalse(WalletService(db: h.db, ctx: h.ctx).verify(token: String(repeating: "x", count: 500), for: pass))
            // Every failed authentication cost something: a client hammering a pass gets rate limited.
            var statuses: [HTTPStatus] = []
            for _ in 0..<14 { statuses.append(try await register(h, pass, token: "guess-guess-guess-guess").status) }
            XCTAssertTrue(statuses.contains(.tooManyRequests), "\(statuses)")
            // …but the real token still works.
            try await eq(try await register(h, pass, token: good).status, .ok)
        }
    }

    func testPassKitUpdateFlowListsSerialsServesTheLatestPassAndUnregisters() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            try await h.enroll(s.consumer, s.business)
            let metadata = try await issuePass(h, s).json(WalletPassMetadata.self)
            let pass = try await record(h, metadata.id)
            let auth = token(h, pass)
            try await eq(try await register(h, pass, token: auth).status, .created)
            let listPath = "/wallet/v1/devices/device-abc123/registrations/\(pass.passTypeIdentifier)"
            // Nothing changed since registration → the first poll with no tag lists the pass.
            let first = try await h.request(.GET, listPath)
            XCTAssertEqual(first.status, .ok)
            struct Serials: Codable { var serialNumbers: [String]; var lastUpdated: String }
            let listed = try first.json(Serials.self)
            XCTAssertEqual(listed.serialNumbers, [pass.serialNumber])
            // With the returned tag nothing is new: 204.
            try await eq(try await h.request(.GET, listPath + "?passesUpdatedSince=\(listed.lastUpdated)").status, .noContent)
            // An unknown device learns nothing.
            try await eq(try await h.request(.GET, "/wallet/v1/devices/other-device/registrations/\(pass.passTypeIdentifier)").status, .noContent)
            // The business adds points: the pass changes, a push is queued, and the next poll lists it again.
            h.clock.advance(by: 30)
            try await h.adjustPoints(s.business, s.relationship, 75)
            let outbox = try await WalletPushOutboxRecord.query(on: h.db).filter(\.$passId == pass.id!).all()
            XCTAssertEqual(outbox.filter { $0.status == "queued" }.count, 1)
            try await h.runJobs()
            XCTAssertEqual(h.passPush.sent, [RecordingPassPush.Sent(token: String(repeating: "ab", count: 32), passType: "pass.com.viadere.test")])
            let after = try await h.request(.GET, listPath + "?passesUpdatedSince=\(listed.lastUpdated)")
            XCTAssertEqual(after.status, .ok)
            XCTAssertEqual(try after.json(Serials.self).serialNumbers, [pass.serialNumber])
            // Wallet then fetches the latest pass with the token; wrong or missing token is 401.
            let passPath = "/wallet/v1/passes/\(pass.passTypeIdentifier)/\(pass.serialNumber)"
            try await eq(try await h.request(.GET, passPath).status, .unauthorized)
            try await eq(try await h.request(.GET, passPath, headers: headers("nope-nope-nope-nope-nope")).status, .unauthorized)
            let latest = try await h.request(.GET, passPath, headers: headers(auth))
            XCTAssertEqual(latest.status, .ok)
            XCTAssertEqual(latest.headers.first(name: .contentType), "application/vnd.apple.pkpass")
            let content = try PKPassContents(latest.body)
            let card = try XCTUnwrap(content.passJSON["storeCard"] as? [String: Any])
            XCTAssertEqual((card["primaryFields"] as? [[String: Any]])?.first?["value"] as? Int, 75, "the refreshed points")
            // If-Modified-Since: unchanged → 304.
            let lastModified = try XCTUnwrap(latest.headers.first(name: .lastModified))
            var conditional = headers(auth)
            conditional["If-Modified-Since"] = lastModified
            try await eq(try await h.request(.GET, passPath, headers: conditional).status, .notModified)
            // Unregister: needs the token too, then no more pushes.
            let unregisterPath = "/wallet/v1/devices/device-abc123/registrations/\(pass.passTypeIdentifier)/\(pass.serialNumber)"
            try await eq(try await h.request(.DELETE, unregisterPath).status, .unauthorized)
            try await eq(try await h.request(.DELETE, unregisterPath, headers: headers(auth)).status, .ok)
            let remaining = try await WalletRegistrationRecord.query(on: h.db).count()
            XCTAssertEqual(remaining, 0)
            h.clock.advance(by: 30)
            try await h.adjustPoints(s.business, s.relationship, 5)
            try await h.runJobs()
            XCTAssertEqual(h.passPush.sent.count, 1, "nothing is pushed to an unregistered device")
        }
    }

    func testPassPushesRetryAndDropDevicesWalletForgot() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            try await h.enroll(s.consumer, s.business)
            let pass = try await record(h, try await issuePass(h, s).json(WalletPassMetadata.self).id)
            let auth = token(h, pass)
            let live = String(repeating: "11", count: 32), dead = String(repeating: "22", count: 32)
            try await eq(try await register(h, pass, device: "live-device", pushToken: live, token: auth).status, .created)
            try await eq(try await register(h, pass, device: "dead-device", pushToken: dead, token: auth).status, .created)
            h.passPush.setOutcome(.tokenInvalid, for: dead)
            try await h.adjustPoints(s.business, s.relationship, 10)
            try await h.runJobs()
            XCTAssertEqual(Set(h.passPush.sent.map(\.token)), [live, dead])
            let remaining = try await WalletRegistrationRecord.query(on: h.db).all().map(\.deviceLibraryIdentifier)
            XCTAssertEqual(remaining, ["live-device"], "APNs said the dead device forgot the pass")
            // A transient failure is retried later with backoff, and eventually given up on.
            h.passPush.setOutcome(.failed, for: live)
            h.clock.advance(by: 30)
            try await h.adjustPoints(s.business, s.relationship, 10)
            try await h.runJobs()
            let queued = try await WalletPushOutboxRecord.query(on: h.db).filter(\.$status == "queued").all()
            XCTAssertEqual(queued.count, 1)
            XCTAssertGreaterThan(queued[0].nextAttemptAt, h.clock.now())
            let before = h.passPush.sent.count
            try await h.runJobs()
            XCTAssertEqual(h.passPush.sent.count, before, "not before the backoff")
            h.passPush.setOutcome(.delivered, for: live)
            h.clock.advance(by: 120)
            try await h.runJobs()
            XCTAssertEqual(h.passPush.sent.count, before + 1)
            let stillQueued = try await WalletPushOutboxRecord.query(on: h.db).filter(\.$status == "queued").count()
            XCTAssertEqual(stillQueued, 0)
        }
    }

    func testVoidedPassesAreStillServedToWalletMarkedVoidAndRevokedCouponsVoid() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            let reward = try await h.reward(s.business, title: "10% off", kind: .coupon)
            let metadata = try await issuePass(h, s, kind: .coupon, rewardId: reward.id).json(WalletPassMetadata.self)
            let pass = try await record(h, metadata.id)
            let auth = token(h, pass)
            try await eq(try await register(h, pass, token: auth).status, .created)
            // Revoking the reward voids the pass and queues the push.
            try await eq(try await h.business(s.business, .POST, "/v1/business/rewards/\(reward.id)/revoke", body: Data("{}".utf8)).status, .ok)
            try await h.runJobs()
            XCTAssertEqual(h.passPush.sent.count, 1)
            let latest = try await h.request(.GET, "/wallet/v1/passes/\(pass.passTypeIdentifier)/\(pass.serialNumber)", headers: headers(auth))
            XCTAssertEqual(latest.status, .ok)
            XCTAssertEqual(try PKPassContents(latest.body).passJSON["voided"] as? Bool, true)
            try await eq(try await download(h, s.consumer, metadata.id).status, .gone, "the app's download refuses a void pass")
        }
    }

    func testRedeemingACouponVoidsItsPass() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            let reward = try await h.reward(s.business, title: "Free pastry", kind: .coupon)
            _ = try await h.claim(s.consumer, reward.id)
            let metadata = try await issuePass(h, s, kind: .coupon, rewardId: reward.id).json(WalletPassMetadata.self)
            let code = try await h.redeem(s.consumer, reward.id).json(RewardRedemption.self).redemptionCode
            try await eq(try await h.consume(s.business, code: code).status, .ok)
            let pass = try await record(h, metadata.id)
            XCTAssertTrue(pass.voided, "a spent coupon can't be shown again")
            let overview = try await h.entry(s.consumer, reward.id)
            XCTAssertEqual(overview.reward.walletPass, nil, "voided passes are not offered for Wallet")
        }
    }

    func testPassKitLogEndpointIsBoundedRedactedAndRateLimited() async throws {
        try await withHarness({ $0.rateLimits.walletLogPerIP = .perMinute(3, burst: 3) }) { h in
            struct Logs: Codable { var logs: [String] }
            let noisy = Logs(logs: (0..<50).map { "line \($0) token=abcdefghijklmnop \(String(repeating: "x", count: 900))" })
            let ok = try await h.post("/wallet/v1/log", noisy)
            XCTAssertEqual(ok.status, .ok)
            let stored = try await WalletLogRecord.query(on: h.db).all()
            XCTAssertEqual(stored.count, WalletService.maxLogMessages)
            XCTAssertTrue(stored.allSatisfy { $0.message.count <= WalletService.maxLogLength })
            XCTAssertFalse(stored.contains { $0.message.contains("abcdefghijklmnop") })
            try await eq(try await h.post("/wallet/v1/log", Logs(logs: ["a"])).status, .ok)
            try await eq(try await h.post("/wallet/v1/log", Logs(logs: ["a"])).status, .ok)
            try await eq(try await h.post("/wallet/v1/log", Logs(logs: ["a"])).status, .tooManyRequests)
            let malformed = try await h.request(.POST, "/wallet/v1/log", body: Data("not json".utf8))
            XCTAssertNotEqual(malformed.status, .ok)
        }
    }
}

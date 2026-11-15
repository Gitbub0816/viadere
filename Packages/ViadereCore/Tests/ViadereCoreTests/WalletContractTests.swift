import Foundation
import Testing
@testable import ViadereCore

@Suite("Wallet contract")
struct WalletContractTests {
    @Test("Scan codes are recognised by shape only, and garbage is refused before any network call")
    func scanCodeShape() {
        let good = WalletScanCode.prefix + String(repeating: "Ab0-_", count: 10).prefix(48)
        #expect(good.count == WalletScanCode.length)
        #expect(WalletScanCode.isWellFormed(good))
        #expect(WalletScanCode.isWellFormed("  \(good)\n"), "scanner whitespace is tolerated")
        #expect(!WalletScanCode.isWellFormed(String(good.dropLast())))
        #expect(!WalletScanCode.isWellFormed(good + "A"))
        #expect(!WalletScanCode.isWellFormed("VQ2." + good.dropFirst(4)))
        #expect(!WalletScanCode.isWellFormed(WalletScanCode.prefix + String(repeating: "=", count: 48)))
        #expect(!WalletScanCode.isWellFormed("K7M2Q-9XPB4"), "a redemption code is not a pass code")
        #expect(!WalletScanCode.isWellFormed(WalletScanCode.prefix + String(repeating: "é", count: 48)))
        // 36 bytes of base64url without padding is exactly 48 characters.
        #expect((WalletScanCode.payloadByteCount + WalletScanCode.tagByteCount) * 4 / 3 == 48)
    }

    @Test("Pass metadata stays compatible: the new fields are optional on the wire")
    func metadataCompatibility() throws {
        let old = #"{"id":"11111111-1111-4111-8111-111111111111","businessId":"22222222-2222-4222-8222-222222222222","kind":"storeCard","passTypeIdentifier":"pass.com.viadere.wallet","serialNumber":"VP-1","updatedAt":"2026-10-30T12:00:00.000Z","voided":false}"#
        let decoded = try ViadereJSON.decode(WalletPassMetadata.self, from: Data(old.utf8))
        #expect(decoded.scanCode == nil && decoded.usedAt == nil)
        var withCode = decoded
        withCode.scanCode = "VQ1.x"
        let round = try ViadereJSON.decode(WalletPassMetadata.self, from: ViadereJSON.encode(withCode))
        #expect(round == withCode)
    }

    @Test("Business Wallet routes are business-key routes in the catalog")
    func routes() {
        let wallet = [APIRoutes.businessWalletPassIssue.descriptor, APIRoutes.businessWalletPassesList.descriptor,
                      APIRoutes.businessWalletPassUpdate.descriptor, APIRoutes.businessWalletPassVoid.descriptor, APIRoutes.businessWalletScan.descriptor]
        let catalog = Set(APIRoutes.all.map { "\($0.method.rawValue) \($0.template)" })
        for route in wallet {
            #expect(route.auth == .businessAPIKey)
            #expect(catalog.contains("\(route.method.rawValue) \(route.template)"))
        }
        #expect(APIRoutes.businessWalletPassUpdate.method == .PATCH)
    }

    @Test("Scan results and business passes round-trip")
    func dtoRoundTrip() throws {
        let now = ViadereDate.truncatedToMilliseconds(Date(timeIntervalSince1970: 1_800_000_000))
        let result = WalletScanResult(outcome: .checkedIn, passId: WalletPassID(), kind: .eventTicket, relationshipId: RelationshipID(),
                                      title: "Jazz Night", scannedAt: now)
        #expect(try ViadereJSON.decode(WalletScanResult.self, from: ViadereJSON.encode(result)) == result)
        let pass = BusinessWalletPass(id: WalletPassID(), kind: .generic, relationshipId: RelationshipID(), issuedBy: .business, voided: false,
                                      usedAt: now, createdAt: now, updatedAt: now)
        #expect(try ViadereJSON.decode(BusinessWalletPass.self, from: ViadereJSON.encode(pass)) == pass)
        let update = UpdateWalletPassRequest(venue: "Hall B", rotateScanCode: true)
        #expect(try ViadereJSON.decode(UpdateWalletPassRequest.self, from: ViadereJSON.encode(update)) == update)
    }
}

import Fluent
import Foundation
import NIOHTTP1
import SQLKit
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Account recovery with single-use recovery codes (SECURITY.md §2.25).
final class RecoveryTests: XCTestCase {
    // MARK: Helpers

    struct Attempt {
        var result: HTTPResult
        var options: PasskeyRegistrationOptions?
    }

    func begin(_ h: TestHarness, _ set: RecoveryCodeSet, code: String? = nil, recoveryId: String? = nil) async throws -> Attempt {
        let result = try await h.post(APIRoutes.recoveryBegin.template, RecoveryBeginRequest(recoveryId: recoveryId ?? set.recoveryId, code: code ?? set.codes[0]))
        return Attempt(result: result, options: result.status == .ok ? try result.json(PasskeyRegistrationOptions.self) : nil)
    }

    /// Registers the new passkey for a recovery; returns the response and the new credential id.
    func finish(_ h: TestHarness, _ options: PasskeyRegistrationOptions) async throws -> (HTTPResult, String) {
        let id = SecureToken.generate(byteCount: 16)
        let credential = PasskeyRegistrationCredential(id: id, rawId: id, attestationObject: SecureToken.generate(byteCount: 32), clientDataJSON: options.challenge)
        return (try await h.post(APIRoutes.recoveryFinish.template, RecoveryFinishRequest(ceremonyId: options.ceremonyId, credential: credential)), id)
    }

    func complete(_ h: TestHarness, _ status: RecoveryStatus, token: String? = nil) async throws -> HTTPResult {
        try await h.post(APIRoutes.recoveryComplete.template, RecoveryCompleteRequest(recoveryId: status.id, statusToken: token ?? status.statusToken ?? ""))
    }

    func login(_ h: TestHarness, credentialId: String) async throws -> HTTPResult {
        let options = try await h.post(APIRoutes.loginBegin.template, PasskeyLoginBeginRequest()).json(PasskeyAssertionOptions.self)
        let credential = PasskeyAssertionCredential(id: credentialId, rawId: credentialId, authenticatorData: "AA", clientDataJSON: options.challenge, signature: "valid", userHandle: nil)
        return try await h.post(APIRoutes.loginFinish.template, PasskeyLoginFinishRequest(ceremonyId: options.ceremonyId, credential: credential))
    }

    func notices(_ h: TestHarness, _ consumer: TestConsumer) async throws -> [SecurityNotice] {
        try await h.signed(consumer, .GET, "/v1/security-notices").json([SecurityNotice].self)
    }

    func registerPush(_ h: TestHarness, _ consumer: TestConsumer) async throws {
        _ = try await h.signedPost(consumer, "/v1/push/apns-token", APNsTokenRegistration(token: String(repeating: "cd", count: 32), environment: .sandbox, bundleId: "com.viadere.app"))
    }

    /// An attacker who holds the recovery ID and one code starts a recovery; returns its status and the new credential id.
    func startRecovery(_ h: TestHarness, _ set: RecoveryCodeSet, code: String? = nil) async throws -> (RecoveryStatus, String) {
        let attempt = try await begin(h, set, code: code)
        XCTAssertEqual(attempt.result.status, .ok, attempt.result.text)
        let (response, credentialId) = try await finish(h, try XCTUnwrap(attempt.options))
        XCTAssertEqual(response.status, .created, response.text)
        return (try response.json(RecoveryStatus.self), credentialId)
    }

    // MARK: Issuing

    func testRegistrationIssuesTenSingleUseCodesStoredOnlyAsHmacs() async throws {
        try await withHarness { h in
            let user = try await h.registerConsumer()
            let set = try XCTUnwrap(user.session.recoveryCodes, "the codes are shown once, in the register/finish response")
            XCTAssertEqual(set.codes.count, 10)
            XCTAssertEqual(Set(set.codes).count, 10)
            XCTAssertTrue(set.codes.allSatisfy { RecoveryCodeFormat.normalizeCode($0) != nil && $0.count == 11 })
            XCTAssertNotNil(RecoveryCodeFormat.normalizeRecoveryID(set.recoveryId))
            // Only peppered HMACs are stored: nothing in the database contains a code, the recovery ID or the normalized forms.
            let rows = try await RecoveryCodeRecord.query(on: h.db).all()
            XCTAssertEqual(rows.count, 10)
            XCTAssertTrue(rows.allSatisfy { $0.state == "active" && $0.codeHash.count == 64 })
            let profile = try await XCTUnwrapAsync(try await RecoveryProfileRecord.query(on: h.db).first())
            let stored = rows.map(\.codeHash) + [profile.recoveryIdHash]
            for secret in set.codes + [set.recoveryId] {
                let normalized = RecoveryCodeFormat.normalizeCode(secret) ?? RecoveryCodeFormat.normalizeRecoveryID(secret)!
                XCTAssertFalse(stored.contains { $0.contains(normalized.lowercased()) || $0 == secret })
            }
            XCTAssertEqual(profile.recoveryIdHash, h.ctx.hasher.hmacHex("recovery-id", RecoveryCodeFormat.normalizeRecoveryID(set.recoveryId)!))
            // Signing in or refreshing never shows them again.
            let again = try await h.login(user)
            XCTAssertNil(again.session.recoveryCodes)
            let audited = try await AuditEventRecord.query(on: h.db).filter(\.$action == "recovery.codes_issued").all()
            XCTAssertEqual(audited.count, 1)
            XCTAssertFalse(audited[0].metadataJSON.contains(set.codes[0]))
        }
    }

    func testInfoCountsTheUnusedCodes() async throws {
        try await withHarness { h in
            let user = try await h.readyConsumer()
            let info = try await h.signed(user, .GET, "/v1/recovery").json(RecoveryInfo.self)
            XCTAssertEqual(info.remainingCodes, 10)
            XCTAssertNotNil(info.issuedAt)
            XCTAssertNil(info.pending)
            let (status, _) = try await startRecovery(h, try XCTUnwrap(user.session.recoveryCodes))
            let after = try await h.signed(user, .GET, "/v1/recovery").json(RecoveryInfo.self)
            XCTAssertEqual(after.remainingCodes, 9, "the code that began the recovery is spent")
            XCTAssertEqual(after.pending?.id, status.id)
            XCTAssertEqual(after.pending?.activatesAt, status.activatesAt)
        }
    }

    // MARK: Begin: uniform failures, attempt cap, IP budget

    func testEveryFailureLooksTheSameAndFiveWrongCodesLockTheAccount() async throws {
        try await withHarness { h in
            let user = try await h.readyConsumer()
            try await registerPush(h, user)
            let set = try XCTUnwrap(user.session.recoveryCodes)
            let wrong = try await begin(h, set, code: "ABCDE-FGHJK")
            let unknown = try await begin(h, set, code: set.codes[0], recoveryId: "AAAA-BBBB-CCCC")
            let malformed = try await begin(h, set, code: "nope")
            for failure in [wrong, unknown, malformed] { XCTAssertEqual(failure.result.status, .unauthorized, failure.result.text) }
            XCTAssertEqual(wrong.result.text.replacingOccurrences(of: #""requestId":"[^"]*""#, with: "", options: .regularExpression),
                           unknown.result.text.replacingOccurrences(of: #""requestId":"[^"]*""#, with: "", options: .regularExpression),
                           "an unknown recovery ID is indistinguishable from a wrong code")
            // Exploit (before): unlimited guessing. Now the account locks after 5 wrong codes, even for the right one.
            for _ in 0..<4 { try await eq(try await begin(h, set, code: "ZZZZZ-ZZZZZ").result.status, .unauthorized) }
            let locked = try await XCTUnwrapAsync(try await RecoveryProfileRecord.query(on: h.db).first())
            XCTAssertNotNil(locked.lockedUntil)
            let right = try await begin(h, set)
            XCTAssertEqual(right.result.status, .unauthorized, "the right code does not help while locked (same answer as a wrong one)")
            try await eq(try await RecoveryCodeRecord.query(on: h.db).filter(\.$state == "used").count(), 0)
            // The account's devices are told.
            let userNotices = try await notices(h, user)
            let notice = try XCTUnwrap(userNotices.first { $0.topic == .recoveryAttemptsLocked })
            XCTAssertNil(notice.action)
            XCTAssertTrue(h.push.sent.contains { $0.body.contains("wrong recovery codes") })
            // The lock ends by itself.
            h.clock.advance(by: 24 * 3600 + 1)
            let after = try await begin(h, set)
            XCTAssertEqual(after.result.status, .ok, after.result.text)
        }
    }

    func testRecoveryCeremoniesAreRateLimitedPerIP() async throws {
        try await withHarness { h in
            let set = RecoveryCodeSet(recoveryId: "AAAA-BBBB-CCCC", codes: ["ABCDE-FGHJK"], issuedAt: h.clock.now())
            var statuses: [UInt] = []
            for _ in 0..<14 { statuses.append(try await begin(h, set).result.status.code) }
            XCTAssertTrue(statuses.contains(429), "guessing recovery IDs from one address is throttled: \(statuses)")
            XCTAssertTrue(statuses.prefix(8).allSatisfy { $0 == 401 })
        }
    }

    // MARK: Round-4 re-review: parallel recoveries

    /// Exploit (before): `begin` counted open recoveries and then inserted, so N concurrent begins with different codes created N holding
    /// recoveries and one cancel flipped only one of them. Now a partial unique index allows one open recovery per account.
    func testConcurrentBeginsCreateAtMostOneOpenRecoveryAndCancelClosesEverything() async throws {
        try await withHarness { h in
            let owner = try await h.readyConsumer()
            let set = try XCTUnwrap(owner.session.recoveryCodes)
            let id = set.recoveryId
            let codes = set.codes
            let raw: [HTTPResult] = try await withThrowingTaskGroup(of: HTTPResult.self) { group in
                for index in 0..<8 {
                    group.addTask { try await h.post(APIRoutes.recoveryBegin.template, RecoveryBeginRequest(recoveryId: id, code: codes[index])) }
                }
                var all: [HTTPResult] = []
                for try await result in group { all.append(result) }
                return all
            }
            let results = try raw.map { Attempt(result: $0, options: $0.status == .ok ? try $0.json(PasskeyRegistrationOptions.self) : nil) }
            let wins = results.filter { $0.result.status == .ok }
            XCTAssertEqual(wins.count, 1, "exactly one begin wins: \(results.map { $0.result.status.code })")
            XCTAssertTrue(results.filter { $0.result.status != .ok }.allSatisfy { $0.result.status == .unauthorized }, "losers get the generic failure")
            let open = try await AccountRecoveryRecord.query(on: h.db).filter(\.$consumerId == owner.id.uuid).filter(\.$state ~~ ["awaiting_passkey", "holding"]).all()
            XCTAssertEqual(open.count, 1)
            // Lose-the-race codes are not burnt beyond the one that began.
            let used = try await RecoveryCodeRecord.query(on: h.db).filter(\.$state == "used").count()
            XCTAssertEqual(used, 1)
            let (response, credentialId) = try await finish(h, try XCTUnwrap(wins.first?.options))
            XCTAssertEqual(response.status, .created)
            let status = try response.json(RecoveryStatus.self)
            try await eq(try await h.signed(owner, .POST, "/v1/recovery/\(status.id)/cancel").status, .ok)
            try await eq(try await AccountRecoveryRecord.query(on: h.db).filter(\.$consumerId == owner.id.uuid).filter(\.$state ~~ ["awaiting_passkey", "holding"]).count(), 0)
            h.clock.advance(by: 73 * 3600)
            try await h.runJobs()
            try await eq(try await login(h, credentialId: credentialId).status, .unauthorized, "nothing can activate after the cancel")
        }
    }

    /// A second open recovery cannot exist even when written directly (the database refuses it), and cancel sweeps every open one.
    func testTheDatabaseRefusesASecondOpenRecoveryAndCancelClosesAllOfThem() async throws {
        try await withHarness { h in
            let owner = try await h.readyConsumer()
            let (status, _) = try await startRecovery(h, try XCTUnwrap(owner.session.recoveryCodes))
            let extra = AccountRecoveryRecord(consumerId: owner.id.uuid, challenge: "c", userHandle: "u", now: h.clock.now())
            do {
                try await extra.create(on: h.db)
                XCTFail("a second open recovery must violate the unique index")
            } catch { XCTAssertTrue(error.isConstraintViolation, "\(error)") }
            // A finished one does not count.
            _ = try await h.signed(owner, .POST, "/v1/recovery/\(status.id)/cancel")
            try await AccountRecoveryRecord(consumerId: owner.id.uuid, challenge: "c", userHandle: "u", now: h.clock.now()).create(on: h.db)
        }
    }

    // MARK: Round-4 re-review: owner cancel paths

    func testInfoListsEveryPendingRecoveryAndRegeneratingCodesCancelsThem() async throws {
        try await withHarness { h in
            let owner = try await h.readyConsumer()
            let cooling = try await h.enrollDevice(owner)
            let set = try XCTUnwrap(owner.session.recoveryCodes)
            let (status, newCredential) = try await startRecovery(h, set)
            let info = try await h.signed(owner, .GET, "/v1/recovery").json(RecoveryInfo.self)
            XCTAssertEqual(info.pendingRecoveries.map(\.id), [status.id])
            XCTAssertEqual(info.pending?.id, status.id, "the old field stays for older clients")
            // Exploit (before): making new codes left the attacker's recovery running, so it still activated after 72 h.
            let begun = try await h.signed(owner, .POST, "/v1/recovery/codes/begin").json(PasskeyAssertionOptions.self)
            let assertion = PasskeyAssertionCredential(id: owner.credentialId, rawId: owner.credentialId, authenticatorData: "AA", clientDataJSON: begun.challenge,
                                                       signature: "valid", userHandle: nil)
            let done = try await h.signedPost(owner, "/v1/recovery/codes/regenerate", RecoveryCodesRegenerateRequest(ceremonyId: begun.ceremonyId, assertion: assertion))
            XCTAssertEqual(done.status, .created, done.text)
            let after = try await h.signed(owner, .GET, "/v1/recovery").json(RecoveryInfo.self)
            XCTAssertTrue(after.pendingRecoveries.isEmpty)
            XCTAssertNil(after.pending)
            let coolingNotices = try await notices(h, cooling)
            XCTAssertTrue(coolingNotices.contains { $0.topic == .recoveryCancelled })
            h.clock.advance(by: 73 * 3600)
            try await h.runJobs()
            try await eq(try await complete(h, status).json(RecoveryStatus.self).state, .cancelled)
            try await eq(try await login(h, credentialId: newCredential).status, .unauthorized, "the attacker's passkey never became usable")
            try await eq(try await login(h, credentialId: owner.credentialId).status, .ok)
        }
    }

    /// Exploit (before): the notice was best effort, so a recovery could start without the owner's account ever storing a notice.
    func testARecoveryDoesNotStartWhenItsNoticeCannotBeStored() async throws {
        try await withHarness { h in
            let owner = try await h.readyConsumer()
            let set = try XCTUnwrap(owner.session.recoveryCodes)
            let attempt = try await begin(h, set)
            let options = try XCTUnwrap(attempt.options)
            let sql = h.db as! any SQLDatabase
            try await sql.raw("ALTER TABLE security_notices RENAME TO security_notices_off").run()
            let result: (HTTPResult, String)
            do { result = try await finish(h, options) } catch {
                try await sql.raw("ALTER TABLE security_notices_off RENAME TO security_notices").run()
                throw error
            }
            try await sql.raw("ALTER TABLE security_notices_off RENAME TO security_notices").run()
            XCTAssertGreaterThanOrEqual(result.0.status.code, 500, result.0.text)
            let rows = try await AccountRecoveryRecord.query(on: h.db).filter(\.$consumerId == owner.id.uuid).all()
            XCTAssertEqual(rows.map(\.state), ["awaiting_passkey"], "no hold started without a stored notice")
            try await eq(try await h.signed(owner, .GET, "/v1/recovery").json(RecoveryInfo.self).pendingRecoveries.count, 0)
        }
    }

    // MARK: Round-4 re-review: third-party trust

    /// Exploit (before): an attacker who recovered the account inherited its household grants (in both directions) and its verified phone
    /// numbers, with no cool-down, without the counterpart accounts ever hearing about it.
    func testActivationEndsHouseholdGrantsTellsBothSidesAndPutsPhonesBackInCoolDown() async throws {
        try await withHarness({ $0.accessTokenTTL = 90 * 86_400 }) { h in
            let business = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let owner = try await h.readyConsumer(name: "Alex")
            let sam = try await h.readyConsumer(name: "Sam")
            let lee = try await h.readyConsumer(name: "Lee")
            _ = try await h.connect(owner, to: business)
            _ = try await h.connect(lee, to: business)
            let given = try await h.shareAccess(from: owner, to: sam, purposes: [.transactional], businesses: [business], lifetimeDays: 20)
            let received = try await h.shareAccess(from: lee, to: owner, purposes: [.transactional], businesses: [business], lifetimeDays: 20)
            let phone = PhoneNumber("+14805550123")!
            let link = try PhoneLinkRecord(consumerId: owner.id.uuid, phone: phone, hasher: h.ctx.hasher, cipher: h.ctx.cipher, now: h.clock.now())
            link.state = "verified"
            link.verifiedPhoneHash = h.ctx.hasher.phoneHash(phone)
            link.verifiedAt = h.clock.now()
            try await link.create(on: h.db)
            let before = try await XCTUnwrapAsync(try await PhoneLinkRecord.find(link.id!, on: h.db))
            XCTAssertTrue(before.isUsable(at: h.clock.now()))

            let (status, newCredential) = try await startRecovery(h, try XCTUnwrap(owner.session.recoveryCodes))
            // Nothing changes during the hold.
            try await eq(try await h.household(sam).received.first?.status, .active)
            h.clock.advance(by: 72 * 3600 + 1)
            let done = try await complete(h, status).json(RecoveryStatus.self)
            XCTAssertEqual(done.state, .activated)
            let activated = h.clock.now()

            try await eq(try await h.household(sam).received.first { $0.grant.id == given.grant.id }?.status, .revoked)
            try await eq(try await h.household(lee).given.first { $0.grant.id == received.grant.id }?.status, .revoked)
            try await eq(try await DelegationGrantRecord.query(on: h.db).filter(\.$revokedAt == nil).count(), 0)
            // Both counterparts are told.
            for other in [sam, lee] {
                let list = try await notices(h, other)
                XCTAssertTrue(list.contains { $0.topic == .delegationEnded }, "\(list.map(\.rawKind))")
            }
            // The phone is cooling down again, confirmable from a trusted device, and does not act as the account until then.
            let cooled = try await XCTUnwrapAsync(try await PhoneLinkRecord.find(link.id!, on: h.db))
            XCTAssertEqual(cooled.usableFrom, activated.addingTimeInterval(72 * 3600))
            XCTAssertNil(cooled.confirmedAt)
            XCTAssertFalse(cooled.isUsable(at: activated))
            XCTAssertTrue(cooled.isUsable(at: activated.addingTimeInterval(72 * 3600 + 1)))
            // The recovered account has a stored notice about what happened to its household and phones.
            try await eq(try await SecurityNoticeRecord.query(on: h.db).filter(\.$consumerId == owner.id.uuid).filter(\.$kind == "recoveryCompleted").count(), 1)
            try await eq(try await login(h, credentialId: newCredential).status, .ok)
            let audit = try await AuditEventRecord.query(on: h.db).filter(\.$action == "recovery.activated").first()
            XCTAssertTrue(try XCTUnwrap(audit).metadataJSON.contains("\"delegations_ended\":\"2\""))
        }
    }

    // MARK: Round-4 re-review: shared recovery budgets

    func testFloodsOfMalformedOrMadeUpRecoveriesFromManyAddressesDoNotBlockARealRecovery() async throws {
        try await withHarness({ $0.trustedProxyCount = 1 }) { h in
            let owner = try await h.readyConsumer()
            let set = try XCTUnwrap(owner.session.recoveryCodes)
            func post(_ id: String, _ code: String, ip: String) async throws -> HTTPResult {
                try await h.post(APIRoutes.recoveryBegin.template, RecoveryBeginRequest(recoveryId: id, code: code), headers: ["X-Forwarded-For": ip])
            }
            // 400 malformed requests from 400 addresses never touch the global budget.
            for index in 0..<400 { _ = try await post("not an id", "nope", ip: "198.51.\(index / 250).\(index % 250 + 1)") }
            // 400 well-formed, made-up IDs from as many addresses use it up for guessers (429 once it is gone)...
            var exhausted = false
            for index in 0..<400 {
                let id = RecoveryCodeFormat.generateRecoveryID()
                let result = try await post(id, "ABCDE-FGHJK", ip: "203.0.\(index / 250).\(index % 250 + 1)")
                if result.status == .tooManyRequests { exhausted = true }
            }
            XCTAssertTrue(exhausted, "guessing the ID space from many addresses is bounded by the global budget")
            // ...but the owner's real recovery ID is not behind that wall.
            let real = try await post(set.recoveryId, set.codes[0], ip: "192.0.2.77")
            XCTAssertEqual(real.status, .ok, real.text)
        }
    }

    func testGuessingCodesForOneRecoveryIDFromManyAddressesIsBoundedPerID() async throws {
        try await withHarness({ $0.trustedProxyCount = 1 }) { h in
            let owner = try await h.readyConsumer()
            let set = try XCTUnwrap(owner.session.recoveryCodes)
            var statuses: [UInt] = []
            for index in 0..<30 {
                let result = try await h.post(APIRoutes.recoveryBegin.template, RecoveryBeginRequest(recoveryId: set.recoveryId, code: "ZZZZZ-ZZZZ\(index % 9 + 1)"),
                                              headers: ["X-Forwarded-For": "198.18.\(index).1"])
                statuses.append(result.status.code)
            }
            XCTAssertTrue(statuses.contains(429), "one ID cannot be hammered from many addresses: \(statuses)")
            // A request that names no account does not burn the victim's per-ID budget.
            let unrelated = try await h.post(APIRoutes.recoveryBegin.template, RecoveryBeginRequest(recoveryId: "AAAA-BBBB-CCCC", code: "ABCDE-FGHJK"),
                                             headers: ["X-Forwarded-For": "198.19.0.1"])
            XCTAssertEqual(unrelated.status, .unauthorized)
        }
    }

    // MARK: The 72 h hold

    func testTheNewPasskeyIsUnusableDuring72HoursThenReplacesEverything() async throws {
        try await withHarness { h in
            let owner = try await h.readyConsumer()
            try await registerPush(h, owner)
            let second = try await h.enrollDevice(owner)            // the owner's other (cooling-down) device
            let set = try XCTUnwrap(owner.session.recoveryCodes)
            let oldCredential = owner.credentialId
            let (status, newCredential) = try await startRecovery(h, set)
            XCTAssertEqual(status.state, .holding)
            XCTAssertEqual(status.activatesAt, h.clock.now().addingTimeInterval(72 * 3600))
            XCTAssertNotNil(status.statusToken)

            // Every existing device is told, with a "Not you? Cancel" action; a push goes out.
            for device in [owner, second] {
                let deviceNotices = try await notices(h, device)
                let notice = try XCTUnwrap(deviceNotices.first { $0.topic == .recoveryStarted })
                XCTAssertEqual(notice.action, .cancelRecovery)
                XCTAssertEqual(notice.subjectId, status.id.description)
            }
            XCTAssertTrue(h.push.sent.contains { $0.body.contains("Account recovery was started") && $0.category == "viadere.security.cancel" })

            // Exploit (before): n/a. During the hold the new passkey does not sign in, and the old passkey and devices still do.
            let early = try await login(h, credentialId: newCredential)
            XCTAssertEqual(early.status, .unauthorized, "the new passkey is not usable until the hold ends")
            try await eq(try await login(h, credentialId: oldCredential).status, .ok)
            try await eq(try await h.signed(owner, .GET, "/v1/devices").status, .ok)
            // Polling during the hold says so; a wrong token is nothing.
            let polling = try await complete(h, status)
            XCTAssertEqual(polling.status, .ok, polling.text)
            let held = try polling.json(RecoveryStatus.self)
            XCTAssertEqual(held.state, .holding)
            XCTAssertNil(held.recoveryCodes)
            XCTAssertNil(held.statusToken, "the token is only returned once")
            try await eq(try await complete(h, status, token: "wrong").status, .unauthorized)
            // A competing recovery during the hold is refused and does not burn a code.
            let usedBefore = try await RecoveryCodeRecord.query(on: h.db).filter(\.$state == "used").count()
            try await eq(try await begin(h, set, code: set.codes[1]).result.status, .unauthorized)
            try await eq(try await RecoveryCodeRecord.query(on: h.db).filter(\.$state == "used").count(), usedBefore)

            h.clock.advance(by: 72 * 3600 - 5)
            let almost = try await complete(h, status).json(RecoveryStatus.self)
            XCTAssertEqual(almost.state, .holding)
            h.clock.advance(by: 10)
            let done = try await complete(h, status)
            XCTAssertEqual(done.status, .ok, done.text)
            let activated = try done.json(RecoveryStatus.self)
            XCTAssertEqual(activated.state, .activated)
            let fresh = try XCTUnwrap(activated.recoveryCodes, "the replacement codes are returned once")
            XCTAssertEqual(fresh.codes.count, 10)
            XCTAssertNotEqual(fresh.recoveryId, set.recoveryId)
            // The second call does not show them again.
            let repeatCall = try await complete(h, status).json(RecoveryStatus.self)
            XCTAssertEqual(repeatCall.state, .activated)
            XCTAssertNil(repeatCall.recoveryCodes)

            // Everything old is gone: devices, sessions, the old passkey and the old codes.
            try await eq(try await h.signed(owner, .GET, "/v1/devices").status, .unauthorized)
            try await eq(try await h.signed(second, .GET, "/v1/devices").status, .unauthorized)
            try await eq(try await h.refresh(owner).status, .unauthorized)
            let devices = try await DeviceRecord.query(on: h.db).filter(\.$consumerId == owner.id.uuid).all()
            XCTAssertTrue(devices.allSatisfy { $0.revokedAt != nil })
            try await eq(try await login(h, credentialId: oldCredential).status, .unauthorized, "the old passkey is gone")
            try await eq(try await begin(h, set, code: set.codes[2]).result.status, .unauthorized, "the old codes and recovery ID are dead")
            // The new passkey works, and the account then enrolls like a lapsed one: it must cool down.
            let signedIn = try await login(h, credentialId: newCredential)
            XCTAssertEqual(signedIn.status, .ok, signedIn.text)
            var recovered = owner
            recovered.credentialId = newCredential
            recovered.session = try signedIn.json(AuthSession.self)
            recovered.device = nil
            let enrolled = try await h.enrollDevice(recovered)
            let record = try await XCTUnwrapAsync(try await DeviceRecord.find(enrolled.device!.id.uuid, on: h.db))
            XCTAssertEqual(record.approvalsLockedUntil, h.clock.now().addingTimeInterval(24 * 3600))
            // The new codes work.
            let second2 = try await begin(h, fresh)
            XCTAssertEqual(second2.result.status, .ok, second2.result.text)
            let audit = try await AuditEventRecord.query(on: h.db).all().map(\.action)
            XCTAssertTrue(audit.contains("recovery.started") && audit.contains("recovery.activated"))
        }
    }

    func testTheBackgroundSweepActivatesADueRecoveryWithoutTheClient() async throws {
        try await withHarness { h in
            let owner = try await h.readyConsumer()
            let (status, newCredential) = try await startRecovery(h, try XCTUnwrap(owner.session.recoveryCodes))
            h.clock.advance(by: 72 * 3600 + 1)
            try await h.runJobs()
            try await eq(try await h.signed(owner, .GET, "/v1/devices").status, .unauthorized, "old devices are revoked at 72 h even if nobody returns")
            try await eq(try await login(h, credentialId: newCredential).status, .ok)
            // The client that comes back later still gets the new codes, once.
            let done = try await complete(h, status).json(RecoveryStatus.self)
            XCTAssertEqual(done.state, .activated)
            XCTAssertEqual(done.recoveryCodes?.codes.count, 10)
            try await eq(try await complete(h, status).json(RecoveryStatus.self).recoveryCodes?.codes.count, nil)
        }
    }

    // MARK: Cancelling

    func testAnyTrustedDeviceCancelsAndTheCodesAreInvalidated() async throws {
        try await withHarness { h in
            let owner = try await h.readyConsumer()
            let cooling = try await h.enrollDevice(owner)            // enrolled a minute ago: not a trusted device
            let set = try XCTUnwrap(owner.session.recoveryCodes)
            let (status, newCredential) = try await startRecovery(h, set)
            // A device that is cooling down cannot cancel (it could be the attacker's), a stranger's device cannot either.
            let tooNew = try await h.signed(cooling, .POST, "/v1/recovery/\(status.id)/cancel")
            XCTAssertEqual(tooNew.status, .forbidden)
            XCTAssertEqual(tooNew.errorCode, .deviceCoolDown)
            let stranger = try await h.readyConsumer(name: "Stranger")
            try await eq(try await h.signed(stranger, .POST, "/v1/recovery/\(status.id)/cancel").status, .notFound)
            try await eq(try await h.signed(owner, .GET, "/v1/recovery").json(RecoveryInfo.self).pending != nil, true)
            // The owner's trusted device cancels.
            let cancel = try await h.signed(owner, .POST, "/v1/recovery/\(status.id)/cancel")
            XCTAssertEqual(cancel.status, .ok, cancel.text)
            XCTAssertEqual(try cancel.json(RecoveryStatus.self).state, .cancelled)
            try await eq(try await h.signed(owner, .POST, "/v1/recovery/\(status.id)/cancel").json(RecoveryStatus.self).state, .cancelled, "idempotent")
            // Whoever started it held a code: the rest are dead, and a new recovery with one is refused.
            try await eq(try await RecoveryCodeRecord.query(on: h.db).filter(\.$consumerId == owner.id.uuid).filter(\.$state == "active").count(), 0)
            try await eq(try await begin(h, set, code: set.codes[3]).result.status, .unauthorized)
            let info = try await h.signed(owner, .GET, "/v1/recovery").json(RecoveryInfo.self)
            XCTAssertEqual(info.remainingCodes, 0)
            XCTAssertNil(info.pending)
            let coolingNotices = try await notices(h, cooling)
            XCTAssertTrue(coolingNotices.contains { $0.topic == .recoveryCancelled })
            // 72 hours later nothing happens.
            h.clock.advance(by: 73 * 3600)
            try await h.runJobs()
            let polled = try await complete(h, status).json(RecoveryStatus.self)
            XCTAssertEqual(polled.state, .cancelled)
            XCTAssertNil(polled.recoveryCodes)
            try await eq(try await login(h, credentialId: newCredential).status, .unauthorized, "the new passkey never became usable")
            try await eq(try await login(h, credentialId: owner.credentialId).status, .ok)
            var again = owner
            again.session = try await h.refresh(owner).json(AuthSession.self)
            try await eq(try await h.signed(again, .GET, "/v1/devices").status, .ok, "the owner's device and session survived")
        }
    }

    func testTheNewPasskeyMustBeRegisteredQuicklyAndOnlyOnce() async throws {
        try await withHarness { h in
            let user = try await h.readyConsumer()
            let set = try XCTUnwrap(user.session.recoveryCodes)
            let first = try await begin(h, set)
            h.clock.advance(by: 11 * 60)
            let late = try await finish(h, try XCTUnwrap(first.options))
            XCTAssertEqual(late.0.status, .unauthorized, "the passkey window is 10 minutes")
            // The next code starts over; finishing twice (or with a mismatched challenge) is refused.
            let second = try await begin(h, set, code: set.codes[1])
            XCTAssertEqual(second.result.status, .ok, second.result.text)
            let options = try XCTUnwrap(second.options)
            var wrong = options
            wrong.challenge = SecureToken.generate()
            try await eq(try await finish(h, wrong).0.status, .unauthorized)
            let ok = try await finish(h, options)
            XCTAssertEqual(ok.0.status, .created, ok.0.text)
            try await eq(try await finish(h, options).0.status, .unauthorized, "single use")
            // An existing credential cannot be "registered" as the new passkey.
            let third = try await begin(h, set, code: set.codes[2])
            XCTAssertEqual(third.result.status, .unauthorized, "a recovery is already holding")
        }
    }

    // MARK: Regenerating codes

    func testRegeneratingCodesNeedsATrustedDeviceAndAFreshPasskeyAssertion() async throws {
        try await withHarness { h in
            let owner = try await h.readyConsumer()
            let cooling = try await h.enrollDevice(owner)
            let set = try XCTUnwrap(owner.session.recoveryCodes)
            // A cooling-down device (a thief's) cannot make codes.
            let blocked = try await h.signed(cooling, .POST, "/v1/recovery/codes/begin")
            XCTAssertEqual(blocked.status, .forbidden)
            XCTAssertEqual(blocked.errorCode, .deviceCoolDown)
            // Exploit: a stolen bearer token plus the device's signature, without the passkey, is not enough.
            let begun = try await h.signed(owner, .POST, "/v1/recovery/codes/begin")
            XCTAssertEqual(begun.status, .ok, begun.text)
            let options = try begun.json(PasskeyAssertionOptions.self)
            XCTAssertEqual(options.userVerification, "required")
            // Neither this device's proof nor a passkey assertion: refused (401), and nothing is consumed.
            let noAssertion = try await h.signed(owner, .POST, "/v1/recovery/codes/regenerate", body: Data(#"{"ceremonyId":"\#(options.ceremonyId)"}"#.utf8))
            XCTAssertEqual(noAssertion.status, .unauthorized)
            XCTAssertEqual(noAssertion.errorCode, .passkeyAssertionRequired)
            func assertion(_ id: String, _ challenge: String, signature: String = "valid") -> PasskeyAssertionCredential {
                PasskeyAssertionCredential(id: id, rawId: id, authenticatorData: "AA", clientDataJSON: challenge, signature: signature, userHandle: nil)
            }
            let forged = try await h.signedPost(owner, "/v1/recovery/codes/regenerate", RecoveryCodesRegenerateRequest(
                ceremonyId: options.ceremonyId, assertion: assertion(owner.credentialId, options.challenge, signature: "forged")))
            XCTAssertEqual(forged.status, .unauthorized)
            XCTAssertEqual(forged.errorCode, .passkeyAssertionRequired)
            // The challenge is single use: the failed attempt consumed it.
            let reuse = try await h.signedPost(owner, "/v1/recovery/codes/regenerate", RecoveryCodesRegenerateRequest(
                ceremonyId: options.ceremonyId, assertion: assertion(owner.credentialId, options.challenge)))
            XCTAssertEqual(reuse.status, .unauthorized)
            try await eq(try await RecoveryCodeRecord.query(on: h.db).filter(\.$consumerId == owner.id.uuid).filter(\.$state == "active").count(), 10, "nothing changed")
            // Another account's passkey is no good either.
            let stranger = try await h.readyConsumer(name: "Stranger")
            let second = try await h.signed(owner, .POST, "/v1/recovery/codes/begin").json(PasskeyAssertionOptions.self)
            let foreign = try await h.signedPost(owner, "/v1/recovery/codes/regenerate", RecoveryCodesRegenerateRequest(
                ceremonyId: second.ceremonyId, assertion: assertion(stranger.credentialId, second.challenge)))
            XCTAssertEqual(foreign.status, .unauthorized)
            // With the owner's passkey it works: new set, old codes and recovery ID die.
            let third = try await h.signed(owner, .POST, "/v1/recovery/codes/begin").json(PasskeyAssertionOptions.self)
            let done = try await h.signedPost(owner, "/v1/recovery/codes/regenerate", RecoveryCodesRegenerateRequest(
                ceremonyId: third.ceremonyId, assertion: assertion(owner.credentialId, third.challenge)))
            XCTAssertEqual(done.status, .created, done.text)
            let fresh = try done.json(RecoveryCodeSet.self)
            XCTAssertEqual(fresh.codes.count, 10)
            XCTAssertNotEqual(fresh.recoveryId, set.recoveryId)
            try await eq(try await RecoveryCodeRecord.query(on: h.db).filter(\.$consumerId == owner.id.uuid).filter(\.$state == "active").count(), 10)
            try await eq(try await RecoveryCodeRecord.query(on: h.db).filter(\.$consumerId == owner.id.uuid).filter(\.$state == "invalidated").count(), 10)
            try await eq(try await begin(h, set).result.status, .unauthorized, "the old set is dead")
            let usable = try await begin(h, fresh)
            XCTAssertEqual(usable.result.status, .ok)
            let audit = try await AuditEventRecord.query(on: h.db).all().map(\.action)
            XCTAssertTrue(audit.contains("recovery.codes_regenerated") && audit.contains("recovery.codes_failed"))
        }
    }

    func testAnAccountThatPredatesCodesCanGetThemFromATrustedDevice() async throws {
        try await withHarness { h in
            let owner = try await h.readyConsumer()
            try await RecoveryCodeRecord.query(on: h.db).delete()
            try await RecoveryProfileRecord.query(on: h.db).delete()
            let info = try await h.signed(owner, .GET, "/v1/recovery").json(RecoveryInfo.self)
            XCTAssertEqual(info.remainingCodes, 0)
            XCTAssertNil(info.issuedAt)
            let options = try await h.signed(owner, .POST, "/v1/recovery/codes/begin").json(PasskeyAssertionOptions.self)
            let done = try await h.signedPost(owner, "/v1/recovery/codes/regenerate", RecoveryCodesRegenerateRequest(
                ceremonyId: options.ceremonyId, assertion: PasskeyAssertionCredential(id: owner.credentialId, rawId: owner.credentialId, authenticatorData: "AA",
                                                                                      clientDataJSON: options.challenge, signature: "valid", userHandle: nil)))
            XCTAssertEqual(done.status, .created, done.text)
            XCTAssertEqual(try done.json(RecoveryCodeSet.self).codes.count, 10)
        }
    }

    func testAnAccountWithoutAnyDeviceCanRecoverToo() async throws {
        try await withHarness { h in
            let user = try await h.registerConsumer()            // never enrolled a device: nobody to notify or to cancel
            let set = try XCTUnwrap(user.session.recoveryCodes)
            let (status, newCredential) = try await startRecovery(h, set)
            h.clock.advance(by: 72 * 3600 + 1)
            let done = try await complete(h, status).json(RecoveryStatus.self)
            XCTAssertEqual(done.state, .activated)
            try await eq(try await login(h, credentialId: newCredential).status, .ok)
            try await eq(try await login(h, credentialId: user.credentialId).status, .unauthorized)
        }
    }
}

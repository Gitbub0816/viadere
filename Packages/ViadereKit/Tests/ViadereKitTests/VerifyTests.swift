import Foundation
import Testing
import ViadereCore
@testable import ViadereKit

/// Scripted Wallet: records what was requested.
actor FakeWallet: WalletIdentityService {
    var available: WalletAvailability
    var failure: WalletPresentationError?
    private(set) var requests: [WalletElementPlan.Request] = []
    private(set) var nonces: [Data] = []
    private(set) var merchants: [String] = []
    init(available: WalletAvailability = .available, failure: WalletPresentationError? = nil) {
        self.available = available
        self.failure = failure
    }
    func setAvailability(_ value: WalletAvailability) { available = value }
    func setFailure(_ value: WalletPresentationError?) { failure = value }
    nonisolated func availability(for request: WalletElementPlan.Request) async -> WalletAvailability { await available }
    func present(_ request: WalletElementPlan.Request, nonce: Data, merchantIdentifier: String) async throws -> Data {
        requests.append(request)
        nonces.append(nonce)
        merchants.append(merchantIdentifier)
        if let failure { throw failure }
        return Data("encrypted-response".utf8)
    }
}

actor FakeDocumentFlow: DocumentVerificationService {
    private(set) var tokens: [String] = []
    var result: DocumentFlowResult = .finished
    func setResult(_ value: DocumentFlowResult) { result = value }
    func verify(sessionToken: String) async -> DocumentFlowResult {
        tokens.append(sessionToken)
        return result
    }
}

@MainActor
@Suite("Verification flow")
struct VerificationFlowTests {
    func model(_ prompt: VerificationPrompt, api: MockVerifyAPI, wallet: FakeWallet = FakeWallet(), document: FakeDocumentFlow = FakeDocumentFlow(),
               lock: MockAppLockAuthenticator = MockAppLockAuthenticator()) async -> VerificationViewModel {
        await api.add(prompt)
        return VerificationViewModel(id: prompt.id, api: api, wallet: wallet, document: document, lock: lock)
    }

    @Test func thePersonSeesWhoWhyWhatAndWhenBeforeConsenting() async throws {
        let api = MockVerifyAPI()
        let prompt = VerificationPrompt.sampleAge(years: 21, business: "Northwind Spirits")
        let vm = await model(prompt, api: api)
        await vm.load()
        #expect(vm.phase == .reviewing)
        #expect(vm.prompt?.recipientName == "Northwind Spirits")
        #expect(vm.disclosure.map(\.field) == ["meets_threshold"])
        #expect(vm.disclosure[0].title.contains("21"))
        #expect(vm.purposeText.contains("age-restricted"))
        #expect(vm.prompt?.notDisclosed.contains("Your date of birth") == true)
        #expect(vm.note == VerificationCopy.ageNote)
        #expect(vm.remaining > 0 && !vm.isExpired)
        // Nothing was sent to the server except reading the prompt.
        #expect(await api.consentLog.isEmpty)
    }

    @Test func consentRequiresLocalAuthenticationAndQuotesTheDisplayDigest() async throws {
        let api = MockVerifyAPI()
        let prompt = VerificationPrompt.sampleAge()
        let denied = await model(prompt, api: api, lock: MockAppLockAuthenticator(succeeds: false))
        await denied.load()
        await denied.consent()
        #expect(denied.phase == .reviewing, "an unlock that fails shares nothing")
        #expect(await api.consentLog.isEmpty)
        let ok = await model(prompt, api: api)
        await ok.load()
        await ok.consent()
        #expect(ok.phase == .choosingMethod)
        let log = await api.consentLog
        #expect(log.count == 1 && log[0].0 == prompt.id && log[0].1 == prompt.displayDigest)
    }

    @Test func aChangedRequestIsNotConsentedToBlindly() async throws {
        let api = MockVerifyAPI()
        var prompt = VerificationPrompt.sampleAge()
        let vm = await model(prompt, api: api)
        await vm.load()
        // The server's version changed after the person looked (a different digest): consent is refused and the person is told to look again.
        prompt.displayDigest = "sha256:changed"
        await api.add(prompt)
        await vm.consent()
        guard case .failed(let message) = vm.phase else { Issue.record("expected a failure"); return }
        #expect(message.contains("changed"))
        #expect(await api.consentLog.isEmpty)
    }

    @Test func walletComesFirstWhenItCanAnswerAndTheRequestUsesAgeAtLeast() async throws {
        let api = MockVerifyAPI()
        let wallet = FakeWallet()
        let vm = await model(.sampleAge(years: 21), api: api, wallet: wallet)
        await vm.load()
        await vm.consent()
        #expect(vm.orderedMethods == [.wallet, .document])
        #expect(vm.walletAvailability == .available)
        await vm.verifyWithWallet()
        guard case .finished(let outcome) = vm.phase else { Issue.record("expected finished, got \(vm.phase)"); return }
        #expect(outcome.status == .released && outcome.label == .verifiedAgeThreshold)
        #expect(vm.resultText == VerificationCopy.released)
        // The age threshold is requested as age(atLeast:), never as a birthdate; the nonce is the server's, as raw bytes.
        #expect(await wallet.requests == [.ageAtLeast(21)])
        #expect(WalletElementPlan.requestedIdentifiers(for: .ageAtLeast(21)) == ["age_over_21"])
        #expect(await wallet.merchants == ["merchant.com.viadere.test"])
        #expect(await wallet.nonces.first?.count == 32)
        #expect(await api.walletEnvelopes == [Data("encrypted-response".utf8)])
    }

    @Test func withoutAWalletIDTheDocumentPathIsTheAlternative() async throws {
        let api = MockVerifyAPI()
        let wallet = FakeWallet(available: .unavailable)
        let document = FakeDocumentFlow()
        let vm = await model(.sampleAge(), api: api, wallet: wallet, document: document)
        await vm.load()
        await vm.consent()
        #expect(vm.orderedMethods == [.document], "Wallet is not offered when it cannot answer")
        await vm.verifyWithWallet()
        #expect(vm.phase == .choosingMethod, "choosing an unavailable method does nothing")
        #expect(await wallet.requests.isEmpty)
        await vm.verifyWithDocument()
        #expect(await document.tokens == ["token-for-tests"])
        guard case .finished(let outcome) = vm.phase else { Issue.record("expected finished"); return }
        #expect(outcome.status == .released)
        #expect(VerificationCopy.alternativePath.contains("instead") && VerificationCopy.alternativePath.contains("you can say no"))
    }

    @Test func theServerNotOfferingAMethodHidesIt() async throws {
        let api = MockVerifyAPI()
        await api.setServerMethods(wallet: false, document: false)
        let vm = await model(.sampleAge(), api: api)
        await vm.load()
        await vm.consent()
        #expect(vm.orderedMethods.isEmpty)
        #expect(VerificationCopy.noMethodAvailable.contains("decline"))
    }

    @Test func cancellingWalletReturnsToTheChoiceWithoutTellingTheServer() async throws {
        let api = MockVerifyAPI()
        let wallet = FakeWallet(failure: .cancelled)
        let vm = await model(.sampleAge(), api: api, wallet: wallet)
        await vm.load()
        await vm.consent()
        await vm.verifyWithWallet()
        #expect(vm.phase == .choosingMethod)
        #expect(await api.walletEnvelopes.isEmpty, "nothing was sent")
        await wallet.setFailure(.unavailable)
        await vm.verifyWithWallet()
        #expect(vm.phase == .choosingMethod)
        #expect(vm.notice == VerificationCopy.walletUnavailableReason)
    }

    @Test func aFailedAttemptSaysTheSameThingWhateverTheReason() async throws {
        let api = MockVerifyAPI()
        await api.setWalletOutcome(VerificationAttemptOutcome(status: .consented, label: nil, receiptId: nil, canRetry: true))
        let vm = await model(.sampleAge(), api: api)
        await vm.load()
        await vm.consent()
        await vm.verifyWithWallet()
        #expect(vm.phase == .choosingMethod)
        #expect(vm.notice == VerificationCopy.retry)
        #expect(!VerificationCopy.retry.lowercased().contains("under") && !VerificationCopy.notVerified.lowercased().contains("age"))
        // Out of attempts: a plain "nothing was shared".
        await api.setWalletOutcome(VerificationAttemptOutcome(status: .notVerified, label: nil, receiptId: nil, canRetry: false))
        await vm.verifyWithWallet()
        #expect(vm.resultText == VerificationCopy.notVerified)
    }

    @Test func decliningSharesNothingAndEndsTheRequest() async throws {
        let api = MockVerifyAPI()
        let prompt = VerificationPrompt.sampleAge()
        let vm = await model(prompt, api: api)
        await vm.load()
        var finished: VerificationAttemptOutcome?
        vm.onFinished = { finished = $0 }
        await vm.decline()
        #expect(await api.declined == [prompt.id])
        #expect(finished?.status == .declined)
        #expect(vm.resultText == VerificationCopy.declined)
        #expect(await api.consentLog.isEmpty)
    }

    @Test func aServerErrorOnTheDocumentPathIsAClearMessageNotAPartialResult() async throws {
        let api = MockVerifyAPI()
        let vm = await model(.sampleAge(), api: api)
        await vm.load()
        await vm.consent()
        await api.setFailure(APIError.server(status: 503, code: .unavailable, message: "down"))
        await vm.verifyWithDocument()
        #expect(vm.phase == .choosingMethod)
        #expect(vm.notice == VerificationCopy.documentUnavailableReason)
    }

    @Test func copyNeverOverclaims() {
        let all = [VerificationCopy.verifiedBusinessNote, VerificationCopy.identityNote, VerificationCopy.ageNote, VerificationCopy.localAuthNote, VerificationCopy.walletDetail,
                   VerificationCopy.documentDetail, VerificationCopy.alternativePath].joined(separator: " ").lowercased()
        for banned in ["guarantee of identity", "100%", "unhackable", "bank-grade", "certified", "nist", "ial2", "aal2", "fully secure", "military"] {
            // The notes may *deny* a guarantee, but never claim one.
            #expect(!all.replacingOccurrences(of: "not a universal guarantee", with: "").replacingOccurrences(of: "or guarantee of legitimacy", with: "").contains(banned) || banned == "guarantee of identity", banned)
        }
        #expect(VerificationCopy.localAuthNote.contains("does not prove your legal identity"))
        #expect(VerificationCopy.verifiedBusinessNote.contains("endorsement"))
        #expect(VerificationCopy.documentDetail.contains("Viadere does not receive or keep them"))
        #expect(VerificationLabel.estimatedAge.displayName.contains("not verified"))
    }
}

@MainActor
@Suite("Verification history")
struct VerificationHistoryTests {
    func item(_ status: ConsumerVerificationStatus, revocable: Bool = false, fields: [String] = [], label: VerificationLabel? = nil) -> VerificationHistoryItem {
        VerificationHistoryItem(id: VerificationRequestID(), recipientName: "Northwind Spirits", capability: .ageMinimum, purposeCode: "age_restricted_access", status: status,
                                requestedAt: Date(), decidedAt: Date(), receiptId: UUID(), revocable: revocable, disclosedFields: fields, label: label)
    }

    @Test func rowsNameTheStatusTheLabelAndWhatWasShared() {
        let shared = item(.released, fields: ["meets_threshold"], label: .verifiedAgeThreshold)
        #expect(VerificationHistoryViewModel.summary(shared) == "Shared · Verified age threshold · Shared: meets threshold")
        #expect(VerificationHistoryViewModel.summary(item(.declined)) == "Declined")
        #expect(VerificationHistoryViewModel.summary(item(.notVerified)) == "Not verified")
    }

    @Test func withdrawalWorksWhileConsentIsUnusedAndExplainsWhenItIsTooLate() async throws {
        let api = MockVerifyAPI()
        let waiting = item(.consented, revocable: true)
        let done = item(.released, fields: ["meets_threshold"], label: .verifiedAgeThreshold)
        await api.setHistory([waiting, done])
        let vm = VerificationHistoryViewModel(api: api)
        await vm.load()
        #expect(vm.items.count == 2)
        await vm.withdraw(waiting)
        #expect(vm.items.first { $0.id == waiting.id }?.status == .revoked)
        #expect(vm.errorMessage == nil)
        await vm.withdraw(done)   // not revocable: nothing is sent
        #expect(vm.items.first { $0.id == done.id }?.status == .released)
        var tooLate = done
        tooLate.revocable = true
        await vm.withdraw(tooLate)
        #expect(vm.errorMessage?.contains("already shared") == true)
    }

    @Test func pendingRequestsAreListedForTheInbox() async throws {
        let api = MockVerifyAPI()
        await api.add(.sampleAge())
        let vm = VerificationHistoryViewModel(api: api)
        await vm.load()
        #expect(vm.pending.count == 1)
    }
}

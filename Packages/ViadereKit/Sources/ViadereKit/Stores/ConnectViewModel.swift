import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class ConnectViewModel {
    public enum Phase: Equatable, Sendable {
        case entry
        case resolving
        /// Several verified matches for a name.
        case choose([BusinessSummary])
        /// A verified business and the purpose-scoped consent review.
        case review(BusinessProfile)
        case connecting
        case connected(Relationship)
        case failed(String)
    }

    public private(set) var input = ""
    public private(set) var state = ConnectInputState(kind: .empty, text: "", validation: .none, alsoCode: nil)
    public private(set) var suggestions: [BusinessSummary] = []
    public private(set) var phase: Phase = .entry
    public private(set) var scanError: String?
    /// Opt-in purposes chosen on the review screen. Security and account service are always on and not listed here.
    public var optIns: Set<InteractionPurpose> = []

    private var source: ConnectSource = .search
    private var link: ConnectLink?
    private let services: ViadereServices

    public init(services: ViadereServices) { self.services = services }

    // MARK: Input

    /// Call with every edit. Formats codes live (`AF-2345`, I→1, O→0) and classifies the input.
    public func setInput(_ raw: String) {
        state = ConnectInputClassifier.evaluate(raw)
        input = state.kind == .empty ? raw.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "" : raw : state.text
        if state.kind != .name { suggestions = [] }
        if case .failed = phase { phase = .entry }
    }

    /// Debounced by the view; refreshes name suggestions only.
    public func refreshSuggestions() async {
        guard state.kind == .name, state.canSubmit else { suggestions = []; return }
        let query = state.text.trimmingCharacters(in: .whitespaces)
        let results = (try? await services.api.searchDirectory(query: query)) ?? []
        // Ignore stale responses.
        if query == state.text.trimmingCharacters(in: .whitespaces) { suggestions = results.filter(\.isVerified) }
    }

    public func submit() async {
        guard state.canSubmit else { return }
        phase = .resolving
        do {
            switch state.kind {
            case .link:
                let parsed = try ConnectLink.parse(state.text)
                link = parsed
                source = .link
                try await loadProfile(code: parsed.code)
            case .handle:
                guard let handle = BusinessHandle(parsing: state.text) else { throw APIError.invalidRequest("handle") }
                source = .handle
                review(try await services.api.businessProfile(handle: handle))
            case .code:
                guard let code = BusinessCode(parsing: state.text) else { throw APIError.invalidRequest("code") }
                source = .code
                try await loadProfile(code: code)
            case .name:
                source = .search
                let response = try await services.api.resolve(input: state.text)
                switch response.matches.count {
                case 0: phase = .failed("No verified business matches that name.")
                case 1: if let only = response.matches.first { await select(only) }
                default: phase = .choose(response.matches)
                }
            case .empty:
                phase = .entry
            }
        } catch let error as APIError {
            phase = .failed(error.code == .notFound ? "We couldn't find a verified business for that." : error.userMessage)
        } catch {
            phase = .failed("That doesn't look like a Viadere code, handle or link.")
        }
    }

    /// Treat an all-letters entry as a business code.
    public func submitAsCode() async {
        guard let code = state.alsoCode else { return }
        phase = .resolving
        source = .code
        do { try await loadProfile(code: code) } catch let error as APIError {
            phase = .failed(error.code == .notFound ? "We couldn't find a verified business for that code." : error.userMessage)
        } catch { phase = .failed("We couldn't find that code.") }
    }

    public func select(_ business: BusinessSummary) async {
        guard business.isVerified else { phase = .failed("That business isn't verified."); return }
        phase = .resolving
        do { try await loadProfile(code: business.code) } catch let error as APIError { phase = .failed(error.userMessage) } catch { phase = .failed("Something went wrong.") }
    }

    private func loadProfile(code: BusinessCode) async throws {
        review(try await services.api.businessProfile(code: code))
    }

    private func review(_ profile: BusinessProfile) {
        guard profile.verificationStatus == .verified else {
            phase = .failed("That business isn't verified, so Viadere can't connect you.")
            return
        }
        optIns = []
        phase = .review(profile)
    }

    // MARK: Entry paths

    /// Universal link, QR code, NFC or App Clip invocation that already carries a code.
    public func open(code: BusinessCode, link: ConnectLink?, source: ConnectSource) async {
        self.link = link
        self.source = source
        setInput(code.display)
        phase = .resolving
        do { try await loadProfile(code: code) } catch let error as APIError {
            phase = .failed(error.code == .notFound ? "We couldn't find a verified business for that code." : error.userMessage)
        } catch { phase = .failed("Something went wrong.") }
    }

    /// Result of the camera QR scanner.
    public func handleScanned(_ payload: String) async {
        scanError = nil
        if case .connect(let code, let link)? = DeepLinkRouter.route(payload) {
            await open(code: code, link: link, source: .qr)
            return
        }
        // Plain handle or code printed in a QR.
        let evaluated = ConnectInputClassifier.evaluate(payload)
        if evaluated.canSubmit, evaluated.kind == .handle || evaluated.kind == .code {
            setInput(payload)
            source = .qr
            await submit()
            return
        }
        scanError = "That QR code isn't from Viadere."
    }

    // MARK: Connect

    public func toggleOptIn(_ purpose: InteractionPurpose) {
        guard !purpose.isGrantedByDefault else { return }
        if optIns.contains(purpose) { optIns.remove(purpose) } else { optIns.insert(purpose) }
    }

    public func connect() async {
        guard case .review(let profile) = phase else { return }
        phase = .connecting
        let request = ConnectRequest(businessId: profile.id, source: source, link: link?.urlString,
                                     optInPurposes: InteractionPurpose.allCases.filter { optIns.contains($0) })
        do {
            phase = .connected(try await services.api.connect(request))
        } catch let error as APIError {
            phase = .failed(error.userMessage)
        } catch {
            phase = .failed("Something went wrong.")
        }
    }

    public func reset() {
        input = ""
        state = ConnectInputState(kind: .empty, text: "", validation: .none, alsoCode: nil)
        suggestions = []
        phase = .entry
        link = nil
        optIns = []
        scanError = nil
    }

    public func backToEntry() {
        phase = .entry
        optIns = []
    }
}

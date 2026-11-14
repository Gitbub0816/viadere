import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

// The deliveries inbox (ADR-0020 §6, §8; FLOW_MATRIX "Inbox" column): sign-in links, one-time codes and security notices that wait for
// this account, shown in Alerts → Needs you. The Alerts read model (`AlertEntry`) does not carry deliveries, so this is its own small
// list, merged into the same screen. The push is only a hint; a delivery sent silently (over budget) shows only here.

/// One row of the inbox, as plain data. Every string is approved copy with the business name passed through `UntrustedText`.
public struct AuthDeliveryInboxRow: Sendable, Equatable, Identifiable {
    public var id: UUID
    public var kind: AuthDeliveryItem.Kind
    public var businessId: BusinessID
    /// The sanitized business name.
    public var business: String
    /// What it is (S-LINK-01 title, C-OTP-01 title, N-06, or INB-01 for a silent sign-in).
    public var line: String
    public var expiresAt: Date
    /// A link or a code opens its sheet; a notice has nothing to open.
    public var opens: Bool
    /// An SF Symbol name (never shield imagery).
    public var symbol: String
}

/// Which sheet a delivery opens.
public enum AuthDeliverySurface: Sendable, Equatable {
    case link
    case code
    /// A security notice (N-06): there is nothing to open; the sheet says who sent it. The name is already sanitized.
    case notice(business: String)
    /// An unknown delivery, or a failure to ask: there is nothing to open. The phase says what to tell the person.
    case none(LinkConfirmationViewModel.Phase)

    /// Asks the display object once (no secret, nothing consumed) and picks the sheet.
    public static func resolve(deliveryId: UUID, api: any AuthDeliveryAPI) async -> AuthDeliverySurface {
        do {
            let item = try await api.item(deliveryId: deliveryId)
            // An expired or used link or code still goes to its own sheet, which says so in its own words (S-LINK-06/07, C-OTP-02).
            switch item.kind {
            case .link: return .link
            case .code: return .code
            case .notice: return .notice(business: UntrustedText.name(item.business, max: 40, attribution: nil).text)
            }
        } catch let error as AuthDeliveryError {
            switch error {
            case .offline: return .none(.offline)
            case .expired: return .none(.expired)
            default: return .none(.gone)
            }
        } catch { return .none(.gone) }
    }

    /// The line for `.notice` (N-06) and `.none` (E-02, E-03).
    public var message: String? {
        switch self {
        case .link, .code: return nil
        case .notice(let business): return AuthDeliveryCopy.n06Body(business: business)
        case .none(.offline): return AuthDeliveryCopy.offline
        case .none: return AuthDeliveryCopy.noLongerActive
        }
    }
}

@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class AuthDeliveryInboxViewModel {
    /// The last refresh failed for lack of a connection: what was loaded stays visible, nothing can be opened.
    public private(set) var isOffline = false
    public private(set) var hasLoaded = false

    public static let limit = 50
    private var items: [AuthDeliveryItem] = []
    private let api: any AuthDeliveryAPI
    private let clock: @Sendable () -> Date

    public init(api: any AuthDeliveryAPI, clock: @escaping @Sendable () -> Date = { Date() }, initial: [AuthDeliveryItem] = []) {
        self.api = api
        self.clock = clock
        items = initial
    }

    /// The server's list replaces the cache. Offline keeps what was loaded; any other failure (no session, no client, an unreadable
    /// answer) empties it, so nothing stale from another state of the account stays on screen.
    public func refresh() async {
        do {
            items = Array(try await api.deliveries().prefix(Self.limit))
            isOffline = false
            hasLoaded = true
        } catch let error as AuthDeliveryError where error == .offline {
            isOffline = true
        } catch {
            items = []
            isOffline = false
        }
    }

    /// What waits now: open by the server's word **and** unexpired by the device clock, newest first. `business` narrows to one business
    /// (the Alerts context); `nil` is every business.
    public func pending(business: BusinessID? = nil) -> [AuthDeliveryItem] {
        let now = clock()
        return items.filter { $0.state == .open && $0.expiresAt > now && (business == nil || $0.businessId == business) }
            .sorted { $0.createdAt != $1.createdAt ? $0.createdAt > $1.createdAt : $0.deliveryId.uuidString < $1.deliveryId.uuidString }
    }

    public func rows(business: BusinessID? = nil) -> [AuthDeliveryInboxRow] { pending(business: business).map(Self.row) }

    /// How many links and codes wait (notices ask for nothing). Used for the Home Screen widget's count.
    public func waitingExpiries() -> [Date] { pending().filter { $0.kind != .notice }.map(\.expiresAt) }

    /// Whether a row may open its sheet now: never offline, never a notice, never past its expiry.
    public func canOpen(_ row: AuthDeliveryInboxRow) -> Bool { !isOffline && row.opens && row.expiresAt > clock() }

    /// A sheet finished with this delivery (opened, reported, expired): it leaves the list at once; the next refresh confirms it.
    public func markHandled(_ id: UUID) { items.removeAll { $0.deliveryId == id } }

    /// Sign-out: nothing survives.
    public func reset() {
        items = []
        isOffline = false
        hasLoaded = false
    }

    static func row(_ item: AuthDeliveryItem) -> AuthDeliveryInboxRow {
        let business = UntrustedText.name(item.business, max: 40, attribution: nil).text
        let line: String
        let symbol: String
        switch item.kind {
        case .link:
            line = item.silent && item.purpose == .signIn ? AuthDeliveryCopy.silentPendingSignIn(business: business) : AuthDeliveryCopy.linkTitle(business: business)
            symbol = "link"
        case .code:
            line = AuthDeliveryCopy.codeTitle(business: business)
            symbol = "number"
        case .notice:
            line = AuthDeliveryCopy.n06Body(business: business)
            symbol = "bell"
        }
        return AuthDeliveryInboxRow(id: item.deliveryId, kind: item.kind, businessId: item.businessId, business: business, line: line,
                                    expiresAt: item.expiresAt, opens: item.kind != .notice, symbol: symbol)
    }
}

/// What the notification service extension shows for an `adl` push once it fetched the display object (UX_COPY §1 N-02, N-05, N-06), and
/// what it shows when it could not (N-08). Never a code, a URL, a host, an amount or a template variable (ST-PRIV-02, UX_COPY §0 rule 5).
public struct AuthDeliveryNotificationText: Sendable, Equatable {
    public var title: String
    public var body: String

    /// N-08: the fetch failed, the phone was never unlocked since restart, or the answer did not match the push.
    public static let generic = AuthDeliveryNotificationText(title: AuthDeliveryCopy.n01Title, body: AuthDeliveryCopy.n08Body)

    /// - Parameters:
    ///   - item: the fetched display object.
    ///   - category: the category the push arrived with. The fetched method must be the one the category names; a mismatch is generic.
    ///   - now: the device clock. A delivery that is no longer open or already expired is generic (never a stale business name).
    public static func make(item: AuthDeliveryItem, category: String, now: Date) -> AuthDeliveryNotificationText {
        guard item.state == .open, item.expiresAt > now else { return .generic }
        let name = UntrustedText.name(item.business, max: 40, attribution: nil)
        // A name that imitates Viadere never becomes a notification title.
        guard !name.impersonatesViadere, name.text != "Unnamed business" else { return .generic }
        switch item.kind {
        case .link where category == AuthNotificationCategory.link:
            return AuthDeliveryNotificationText(title: name.text, body: AuthDeliveryCopy.n02Body(business: name.text))
        case .code where category == AuthNotificationCategory.code:
            return AuthDeliveryNotificationText(title: name.text, body: AuthDeliveryCopy.n05Body(business: name.text))
        case .notice where category == AuthNotificationCategory.notice:
            return AuthDeliveryNotificationText(title: name.text, body: AuthDeliveryCopy.n06Body(business: name.text))
        default:
            return .generic
        }
    }

    /// The delivery id of an auth-delivery push, or `nil` when the push is not one (wrong category, no or malformed `adl`).
    public static func deliveryId(category: String, userInfo: [AnyHashable: Any]) -> UUID? {
        guard AuthPushPayloadPolicy.allowedCategories.contains(category) else { return nil }
        return PushPayload.deliveryId(from: PushPayload.stringify(userInfo))
    }
}

import Foundation

/// The consumer Organization API (WP-1.1, WP-1.5, WP-1.6; SECURITY.md §2.96). Every route is device-signed; the tenant is always the
/// authenticated account, and a `business_id` / `{businessId}` is only ever a **filter** the server checks against the caller's own
/// connections (`404` for anything else, so it is never an existence oracle).
extension APIRoutes {
    /// Query: `status` (`pending|completed|expired`), `unread=1`, `business_id`, `cursor`, `since`, `limit` (≤ 50). See `AlertQuery`.
    public static let alertsList = Endpoint<EmptyBody, AlertPage>(
        "alerts.list", .GET, "/v1/alerts", auth: .deviceSignedBearer)
    /// Marks alerts seen for this account (≤ 100 ids). Idempotent; ids the caller cannot see are ignored.
    public static let alertsSeen = Endpoint<AlertSeenRequest, EmptyBody>(
        "alerts.seen", .POST, "/v1/alerts/seen", auth: .deviceSignedBearer)
    /// Query: `filter` (`available|saved|redeemed|expired|eligible`), `business_id`.
    public static let benefitsList = Endpoint<EmptyBody, RewardsOverview>(
        "benefits.list", .GET, "/v1/benefits", auth: .deviceSignedBearer)
    /// The Businesses directory: the caller's connections (active and ended, never pending link confirmations) with their preferences.
    public static let businessesList = Endpoint<EmptyBody, [ConnectedBusiness]>(
        "businesses.list", .GET, "/v1/businesses", auth: .deviceSignedBearer)
    public static let businessPreferencesGet = Endpoint<EmptyBody, BusinessPreferences>(
        "businesses.preferences.get", .GET, "/v1/businesses/{businessId}/preferences", auth: .deviceSignedBearer)
    /// Blocking ends the connection (the normal disconnect: pending requests cancelled, approval keys revoked, the business told) and refuses
    /// new connections and link sessions from the business until unblocked.
    public static let businessPreferencesPut = Endpoint<BusinessPreferencesUpdate, BusinessPreferences>(
        "businesses.preferences.put", .PUT, "/v1/businesses/{businessId}/preferences", auth: .deviceSignedBearer)
    /// The neutral business home: the published module layout (or Viadere's default). Active connections only.
    public static let businessSurfaceGet = Endpoint<EmptyBody, BusinessSurfaceView>(
        "businesses.surface.get", .GET, "/v1/businesses/{businessId}/surface", auth: .deviceSignedBearer)
    public static let conversationStatePut = Endpoint<ConversationStateUpdate, ConversationStateView>(
        "conversations.state.put", .PUT, "/v1/conversations/{sessionId}/state", auth: .deviceSignedBearer)

    /// Appended to `APIRoutes.all`.
    public static let organizationEndpoints: [AnyEndpoint] = [
        alertsList.descriptor, alertsSeen.descriptor, benefitsList.descriptor, businessesList.descriptor, businessPreferencesGet.descriptor,
        businessPreferencesPut.descriptor, businessSurfaceGet.descriptor, conversationStatePut.descriptor,
    ]
}

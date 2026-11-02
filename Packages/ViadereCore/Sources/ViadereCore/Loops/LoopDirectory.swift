import Foundation

// MARK: - Installable Loops: directory, installs and declared permissions (SECURITY.md §2.98 "Installed Loops").
//
// A customer **adds** a Loop (like a plugin) from the in-app directory, a business page or a shared install link, whether or not they are
// connected to the business. At install the customer chooses:
//
// * **Install only** (`install_only`): the Loop is added; the business receives only what the Loop's reviewed definition sends (the
//   customer's answers to its fields, in the hosted inbox, with no customer identity). No relationship is created: no messaging, no
//   `subjectRef`, no profile, no webhooks.
// * **Install and connect** (`install_and_connect`): also creates the normal connection, exactly as Connect does today.
//
// Directory metadata comes from reviewed data only: the name and short description are the reviewed definition's `title` and `description`
// (published, hence human-reviewed and signed); category, listing and "featured" are set by a Viadere operator holding `loop_reviewer`; the
// icon is the business's approved Brand Kit logo or mark, read from its signed brand manifest on the device.

/// Directory categories (closed list chosen by Viadere; unknown values from a newer server decode and show as "Other").
public struct LoopDirectoryCategory: RawRepresentable, Hashable, Sendable, Codable {
    public let rawValue: String
    public init(rawValue: String) { self.rawValue = rawValue }

    public static let foodAndDrink = LoopDirectoryCategory(rawValue: "food_and_drink")
    public static let shopping = LoopDirectoryCategory(rawValue: "shopping")
    public static let appointments = LoopDirectoryCategory(rawValue: "appointments")
    public static let services = LoopDirectoryCategory(rawValue: "services")
    public static let travel = LoopDirectoryCategory(rawValue: "travel")
    public static let homeAndAuto = LoopDirectoryCategory(rawValue: "home_and_auto")
    public static let beauty = LoopDirectoryCategory(rawValue: "beauty")
    public static let entertainment = LoopDirectoryCategory(rawValue: "entertainment")
    public static let other = LoopDirectoryCategory(rawValue: "other")

    /// In display order. There is deliberately no health category (FX-4: Loops are refused for health).
    public static let known: [LoopDirectoryCategory] = [.foodAndDrink, .shopping, .appointments, .services, .travel, .homeAndAuto, .beauty, .entertainment, .other]

    public var isKnown: Bool { Self.known.contains(self) }

    /// Viadere's own label (never business text).
    public var title: String {
        switch self {
        case .foodAndDrink: "Food and drink"
        case .shopping: "Shopping"
        case .appointments: "Appointments"
        case .services: "Services"
        case .travel: "Travel"
        case .homeAndAuto: "Home and auto"
        case .beauty: "Beauty"
        case .entertainment: "Entertainment"
        default: "Other"
        }
    }

    /// SF Symbol (no shield imagery).
    public var symbol: String {
        switch self {
        case .foodAndDrink: "fork.knife"
        case .shopping: "bag"
        case .appointments: "calendar"
        case .services: "wrench.and.screwdriver"
        case .travel: "airplane"
        case .homeAndAuto: "house"
        case .beauty: "scissors"
        case .entertainment: "ticket"
        default: "square.grid.2x2"
        }
    }
}

/// What the customer chose on the install sheet.
public enum LoopInstallMode: String, Sendable, Codable, CaseIterable, Hashable {
    /// The Loop only. No relationship, no messaging; the business sees only what the Loop sends.
    case installOnly = "install_only"
    /// The Loop and the normal connection (as Connect).
    case installAndConnect = "install_and_connect"
}

/// Where the install started (audit and the connection's `ConnectSource` for `install_and_connect`).
public enum LoopInstallSource: String, Sendable, Codable, CaseIterable, Hashable {
    case directory
    case businessPage = "business_page"
    case link

    /// The connection source recorded when the customer also connects.
    public var connectSource: ConnectSource {
        switch self {
        case .directory, .businessPage: .search
        case .link: .link
        }
    }
}

// MARK: - Declared permissions

/// One line of the plugin-style permission list on the install sheet, derived **only** from the reviewed definition (never from business
/// text describing itself) and from the customer's install choice. The words are Viadere's.
public struct LoopPermissionItem: Sendable, Hashable, Identifiable {
    public enum Kind: String, Sendable, Hashable, CaseIterable {
        /// The Loop sends the customer's answers to the business (`fields` lists the field labels).
        case sendsAnswers = "sends_answers"
        /// The Loop sends nothing to the business.
        case sendsNothing = "sends_nothing"
        /// The customer is told when the business answers (opaque notification, details in the app).
        case outcomeUpdates = "outcome_updates"
        /// No access to name, phone, email, profile or location.
        case noProfile = "no_profile"
        /// Install only: no connection, the business cannot message the customer.
        case noMessaging = "no_messaging"
        /// Install and connect: the normal connection (messages as set in the connection's settings).
        case connection
        /// Each request ends after the reviewed limit.
        case expires
    }

    public var kind: Kind
    public var title: String
    public var detail: String?
    /// Field labels (sanitized business text) for `sendsAnswers`.
    public var fields: [String]

    public var id: String { kind.rawValue }

    /// SF Symbol (no shield imagery).
    public var symbol: String {
        switch kind {
        case .sendsAnswers: "arrow.up.doc"
        case .sendsNothing: "nosign"
        case .outcomeUpdates: "bell"
        case .noProfile: "person.crop.circle.badge.xmark"
        case .noMessaging: "bubble.left.and.exclamationmark.bubble.right"
        case .connection: "link"
        case .expires: "clock"
        }
    }

    public init(kind: Kind, title: String, detail: String? = nil, fields: [String] = []) {
        self.kind = kind
        self.title = title
        self.detail = detail
        self.fields = fields
    }
}

public enum LoopPermissions {
    /// Whether any action of the definition delivers to the business (a registered delivering action with hosted routing).
    public static func delivers(_ definition: LoopDefinition, registry: LoopActionRegistry = .v1) -> Bool {
        definition.steps.contains { step in
            step.actions.contains { binding in
                guard binding.routing != nil, case .registered(let action) = registry.resolve(binding.action) else { return false }
                return action.deliversToBusiness
            }
        }
    }

    /// Every field label the customer may be asked for. The hosted inbox shows the answers of **every** event of an instance once something
    /// was delivered, so every field counts (not only those on the delivering step). Sanitized, de-duplicated, in reading order.
    public static func fieldLabels(_ definition: LoopDefinition) -> [String] {
        var seen = Set<String>()
        var out: [String] = []
        for step in definition.steps {
            for field in step.fields where field.type != .acknowledgement {
                let label = DisplayTextSanitizer.sanitize(field.label, maxCharacters: LoopLimits.fieldLabelLength)
                guard !label.isEmpty, seen.insert(label.lowercased()).inserted else { continue }
                out.append(label)
            }
        }
        return out
    }

    /// The permission list. `business` is the verified display name; `connected` is the customer's choice (or current state).
    public static func derive(_ definition: LoopDefinition, business: String, connected: Bool, registry: LoopActionRegistry = .v1) -> [LoopPermissionItem] {
        var items: [LoopPermissionItem] = []
        let name = business.isEmpty ? "the business" : business
        if delivers(definition, registry: registry) {
            let labels = fieldLabels(definition)
            items.append(LoopPermissionItem(kind: .sendsAnswers, title: "Sends \(name) what you enter",
                                            detail: labels.isEmpty ? "Only that you sent the request." : "Only when you tap send.",
                                            fields: labels))
            items.append(LoopPermissionItem(kind: .outcomeUpdates, title: "Tells you when \(name) answers",
                                            detail: "The notification says only that there's an update; details stay in the app."))
        } else {
            items.append(LoopPermissionItem(kind: .sendsNothing, title: "Sends nothing to \(name)"))
        }
        items.append(LoopPermissionItem(kind: .noProfile, title: "Can't see your name, phone number, email or profile",
                                        detail: "Unless you type it into an answer yourself."))
        if connected {
            items.append(LoopPermissionItem(kind: .connection, title: "Connects you to \(name)",
                                            detail: "\(name) can send you messages and requests as your connection settings allow. You can disconnect at any time."))
        } else {
            items.append(LoopPermissionItem(kind: .noMessaging, title: "\(name) can't message you",
                                            detail: "You aren't connected. It only sees requests you send with this Loop."))
        }
        items.append(LoopPermissionItem(kind: .expires, title: "Each request ends after \(duration(definition.limits.expiresInSeconds))"))
        return items
    }

    /// "2 hours", "3 days", "1 day".
    public static func duration(_ seconds: Int64) -> String {
        let hours = max(1, (seconds + 3599) / 3600)
        if hours < 48 { return hours == 1 ? "1 hour" : "\(hours) hours" }
        let days = (hours + 23) / 24
        return days == 1 ? "1 day" : "\(days) days"
    }
}

// MARK: - Install link

/// `https://{link domain}/lp/{loopId}`: a business shares it (or its QR code) so customers can add the Loop. The id is the stable Loop
/// (definition) id; the link carries nothing else (no query, no fragment) and grants nothing: opening it shows the install sheet.
public struct LoopInstallLink: Sendable, Hashable {
    public var loopId: LoopDefinitionID

    public init(loopId: LoopDefinitionID) { self.loopId = loopId }

    public func url(domain: LinkDomain = .current) -> URL? { domain.url(APIRoutes.Web.loopInstallPrefix + loopId.description) }

    /// Strict parse: https, the exact link domain or its `www.` alias, port 443 or none, no user info, no query, no fragment, exactly
    /// `/lp/{uuid}` (an optional trailing slash).
    public static func parse(_ url: URL, domain: LinkDomain = .current) -> LoopInstallLink? {
        guard url.scheme?.lowercased() == "https",
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false), let host = components.host?.lowercased(),
              domain.connectHosts.contains(host), components.user == nil, components.password == nil,
              components.port == nil || components.port == 443, components.query == nil, components.fragment == nil else { return nil }
        return parse(path: components.percentEncodedPath)
    }

    /// The path form (`/lp/{uuid}`), shared by the custom scheme parser.
    public static func parse(path: String) -> LoopInstallLink? {
        guard path.hasPrefix(APIRoutes.Web.loopInstallPrefix) else { return nil }
        var rest = Substring(path.dropFirst(APIRoutes.Web.loopInstallPrefix.count))
        if rest.hasSuffix("/") { rest = rest.dropLast() }
        guard rest.count == 36, !rest.contains("/"), let id = LoopDefinitionID(String(rest)) else { return nil }
        return LoopInstallLink(loopId: id)
    }
}

extension APIRoutes.Web {
    /// Loop install link: `/lp/{loopId}` (`LoopInstallLink`).
    public static let loopInstallPrefix = "/lp/"
}

// MARK: - DTOs

/// One Loop in the directory (`GET /v1/loops/directory`) or on a business page. Only active, reviewed publications the caller may see
/// (rollout, business verified, category allowed, switches off, not blocked by the caller).
public struct LoopDirectoryEntry: Codable, Sendable, Hashable, Identifiable {
    /// The stable Loop id (definition id): what an install refers to, across revisions.
    public var loopId: LoopDefinitionID
    /// The current active publication (what would start).
    public var publicationId: LoopPublicationID
    public var revision: Int64
    /// The verified directory record of the business (shown as "Built by {name}").
    public var business: BusinessSummary
    /// The business's verified category (for `VerifiedBusinessRecord`).
    public var businessCategory: BusinessCategory
    /// The reviewed definition's title (sanitized). Shown under the verified attribution, never instead of it.
    public var title: String
    /// The reviewed definition's description (sanitized), if it has one.
    public var summary: String?
    /// Set by a Viadere operator; `nil` = not listed in a category.
    public var category: LoopDirectoryCategory?
    public var featured: Bool
    public var entryPoints: [LoopEntryPoint]
    /// The caller has this Loop installed.
    public var installed: Bool
    /// The caller has an active connection with the business.
    public var connected: Bool
    /// The Brand Kit the reviewed definition names (`appearance: brand_kit`), for the icon; the device reads the kit from the business's
    /// signed brand manifest only.
    public var brandKitId: String?

    public var id: LoopDefinitionID { loopId }

    public init(loopId: LoopDefinitionID, publicationId: LoopPublicationID, revision: Int64, business: BusinessSummary, businessCategory: BusinessCategory,
                title: String, summary: String?, category: LoopDirectoryCategory?, featured: Bool, entryPoints: [LoopEntryPoint], installed: Bool,
                connected: Bool, brandKitId: String?) {
        self.loopId = loopId
        self.publicationId = publicationId
        self.revision = revision
        self.business = business
        self.businessCategory = businessCategory
        self.title = title
        self.summary = summary
        self.category = category
        self.featured = featured
        self.entryPoints = entryPoints
        self.installed = installed
        self.connected = connected
        self.brandKitId = brandKitId
    }
}

/// `GET /v1/loops/directory`. Query: `q` (search in titles, descriptions and business names, at most 60 characters), `category`,
/// `business_id` (a business page: every Loop of that business, listed or not).
public struct LoopDirectoryPage: Codable, Sendable, Hashable {
    /// Operator-featured entries (empty when a query, category or business filter is given).
    public var featured: [LoopDirectoryEntry]
    public var entries: [LoopDirectoryEntry]
    /// Categories that have at least one listed entry, in `LoopDirectoryCategory.known` order.
    public var categories: [LoopDirectoryCategory]

    public init(featured: [LoopDirectoryEntry], entries: [LoopDirectoryEntry], categories: [LoopDirectoryCategory]) {
        self.featured = featured
        self.entries = entries
        self.categories = categories
    }
}

/// `GET /v1/loops/directory/{loopId}`: the entry plus the signed manifest and the reviewed definition, so the device verifies the
/// publication itself (pinned `loop-publication` keys, `definition_hash`) and derives the permission list from exactly what was reviewed.
public struct LoopDirectoryDetail: Codable, Sendable, Hashable {
    public var entry: LoopDirectoryEntry
    /// Compact JWS (`viadere-loop-publication+jws`, §2.92).
    public var manifest: String
    /// The definition in canonical form.
    public var definition: JSONValue

    public init(entry: LoopDirectoryEntry, manifest: String, definition: JSONValue) {
        self.entry = entry
        self.manifest = manifest
        self.definition = definition
    }
}

/// `PUT /v1/loops/installed/{loopId}`. The install sheet is also the per-business Loop authorization (`LoopConsentText.businessAuthorization`
/// with the verified name), so it echoes the text version and digest the customer saw and `agree: true`. Requires the current global grant.
public struct LoopInstallRequest: Codable, Sendable, Hashable {
    public var mode: LoopInstallMode
    public var source: LoopInstallSource
    public var textVersion: Int
    public var textDigest: String
    public var agree: Bool

    public init(mode: LoopInstallMode, source: LoopInstallSource, textVersion: Int, textDigest: String, agree: Bool) {
        self.mode = mode
        self.source = source
        self.textVersion = textVersion
        self.textDigest = textDigest
        self.agree = agree
    }
}

/// One installed Loop (`GET /v1/loops/installed`, Your Loops and Settings).
public struct InstalledLoop: Codable, Sendable, Hashable, Identifiable {
    public var loopId: LoopDefinitionID
    public var business: BusinessSummary
    public var businessCategory: BusinessCategory
    /// The reviewed title of the current publication (or of the last one, when none is active now).
    public var title: String
    public var mode: LoopInstallMode
    public var source: LoopInstallSource
    public var installedAt: Date
    /// The caller has an active connection with the business now.
    public var connected: Bool
    /// The current active publication the caller may start, or `nil` (paused, suspended, retired without successor, outside the rollout).
    public var publicationId: LoopPublicationID?
    /// Whether the Loop can be started from Your Loops (`business_page` entry point).
    public var entryPoints: [LoopEntryPoint]
    /// Open (active or submitted) instances, newest first, so Your Loops can resume them.
    public var openInstances: [LoopInstanceID]
    public var brandKitId: String?

    public var id: LoopDefinitionID { loopId }
    public var isStartable: Bool { publicationId != nil && entryPoints.contains(.businessPage) }

    public init(loopId: LoopDefinitionID, business: BusinessSummary, businessCategory: BusinessCategory, title: String, mode: LoopInstallMode,
                source: LoopInstallSource, installedAt: Date, connected: Bool, publicationId: LoopPublicationID?, entryPoints: [LoopEntryPoint],
                openInstances: [LoopInstanceID], brandKitId: String?) {
        self.loopId = loopId
        self.business = business
        self.businessCategory = businessCategory
        self.title = title
        self.mode = mode
        self.source = source
        self.installedAt = installedAt
        self.connected = connected
        self.publicationId = publicationId
        self.entryPoints = entryPoints
        self.openInstances = openInstances
        self.brandKitId = brandKitId
    }
}

/// The answer to install: the installed Loop and the consent status (the install recorded the business authorization).
public struct LoopInstallResult: Codable, Sendable, Hashable {
    public var installed: InstalledLoop
    public var consent: LoopConsentStatus

    public init(installed: InstalledLoop, consent: LoopConsentStatus) {
        self.installed = installed
        self.consent = consent
    }
}

extension APIRoutes {
    /// Browse and search. Device-signed like every Loop route (the rollout and blocks are per account).
    public static let loopDirectory = Endpoint<EmptyBody, LoopDirectoryPage>(
        "loops.directory", .GET, "/v1/loops/directory", auth: .deviceSignedBearer)
    /// One Loop with its manifest and reviewed definition. `404` for anything the caller may not see.
    public static let loopDirectoryDetail = Endpoint<EmptyBody, LoopDirectoryDetail>(
        "loops.directory.get", .GET, "/v1/loops/directory/{loopId}", auth: .deviceSignedBearer)
    public static let loopsInstalled = Endpoint<EmptyBody, [InstalledLoop]>(
        "loops.installed.list", .GET, "/v1/loops/installed", auth: .deviceSignedBearer)
    /// Install (idempotent; a second call can upgrade `install_only` to `install_and_connect`). `409` without the current global grant or
    /// for a blocked business; `422` for a stale text or `agree != true`; `429` over the rate or the per-account cap.
    public static let loopInstall = Endpoint<LoopInstallRequest, LoopInstallResult>(
        "loops.installed.put", .PUT, "/v1/loops/installed/{loopId}", auth: .deviceSignedBearer)
    /// Uninstall: cancels the caller's open instances of that Loop; the connection (if any) is untouched. Returns the remaining list.
    public static let loopUninstall = Endpoint<EmptyBody, [InstalledLoop]>(
        "loops.installed.delete", .DELETE, "/v1/loops/installed/{loopId}", auth: .deviceSignedBearer)

    /// Appended to `APIRoutes.all`.
    public static let loopInstallEndpoints: [AnyEndpoint] = [
        loopDirectory.descriptor, loopDirectoryDetail.descriptor, loopsInstalled.descriptor, loopInstall.descriptor, loopUninstall.descriptor,
    ]
}

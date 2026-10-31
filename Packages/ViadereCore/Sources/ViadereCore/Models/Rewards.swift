import Foundation

/// Apple Wallet pass style.
public enum WalletPassKind: String, Codable, Sendable, CaseIterable {
    case storeCard, coupon, eventTicket, boardingPass, generic
}

/// Metadata about an issued Wallet pass. The `.pkpass` bundle itself is fetched from
/// `APIRoutes.walletPass`.
public struct WalletPassMetadata: Codable, Sendable, Hashable, Identifiable {
    public var id: WalletPassID
    public var businessId: BusinessID
    public var kind: WalletPassKind
    public var passTypeIdentifier: String
    public var serialNumber: String
    public var updatedAt: Date
    public var voided: Bool
    /// The pass's presentation code (`WalletScanCode`), for showing the same QR in the app. Present only in the holder's own
    /// responses for a pass that is still valid; never sent to a business.
    public var scanCode: String?
    /// When the ticket or reservation was checked in, if it was.
    public var usedAt: Date?

    public init(id: WalletPassID, businessId: BusinessID, kind: WalletPassKind, passTypeIdentifier: String,
                serialNumber: String, updatedAt: Date, voided: Bool = false, scanCode: String? = nil, usedAt: Date? = nil) {
        self.scanCode = scanCode
        self.usedAt = usedAt
        self.id = id
        self.businessId = businessId
        self.kind = kind
        self.passTypeIdentifier = passTypeIdentifier
        self.serialNumber = serialNumber
        self.updatedAt = updatedAt
        self.voided = voided
    }
}

/// Recurring eligibility, e.g. "a free coffee on Tuesdays". Enforced by the backend.
public struct RewardRecurrence: Codable, Sendable, Hashable {
    /// ISO weekdays 1 (Mon) … 7 (Sun) on which the reward may be redeemed.
    public var weekdays: [Int]
    /// Max redemptions per eligible day.
    public var perDayLimit: Int
    /// IANA time zone used to evaluate weekdays (business location).
    public var timeZone: String

    public init(weekdays: [Int], perDayLimit: Int = 1, timeZone: String) {
        self.weekdays = weekdays
        self.perDayLimit = perDayLimit
        self.timeZone = timeZone
    }

    /// Whether `date` falls on an eligible weekday in `timeZone`.
    public func isEligible(on date: Date) -> Bool {
        var calendar = Calendar(identifier: .iso8601)
        guard let zone = TimeZone(identifier: timeZone) else { return false }
        calendar.timeZone = zone
        // Calendar weekday: 1 = Sunday … 7 = Saturday → ISO 1 = Monday … 7 = Sunday.
        let weekday = calendar.component(.weekday, from: date)
        let iso = weekday == 1 ? 7 : weekday - 1
        return weekdays.contains(iso)
    }
}

/// A loyalty reward / offer / perk.
public struct Reward: Codable, Sendable, Hashable, Identifiable {
    public enum Status: String, Codable, Sendable { case available, redeemed, expired, revoked }

    public var id: RewardID
    public var business: BusinessSummary
    public var title: String
    public var details: String?
    public var status: Status
    public var validFrom: Date?
    public var validUntil: Date?
    public var recurrence: RewardRecurrence?
    public var redeemedAt: Date?
    public var walletPass: WalletPassMetadata?

    public init(id: RewardID, business: BusinessSummary, title: String, details: String? = nil, status: Status,
                validFrom: Date? = nil, validUntil: Date? = nil, recurrence: RewardRecurrence? = nil,
                redeemedAt: Date? = nil, walletPass: WalletPassMetadata? = nil) {
        self.id = id
        self.business = business
        self.title = title
        self.details = details
        self.status = status
        self.validFrom = validFrom
        self.validUntil = validUntil
        self.recurrence = recurrence
        self.redeemedAt = redeemedAt
        self.walletPass = walletPass
    }

    /// Client-side hint only; the server is authoritative for eligibility and redemption.
    public func isRedeemable(at now: Date) -> Bool {
        guard status == .available else { return false }
        if let validFrom, now < validFrom { return false }
        if let validUntil, now >= validUntil { return false }
        if let recurrence, !recurrence.isEligible(on: now) { return false }
        return true
    }
}

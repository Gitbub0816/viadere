import Foundation

// MARK: - Wallet pass presentation code and the business Wallet API

/// The code in a Wallet pass's QR (and in the app's pass detail): `VQ1.` + base64url(passId[16] ‖ generation[4, big-endian] ‖ tag[16]),
/// 52 characters. The tag is an HMAC the server keys and checks; nobody else can mint or alter a code. It is a **presentation**
/// code: it says which pass is shown, never who the holder is, and the business learns anything only by sending it to
/// `POST /v1/business/wallet/scan`, where the server enforces tenant, validity window and single use (SECURITY.md §2.14).
public enum WalletScanCode {
    public static let prefix = "VQ1."
    public static let payloadByteCount = 16 + 4
    public static let tagByteCount = 16
    /// Exact length of a well-formed code: the prefix plus 48 base64url characters (36 bytes, no padding).
    public static let length = prefix.count + 48

    /// Syntactic check only (the server alone can tell a genuine code). Used to refuse obvious garbage before a network call.
    public static func isWellFormed(_ raw: String) -> Bool {
        let code = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard code.count == length, code.hasPrefix(prefix) else { return false }
        return code.dropFirst(prefix.count).allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") }
    }
}

/// `POST /v1/business/wallet/passes`: issue (or return the existing) pass for a connected customer. Live keys only.
/// `storeCard` needs the customer's loyalty membership, `coupon` a reward they can see, `eventTicket`/`generic` a ticket interaction
/// the business sent them (`generic` is the reservation/appointment style). The customer adds it to Wallet from the app; the business
/// never receives the `.pkpass` or anything that would let it add the pass for them.
public struct BusinessIssueWalletPassRequest: Codable, Sendable, Hashable {
    public var relationshipId: RelationshipID?
    public var subjectRef: SubjectRef?
    public var kind: WalletPassKind
    public var rewardId: RewardID?
    public var interactionId: InteractionID?

    public init(relationshipId: RelationshipID? = nil, subjectRef: SubjectRef? = nil, kind: WalletPassKind, rewardId: RewardID? = nil,
                interactionId: InteractionID? = nil) {
        self.relationshipId = relationshipId
        self.subjectRef = subjectRef
        self.kind = kind
        self.rewardId = rewardId
        self.interactionId = interactionId
    }
}

/// A pass as the issuing business sees it. Deliberately says nothing about whether, or on which devices, the customer added it to
/// Wallet: that is the customer's business.
public struct BusinessWalletPass: Codable, Sendable, Hashable, Identifiable {
    public enum Issuer: String, Codable, Sendable { case customer, business }

    public var id: WalletPassID
    public var kind: WalletPassKind
    public var relationshipId: RelationshipID?
    public var subjectRef: SubjectRef?
    public var rewardId: RewardID?
    public var interactionId: InteractionID?
    public var issuedBy: Issuer
    public var voided: Bool
    /// First successful check-in (tickets, reservations).
    public var usedAt: Date?
    public var createdAt: Date
    public var updatedAt: Date

    public init(id: WalletPassID, kind: WalletPassKind, relationshipId: RelationshipID? = nil, subjectRef: SubjectRef? = nil,
                rewardId: RewardID? = nil, interactionId: InteractionID? = nil, issuedBy: Issuer, voided: Bool, usedAt: Date? = nil,
                createdAt: Date, updatedAt: Date) {
        self.id = id
        self.kind = kind
        self.relationshipId = relationshipId
        self.subjectRef = subjectRef
        self.rewardId = rewardId
        self.interactionId = interactionId
        self.issuedBy = issuedBy
        self.voided = voided
        self.usedAt = usedAt
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }
}

/// `PATCH /v1/business/wallet/passes/{passId}`: a schedule or venue change on a ticket/reservation pass, or a fresh presentation code.
/// Every change is pushed to the customer's devices. These are operational updates, not a marketing channel: only the fields below
/// exist, they are length-limited, and a pass accepts a few updates per day.
public struct UpdateWalletPassRequest: Codable, Sendable, Hashable {
    /// ≤ 80 characters. Tickets and reservations only.
    public var venue: String?
    /// Seat, table, room or gate, ≤ 80 characters. Tickets and reservations only.
    public var seat: String?
    /// New start time. Tickets and reservations only.
    public var startsAt: Date?
    /// Invalidates the code currently in the pass (a photographed or shared QR stops working) and pushes a new one.
    public var rotateScanCode: Bool?

    public init(venue: String? = nil, seat: String? = nil, startsAt: Date? = nil, rotateScanCode: Bool? = nil) {
        self.venue = venue
        self.seat = seat
        self.startsAt = startsAt
        self.rotateScanCode = rotateScanCode
    }
}

/// `POST /v1/business/wallet/scan`: the till or door scanned a pass. What happens depends on the pass:
/// a coupon is **redeemed** (single use, same rules as a redemption code), a ticket or reservation is **checked in** (single use),
/// a loyalty card identifies the **member** (so the till can add points).
public struct WalletScanRequest: Codable, Sendable, Hashable {
    public var code: String
    /// Optional till or store identifier (≤ 64), recorded like a redemption's.
    public var locationCode: String?

    public init(code: String, locationCode: String? = nil) {
        self.code = code
        self.locationCode = locationCode
    }
}

public struct WalletScanResult: Codable, Sendable, Hashable {
    public enum Outcome: String, Codable, Sendable { case redeemed, checkedIn, member }

    public var outcome: Outcome
    public var passId: WalletPassID
    public var kind: WalletPassKind
    public var relationshipId: RelationshipID
    public var subjectRef: SubjectRef?
    /// What the pass is for (offer or event title), so staff can confirm it is the right one.
    public var title: String?
    /// Loyalty cards: the current balance.
    public var pointsBalance: Int?
    /// Coupons: the redemption, exactly as `POST /v1/business/redemptions/consume` would return it (and the same webhook fires).
    public var redemption: RedemptionReceipt?
    public var scannedAt: Date

    public init(outcome: Outcome, passId: WalletPassID, kind: WalletPassKind, relationshipId: RelationshipID, subjectRef: SubjectRef? = nil,
                title: String? = nil, pointsBalance: Int? = nil, redemption: RedemptionReceipt? = nil, scannedAt: Date) {
        self.outcome = outcome
        self.passId = passId
        self.kind = kind
        self.relationshipId = relationshipId
        self.subjectRef = subjectRef
        self.title = title
        self.pointsBalance = pointsBalance
        self.redemption = redemption
        self.scannedAt = scannedAt
    }
}

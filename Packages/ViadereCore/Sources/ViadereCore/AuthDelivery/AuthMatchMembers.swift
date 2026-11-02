import Foundation

/// The two members `POST /v1/business/auth-approvals` gains (ADR-0020 section 2a), present **iff** the request carries `number_match`; `match_prefix_tag` only for
/// 3-digit codes. Validated here so the future approvals route and the SDK share one definition.
public struct AuthMatchTagMembers: Sendable, Hashable {
    public var matchTag: String?
    public var matchPrefixTag: String?
    public init(matchTag: String?, matchPrefixTag: String?) {
        self.matchTag = matchTag
        self.matchPrefixTag = matchPrefixTag
    }

    public func validate(hasNumberMatch: Bool, threeDigit: Bool) -> AuthDeliveryValidationIssue? {
        guard hasNumberMatch else { return matchTag == nil && matchPrefixTag == nil ? nil : AuthDeliveryValidationIssue("match_tag", "not_allowed") }
        guard let tag = matchTag, AuthMatchTags.isValidTag(tag) else { return AuthDeliveryValidationIssue("match_tag", "invalid") }
        if threeDigit {
            guard let prefix = matchPrefixTag, AuthMatchTags.isValidTag(prefix) else { return AuthDeliveryValidationIssue("match_prefix_tag", "invalid") }
        } else if matchPrefixTag != nil {
            return AuthDeliveryValidationIssue("match_prefix_tag", "not_allowed")
        }
        return nil
    }
}

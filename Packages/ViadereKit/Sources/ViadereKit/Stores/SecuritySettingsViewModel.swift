import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class SecuritySettingsViewModel {
    public struct ConsentHistoryItem: Identifiable, Equatable, Sendable {
        public var id: ConsentGrantID { grant.id }
        public var grant: ConsentGrant
        public var businessName: String
    }

    public private(set) var devices: [Device] = []
    public private(set) var phones: [PhoneLink] = []
    public private(set) var sessions: [ConsumerSession] = []
    public private(set) var consentHistory: [ConsentHistoryItem] = []
    public private(set) var currentDeviceId: DeviceID?
    public private(set) var phonesAvailable = true
    public private(set) var sessionsAvailable = true
    public private(set) var errorMessage: String?
    public private(set) var appLockMethod: String
    public var appLockEnabled: Bool
    /// Show amounts, places and other details in approval notifications on the lock screen. Off by default: the
    /// lock screen then names only who is asking.
    public var richPreviewsEnabled: Bool
    private let services: ViadereServices

    public init(services: ViadereServices) {
        self.services = services
        appLockEnabled = services.preferences.bool(.appLockEnabled)
        richPreviewsEnabled = services.preferences.bool(.richNotificationPreviews)
        appLockMethod = services.appLock.methodName
    }

    public func load() async {
        currentDeviceId = (try? await services.records.load())?.deviceId
        async let d = try? services.api.devices()
        async let relationships = try? services.api.relationships()
        let (deviceList, rels) = await (d, relationships)
        devices = (deviceList ?? []).sorted { ($0.lastSeenAt ?? $0.createdAt) > ($1.lastSeenAt ?? $1.createdAt) }

        do { phones = try await services.api.phoneLinks(); phonesAvailable = true } catch let error as APIError {
            if error.code == .notFound { phonesAvailable = false }
        } catch {}
        do { sessions = try await services.api.sessions(); sessionsAvailable = true } catch let error as APIError {
            if error.code == .notFound { sessionsAvailable = false }
        } catch {}

        var history: [ConsentHistoryItem] = []
        for relationship in rels ?? [] {
            for grant in (try? await services.api.consents(for: relationship.id)) ?? [] {
                history.append(ConsentHistoryItem(grant: grant, businessName: relationship.business.safeName))
            }
        }
        consentHistory = history.sorted { $0.grant.updatedAt > $1.grant.updatedAt }
    }

    /// Turning the lock on requires a successful authentication first, so a stranger can't enable and lock out the owner.
    public func setAppLock(_ enabled: Bool) async {
        guard enabled != services.preferences.bool(.appLockEnabled) else { return }
        if enabled {
            guard await services.appLock.isAvailable(),
                  await services.appLock.authenticate(reason: "Turn on app lock") else {
                appLockEnabled = false
                return
            }
        }
        services.preferences.setBool(enabled, for: .appLockEnabled)
        appLockEnabled = enabled
    }

    /// Turning detailed previews on needs a successful authentication (it exposes request details to anyone who can
    /// see the lock screen); turning them off never does.
    public func setRichPreviews(_ enabled: Bool) async {
        guard enabled != services.preferences.bool(.richNotificationPreviews) else { return }
        if enabled {
            guard await services.appLock.isAvailable(),
                  await services.appLock.authenticate(reason: "Show request details in notifications") else {
                richPreviewsEnabled = false
                return
            }
        }
        services.preferences.setBool(enabled, for: .richNotificationPreviews)
        richPreviewsEnabled = enabled
    }

    public func revoke(_ device: Device) async {
        guard device.id != currentDeviceId else { return }
        do {
            try await services.api.revokeDevice(device.id)
            if let index = devices.firstIndex(where: { $0.id == device.id }) { devices[index].revokedAt = services.clock() }
        } catch {
            errorMessage = (error as? APIError)?.userMessage ?? "Couldn't remove that device."
        }
    }

    // MARK: Linking another phone

    public enum AddPhoneStage: Equatable, Sendable { case idle, awaitingCode, failed(String) }
    public private(set) var addPhoneStage: AddPhoneStage = .idle
    private var pendingPhoneLinkId: PhoneLinkID?

    /// Starts linking a number (`PhoneInput` accepts "(480) 555-0123"); an SMS code follows.
    public func startAddPhone(_ raw: String) async {
        guard let phone = PhoneInput.normalize(raw) else { addPhoneStage = .failed("Enter a full mobile number."); return }
        do {
            pendingPhoneLinkId = try await services.api.startPhoneLink(phone: phone).phoneLinkId
            addPhoneStage = .awaitingCode
        } catch {
            addPhoneStage = .failed((error as? APIError)?.userMessage ?? "Couldn't send a code.")
        }
    }

    public func verifyAddPhone(code: String) async {
        guard let id = pendingPhoneLinkId, OTPInput.isComplete(code) else { return }
        do {
            let link = try await services.api.verifyPhoneLink(id: id, code: OTPInput.normalize(code))
            phones.append(link)
            pendingPhoneLinkId = nil
            addPhoneStage = .idle
        } catch {
            addPhoneStage = .failed((error as? APIError)?.userMessage ?? "That code isn't right.")
        }
    }

    public func cancelAddPhone() { pendingPhoneLinkId = nil; addPhoneStage = .idle }

    // MARK: SMS account link (https://viadere.com/l/{token})

    /// Warning shown on the link confirmation screen. Linking someone else's number lets them message businesses as you.
    public static let accountLinkWarning = "Only continue if you started this from your own phone. Linking someone else's number lets them message businesses as you."

    public enum AccountLinkPhase: Equatable, Sendable {
        case idle, loading
        /// The token is valid; the screen shows the masked number and waits for an explicit "This is my phone".
        case ready(PhoneLinkPreview)
        case failed(String)
    }

    public private(set) var accountLinkPhase: AccountLinkPhase = .idle

    /// Fetches what the one-time token would link (masked number and expiry). Read-only: nothing is linked yet.
    public func loadAccountLinkPreview(token: String) async {
        accountLinkPhase = .loading
        do {
            accountLinkPhase = .ready(try await services.api.previewPhoneLink(token: token))
        } catch {
            accountLinkPhase = .failed((error as? APIError)?.userMessage ?? "This link isn't valid anymore.")
        }
    }

    /// Redeems the token for the number previewed. Refuses unless the person explicitly confirmed "This is my phone"
    /// for a preview that is still valid.
    public func redeemAccountLink(token: String, confirmedOwnPhone: Bool) async -> Bool {
        guard confirmedOwnPhone, case .ready(let preview) = accountLinkPhase, preview.expiresAt > services.clock(),
              let last4 = preview.last4 else { return false }
        do {
            phones.append(try await services.api.redeemSMSLink(token: token, confirmPhoneLast4: last4))
            accountLinkPhase = .idle
            return true
        } catch {
            errorMessage = (error as? APIError)?.userMessage ?? "We couldn't link that number."
            return false
        }
    }

    public func resetAccountLink() { accountLinkPhase = .idle }

    public func removePhone(_ phone: PhoneLink) async {
        do { try await services.api.removePhoneLink(phone.id); phones.removeAll { $0.id == phone.id } } catch {
            errorMessage = (error as? APIError)?.userMessage ?? "Couldn't unlink that number."
        }
    }

    public func revokeSession(_ session: ConsumerSession) async {
        guard !session.isCurrent else { return }
        do { try await services.api.revokeSession(session.id); sessions.removeAll { $0.id == session.id } } catch {
            errorMessage = (error as? APIError)?.userMessage ?? "Couldn't sign that session out."
        }
    }
}

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
    private let services: ViadereServices

    public init(services: ViadereServices) {
        self.services = services
        appLockEnabled = services.preferences.bool(.appLockEnabled)
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
                history.append(ConsentHistoryItem(grant: grant, businessName: relationship.business.displayName))
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

    public func revoke(_ device: Device) async {
        guard device.id != currentDeviceId else { return }
        do {
            try await services.api.revokeDevice(device.id)
            if let index = devices.firstIndex(where: { $0.id == device.id }) { devices[index].revokedAt = services.clock() }
        } catch {
            errorMessage = (error as? APIError)?.userMessage ?? "Couldn't remove that device."
        }
    }

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

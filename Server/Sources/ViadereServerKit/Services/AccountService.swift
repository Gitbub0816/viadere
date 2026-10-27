import Fluent
import Foundation
import ViadereCore

/// Phone-link management, signed-in sessions, and account deletion.
struct AccountService {
    let db: any Database
    let ctx: ServerContext

    // MARK: Phone links

    func phoneLinks(for consumer: ConsumerID) async throws -> [PhoneLink] {
        try await PhoneLinkRecord.query(on: db).filter(\.$consumerId == consumer.uuid).filter(\.$state == "verified")
            .sort(\.$createdAt, .ascending).all().compactMap { link in
                link.id.map { PhoneLink(id: PhoneLinkID($0), maskedPhone: link.phoneMasked, verifiedAt: link.verifiedAt ?? link.createdAt) }
            }
    }

    func removePhoneLink(principal: ConsumerPrincipal, id: PhoneLinkID) async throws {
        guard let link = try await PhoneLinkRecord.query(on: db).filter(\.$id == id.uuid)
            .filter(\.$consumerId == principal.consumerId.uuid).first() else { throw APIError.notFound }
        guard link.state != "revoked" else { return }
        try await db.transaction { tx in
            link.state = "revoked"
            link.verifiedPhoneHash = nil
            link.otpHash = nil
            try await link.update(on: tx)
            // Active SMS threads for the number stop being attributed to this account immediately.
            try await SMSContextRecord.query(on: tx).filter(\.$phoneHash == link.phoneHash).set(\.$consumerId, to: nil).update()
            _ = try await AuditService(db: tx, ctx: ctx).record("phone_link.removed", principal: principal, subjectType: "phone_link", subjectId: id.description)
        }
    }

    // MARK: Sessions

    func sessions(principal: ConsumerPrincipal) async throws -> [SessionInfo] {
        let now = ctx.now
        let tokens = try await RefreshTokenRecord.query(on: db).filter(\.$consumerId == principal.consumerId.uuid)
            .filter(\.$state == "active").filter(\.$expiresAt > now).all()
        var byFamily: [UUID: (created: Date, expires: Date)] = [:]
        for token in tokens {
            let current = byFamily[token.familyId]
            byFamily[token.familyId] = (min(current?.created ?? token.createdAt, token.createdAt), max(current?.expires ?? token.expiresAt, token.expiresAt))
        }
        return byFamily.map { SessionInfo(id: $0.key, createdAt: $0.value.created, expiresAt: $0.value.expires, current: $0.key == principal.familyId) }
            .sorted { $0.createdAt < $1.createdAt }
    }

    func revokeSession(principal: ConsumerPrincipal, id: UUID) async throws {
        guard try await RefreshTokenRecord.query(on: db).filter(\.$familyId == id).filter(\.$consumerId == principal.consumerId.uuid).count() > 0
        else { throw APIError.notFound }
        try await ConsumerTokenService(db: db, ctx: ctx).revokeFamily(id, now: ctx.now)
        _ = try await AuditService(db: db, ctx: ctx).record("session.revoked", principal: principal, subjectType: "session", subjectId: id.uuidString.lowercased())
    }

    // MARK: Account deletion

    /// Revokes every device and token, disconnects all businesses, erases personal data (name, passkeys, phone numbers,
    /// message bodies, push tokens, SMS threads) and keeps pseudonymous security records (audit chain, consent history,
    /// signed decisions) that contain only opaque ids. Businesses are told each relationship ended.
    func deleteAccount(principal: ConsumerPrincipal) async throws {
        let consumer = principal.consumerId
        let id = consumer.uuid
        let now = ctx.now
        let relationships = try await RelationshipRecord.query(on: db).filter(\.$consumerId == id).filter(\.$status == "active").all()
        for relationship in relationships {
            try await RelationshipService(db: db, ctx: ctx).disconnect(consumer: consumer, relationshipId: RelationshipID(relationship.id!))
        }
        try await db.transaction { tx in
            try await ConsumerTokenService(db: tx, ctx: ctx).revokeAll(consumerId: id, now: now)
            let devices = try await DeviceRecord.query(on: tx).filter(\.$consumerId == id).all()
            let deviceIds = devices.compactMap(\.id)
            try await DeviceRecord.query(on: tx).filter(\.$consumerId == id).filter(\.$revokedAt == nil).set(\.$revokedAt, to: now).update()
            if !deviceIds.isEmpty { try await APNsTokenRecord.query(on: tx).filter(\.$deviceId ~~ deviceIds).delete() }
            try await LiveActivityTokenRecord.query(on: tx).filter(\.$consumerId == id).delete()
            try await DeviceEnrollChallengeRecord.query(on: tx).filter(\.$consumerId == id).delete()
            try await PasskeyCredentialRecord.query(on: tx).filter(\.$consumerId == id).delete()
            // Phone numbers: unlink, and overwrite the encrypted number and masked display.
            let links = try await PhoneLinkRecord.query(on: tx).filter(\.$consumerId == id).all()
            let erased = try ctx.cipher.seal("[deleted]", context: "phone_links.phone")
            for link in links {
                try await SMSContextRecord.query(on: tx).filter(\.$phoneHash == link.phoneHash).set(\.$consumerId, to: nil).update()
                link.state = "revoked"
                link.verifiedPhoneHash = nil
                link.otpHash = nil
                link.phoneCiphertext = erased
                link.phoneMasked = "deleted"
                link.phoneLast4 = "0000"
                link.phoneHash = SecureToken.hash("deleted:" + (link.id?.uuidString ?? ""))
                try await link.update(on: tx)
            }
            // Message history: bodies erased; rows kept so business-side ids stay consistent.
            let blank = try ctx.cipher.seal("[deleted]", context: "conversation_messages.body")
            try await ConversationMessageRecord.query(on: tx).filter(\.$consumerId == id).set(\.$bodyCiphertext, to: blank).update()
            try await ConversationSessionRecord.query(on: tx).filter(\.$consumerId == id).filter(\.$state != "closed")
                .set(\.$state, to: "closed").set(\.$closedAt, to: now).update()
            // Interaction payloads can contain personal context (devices, locations, amounts): erase them.
            let placeholder = String(decoding: try ViadereJSON.encode(JSONValue.object([:])), as: UTF8.self)
            let owned = try await InteractionRecord.query(on: tx).filter(\.$consumerId == id).all()
            for interaction in owned {
                interaction.interactionJSON = placeholder
                try await interaction.update(on: tx)
            }
            guard let record = try await ConsumerRecord.find(id, on: tx) else { throw APIError.notFound }
            record.displayName = "Deleted account"
            record.userHandle = SecureToken.generate(byteCount: 32)
            record.status = "deleted"
            try await record.update(on: tx)
            _ = try await AuditService(db: tx, ctx: ctx).record("account.deleted", actor: AuditActor(kind: .consumer, id: consumer.description),
                consumerId: consumer, subjectType: "consumer", subjectId: consumer.description,
                metadata: ["relationships_closed": String(relationships.count), "devices_revoked": String(deviceIds.count)])
        }
    }
}

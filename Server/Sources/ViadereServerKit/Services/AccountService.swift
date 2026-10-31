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
                link.id.map { PhoneLink(id: PhoneLinkID($0), maskedPhone: link.phoneMasked, verifiedAt: link.verifiedAt ?? link.createdAt,
                                        usableFrom: link.usableFrom.flatMap { $0 > ctx.now ? $0 : nil }) }
            }
    }

    func removePhoneLink(principal: ConsumerPrincipal, id: PhoneLinkID) async throws {
        try await DeviceTrust.require(principal, db: db, now: ctx.now)
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
        // Ending another session (and the devices enrolled through it) needs a trusted device.
        if id != principal.familyId { try await DeviceTrust.require(principal, db: db, now: ctx.now) }
        try await ConsumerTokenService(db: db, ctx: ctx).revokeFamily(id, now: ctx.now)
        _ = try await AuditService(db: db, ctx: ctx).record("session.revoked", principal: principal, subjectType: "session", subjectId: id.uuidString.lowercased())
    }

    // MARK: Account deletion

    /// Revokes every device and token, disconnects all businesses, erases personal data (name, passkeys, phone numbers,
    /// message bodies, push tokens, SMS threads) and keeps pseudonymous security records (audit chain, consent history,
    /// signed decisions) that contain only opaque ids. Businesses are told each relationship ended.
    func deleteAccount(principal: ConsumerPrincipal) async throws {
        // Irreversible: only a trusted device (not one enrolled in the last day, not an App Clip) can do it.
        try await DeviceTrust.require(principal, db: db, now: ctx.now)
        let consumer = principal.consumerId
        let id = consumer.uuid
        let now = ctx.now
        let relationships = try await RelationshipRecord.query(on: db).filter(\.$consumerId == id).filter(\.$status == "active").all()
        for relationship in relationships {
            try await RelationshipService(db: db, ctx: ctx).disconnect(consumer: consumer, relationshipId: RelationshipID(relationship.id!))
        }
        // Household access ends with the account, in both directions.
        try await HouseholdService(db: db, ctx: ctx).endAll(for: consumer)
        try await db.transaction { tx in
            try await ConsumerTokenService(db: tx, ctx: ctx).revokeAll(consumerId: id, now: now)
            let devices = try await DeviceRecord.query(on: tx).filter(\.$consumerId == id).all()
            let deviceIds = devices.compactMap(\.id)
            try await DeviceLifecycle(db: tx, ctx: ctx).revoke(deviceIds: deviceIds, now: now)
            // A device name ("Ana's iPhone") is personal data.
            try await DeviceRecord.query(on: tx).filter(\.$consumerId == id).set(\.$name, to: "Deleted device").update()
            try await LiveActivityTokenRecord.query(on: tx).filter(\.$consumerId == id).delete()
            try await DeviceEnrollChallengeRecord.query(on: tx).filter(\.$consumerId == id).delete()
            try await PasskeyCredentialRecord.query(on: tx).filter(\.$consumerId == id).delete()
            // The synced credential vault (ciphertext, public keys, join requests) goes with the account.
            try await VaultService.wipe(consumer: id, on: tx)
            // Approval keys are revoked, and what the relay kept of requests (details, nonces, ciphertext) is erased (WP1).
            try await ApproveKeyService.wipe(consumer: id, on: tx, ctx: ctx)
            // Verification requests and results (WP3) are deleted; consent receipts and audit follow their own retention.
            try await VerifyService.wipe(consumer: id, on: tx)
            // Organization rows (WP-1.1): per-business preferences, conversation archive/mute, alert seen marks.
            try await PreferenceService.wipe(consumer: id, on: tx)
            // Customer profile (docs/PROFILES.md): values, custom public name, verified facts, requests; remaining grants end.
            try await ProfileService.wipe(consumer: id, on: tx, ctx: ctx)
            // Phone numbers: unlink, and overwrite the encrypted number and masked display. Everything that holds the same number
            // (outbound queues, link tokens, SMS thread state) is found by its phone hash *before* the hash is replaced.
            let links = try await PhoneLinkRecord.query(on: tx).filter(\.$consumerId == id).all()
            for link in links {
                try await Self.erasePhoneTraces(phoneHash: link.phoneHash, ctx: ctx, on: tx)
                link.state = "revoked"
                link.verifiedPhoneHash = nil
                link.otpHash = nil
                link.phoneCiphertext = try ctx.cipher.seal("[deleted]", context: "phone_links.phone", rowId: link.id!)
                link.phoneMasked = "deleted"
                link.phoneLast4 = "0000"
                link.phoneHash = SecureToken.hash("deleted:" + (link.id?.uuidString ?? ""))
                try await link.update(on: tx)
            }
            // Queued or delivered channel messages addressed to this person.
            for row in try await ChannelOutboundRecord.query(on: tx).filter(\.$consumerId == id).all() {
                row.phoneCiphertext = try ctx.cipher.seal("[deleted]", context: "channel_outbound.phone", rowId: row.id!)
                row.phoneHash = SecureToken.hash("deleted:" + row.id!.uuidString)
                if ["queued", "sending"].contains(row.status) { row.status = "cancelled"; row.errorCode = "account_deleted" }
                try await row.update(on: tx)
            }
            // Link tokens minted for this consumer (handoffs) hold the number too.
            for token in try await LinkTokenRecord.query(on: tx).filter(\.$consumerId == id).all() {
                token.phoneCiphertext = try ctx.cipher.seal("[deleted]", context: "link_tokens.phone", rowId: token.id!)
                token.phoneLast4 = "0000"
                token.phoneHash = SecureToken.hash("deleted:" + token.id!.uuidString)
                token.state = "revoked"
                try await token.update(on: tx)
            }
            // Delegation labels are names the account holder chose for other people.
            for grant in try await DelegationGrantRecord.query(on: tx).filter(\.$grantorId == id).all() where grant.labelCiphertext != nil {
                grant.labelCiphertext = try ctx.cipher.seal("Someone", context: "delegation.label", rowId: grant.id!)
                try await grant.update(on: tx)
            }
            for invitation in try await DelegationInvitationRecord.query(on: tx).filter(\.$grantorId == id).all() {
                invitation.labelCiphertext = try ctx.cipher.seal("Someone", context: "delegation.label", rowId: invitation.id!)
                try await invitation.update(on: tx)
            }
            // Signed decisions are append-only (non-repudiation: a business and Viadere must be able to prove what a device signed).
            // Only decisions that carry free text (`reply`, which can contain anything the person typed) are erased, by the one permitted
            // edit. The others hold ids, the challenge, timestamps and the context digest, no personal data, and stay verifiable and
            // exportable (`export-dispute`) under the retention basis in SECURITY.md §2.20 (legitimate interest in dispute handling).
            for decision in try await DecisionRecord.query(on: tx).filter(\.$consumerId == id).all() where Self.carriesFreeText(decision.signedPayload) {
                try await DecisionRecord.query(on: tx).filter(\.$id == decision.id!).set(\.$signedPayload, to: CreateSecurityHardeningSchema.erased).update()
            }
            // Loyalty: the business-side member reference is personal data; balances stay as pseudonymous records.
            try await LoyaltyAccountRecord.query(on: tx).filter(\.$consumerId == id)
                .set(\.$memberReferenceCiphertext, to: nil).set(\.$memberReferenceMasked, to: nil).update()
            // Wallet: passes are voided and devices unregistered, so nothing keeps updating a deleted person's cards.
            let passes = try await WalletPassRecord.query(on: tx).filter(\.$consumerId == id).all()
            for pass in passes {
                try await WalletRegistrationRecord.query(on: tx).filter(\.$passId == pass.id!).delete()
                try await WalletPassRecord.query(on: tx).filter(\.$id == pass.id!).set(\.$voided, to: true).set(\.$updatedAt, to: now).update()
            }
            // Redemption codes in flight are released (slots and points are moot now, but no live code survives).
            try await RewardRedemptionRecord.query(on: tx).filter(\.$consumerId == id).filter(\.$status == "issued")
                .set(\.$status, to: "expired").set(\.$slot, to: nil).set(\.$releasedAt, to: now).update()
            // Message history: bodies erased; rows kept so business-side ids stay consistent.
            for message in try await ConversationMessageRecord.query(on: tx).filter(\.$consumerId == id).all() {
                message.bodyCiphertext = try ctx.cipher.seal("[deleted]", context: "conversation_messages.body", rowId: message.id!)
                try await message.update(on: tx)
            }
            try await ConversationSessionRecord.query(on: tx).filter(\.$consumerId == id).filter(\.$state != "closed")
                .set(\.$state, to: "closed").set(\.$closedAt, to: now).update()
            // Interaction payloads can contain personal context (devices, locations, amounts): erase them.
            let placeholder = String(decoding: try ViadereJSON.encode(JSONValue.object([:])), as: UTF8.self)
            let owned = try await InteractionRecord.query(on: tx).filter(\.$consumerId == id).all()
            for interaction in owned {
                interaction.interactionJSON = placeholder
                // The outcome carries the free-text reply and the selected options.
                if var outcome = interaction.outcomeJSON.flatMap({ try? ViadereJSON.decode(InteractionOutcome.self, from: Data($0.utf8)) }) {
                    outcome.reply = nil
                    outcome.selectedOptionIds = nil
                    outcome.signedDecision = nil
                    interaction.outcomeJSON = String(decoding: try ViadereJSON.encode(outcome), as: UTF8.self)
                }
                try await interaction.update(on: tx)
            }
            // Webhook deliveries that still hold this person's message text or replies.
            try await WebhookService(db: tx, ctx: ctx).scrubDeliveries(forConsumer: id)
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

    /// True when a stored signed-decision payload (base64url canonical JSON) contains a free-text `reply`. An unreadable payload is
    /// treated as carrying text (erased), never kept by accident.
    static func carriesFreeText(_ signedPayload: String) -> Bool {
        guard signedPayload != CreateSecurityHardeningSchema.erased else { return false }
        guard let data = Base64URL.decode(signedPayload), let payload = try? ViadereJSON.decode(JSONValue.self, from: data),
              case .object(let members) = payload else { return true }
        if let reply = members["reply"], case .string = reply { return true }
        return false
    }

    /// Removes the number from the SMS queue and the thread state of `phoneHash`. An opted-out number stays suppressed (a fresh thread
    /// that keeps only the opt-out), because forgetting a STOP would allow texting it again.
    private static func erasePhoneTraces(phoneHash: String, ctx: ServerContext, on tx: any Database) async throws {
        for row in try await SMSOutboundRecord.query(on: tx).filter(\.$phoneHash == phoneHash).all() {
            row.phoneCiphertext = try ctx.cipher.seal("[deleted]", context: "sms_outbound.phone", rowId: row.id!)
            row.bodyCiphertext = try ctx.cipher.seal("[removed]", context: "sms_outbound.body", rowId: row.id!)
            row.phoneHash = SecureToken.hash("deleted:" + row.id!.uuidString)
            if ["queued", "sending"].contains(row.status) { row.status = "cancelled"; row.errorCode = "account_deleted" }
            try await row.update(on: tx)
        }
        for token in try await LinkTokenRecord.query(on: tx).filter(\.$phoneHash == phoneHash).all() {
            token.phoneCiphertext = try ctx.cipher.seal("[deleted]", context: "link_tokens.phone", rowId: token.id!)
            token.phoneLast4 = "0000"
            token.phoneHash = SecureToken.hash("deleted:" + token.id!.uuidString)
            token.state = "revoked"
            try await token.update(on: tx)
        }
        for thread in try await SMSContextRecord.query(on: tx).filter(\.$phoneHash == phoneHash).all() {
            if thread.optedOut {
                // Keep only the suppression.
                guard let data = try? ctx.cipher.open(thread.contextCiphertext, context: "sms_contexts.context", rowId: thread.id!),
                      let old = try? ViadereJSON.decode(ConversationContext.self, from: data) else { try await thread.delete(on: tx); continue }
                var fresh = ConversationContext(phone: old.phone, consentVersion: old.consent.consentVersion)
                fresh.consent = old.consent
                fresh.state = .optedOut
                fresh.revision = old.revision + 1
                thread.contextCiphertext = try ctx.cipher.seal(try ViadereJSON.encode(fresh), context: "sms_contexts.context", rowId: thread.id!)
                thread.revision = fresh.revision
                thread.consumerId = nil
                thread.activeSessionId = nil
                try await thread.update(on: tx)
            } else {
                try await thread.delete(on: tx)
            }
        }
    }
}

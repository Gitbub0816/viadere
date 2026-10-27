import Fluent
import FluentSQL
import Foundation
import SQLKit

/// WP5: the synced credential vault. Every table holds ciphertext, signed public structures and public keys only.
struct CreateVaultWP5Schema: AsyncMigration {
    var name: String { "CreateVaultWP5Schema.v1" }

    func prepare(on db: any Database) async throws {
        try await db.schema("vault_vaults")
            .id()
            .field("consumer_id", .uuid, .required, .references("consumers", "id"))
            .field("version", .int, .required)
            .field("epoch", .int, .required)
            .field("manifest_hash", .string, .required)
            .field("created_at", .datetime, .required)
            .field("updated_at", .datetime, .required)
            .unique(on: "consumer_id")
            .create()

        try await db.schema("vault_manifests")
            .id()
            .field("vault_id", .uuid, .required, .references("vault_vaults", "id", onDelete: .cascade))
            .field("version", .int, .required)
            .field("manifest", .string, .required)
            .field("signature", .string, .required)
            .field("authorization", .string)
            .field("hash", .string, .required)
            .field("created_at", .datetime, .required)
            .unique(on: "vault_id", "version")
            .create()

        try await db.schema("vault_blobs")
            .id()
            .field("vault_id", .uuid, .required, .references("vault_vaults", "id", onDelete: .cascade))
            .field("item_id", .uuid, .required)
            .field("revision", .int, .required)
            .field("blob_hash", .string, .required)
            .field("blob", .data, .required)
            .field("updated_at", .datetime, .required)
            .unique(on: "vault_id", "item_id")
            .create()

        try await db.schema("vault_members")
            .id()
            .field("vault_id", .uuid, .required, .references("vault_vaults", "id", onDelete: .cascade))
            .field("member_id", .string, .required)
            .field("role", .string, .required)
            .field("signing_key", .string, .required)
            .field("envelope_hash", .string, .required)
            .field("envelope", .data)
            .field("account_device_id", .uuid)
            .field("added_at", .datetime, .required)
            .field("removed_at", .datetime)
            .unique(on: "vault_id", "member_id")
            .create()

        try await db.schema("vault_joins")
            .id()
            .field("join_id", .string, .required)
            .field("consumer_id", .uuid, .required)
            .field("vault_id", .uuid, .required, .references("vault_vaults", "id", onDelete: .cascade))
            .field("requester_device_id", .uuid)
            .field("request", .data)
            .field("approval", .data)
            .field("approved_member_id", .string)
            .field("created_at", .datetime, .required)
            .field("expires_at", .datetime, .required)
            .unique(on: "join_id")
            .create()

        guard let sql = db as? any SQLDatabase else { return }
        let indexes: [(String, String, String)] = [
            ("idx_vault_members_device", "vault_members", "account_device_id"),
            ("idx_vault_joins_consumer", "vault_joins", "consumer_id, expires_at"),
        ]
        for (name, table, columns) in indexes {
            // Identifiers are compile-time constants above; no user input reaches this statement.
            try await sql.raw(SQLQueryString("CREATE INDEX IF NOT EXISTS \(unsafeRaw: name) ON \(unsafeRaw: table) (\(unsafeRaw: columns))")).run()
        }
    }

    func revert(on db: any Database) async throws {
        guard let sql = db as? any SQLDatabase else { return }
        for table in ["vault_joins", "vault_members", "vault_blobs", "vault_manifests", "vault_vaults"] {
            try await sql.raw(SQLQueryString("DROP TABLE IF EXISTS \(unsafeRaw: table)")).run()
        }
    }
}

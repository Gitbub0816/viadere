package com.viadere.sdk

/**
 * A durable record of processed webhook event ids (ADR-0025 section 2 rule 4). Keep an id for at least [RETENTION_SECONDS] (72 h) **from first
 * receipt**; implement it with an atomic insert on a unique key, for example:
 *
 * ```sql
 * CREATE TABLE viadere_webhook_events (event_id TEXT PRIMARY KEY, first_seen TIMESTAMPTZ NOT NULL);
 * INSERT INTO viadere_webhook_events (event_id, first_seen) VALUES ($1, now()) ON CONFLICT DO NOTHING; -- 1 row inserted = first time
 * DELETE FROM viadere_webhook_events WHERE first_seen < now() - interval '72 hours';
 * ```
 */
public interface WebhookReplayStore {
    /** Atomically records [eventId] and returns `true` the first time, `false` for a repeat still inside the retention window. */
    public fun recordFirstReceipt(eventId: String, nowMillis: Long): Boolean

    /** Forgets an id so Viadere's retry is processed again, when your handler failed before it finished. Optional. */
    public fun release(eventId: String) {}

    public companion object {
        /** The documented minimum retention: the retry horizon plus 300 s, rounded up to 72 h. */
        public const val RETENTION_SECONDS: Long = 72 * 3600

        /** Explicit opt-out of dedup (tests only): every event counts as the first. A verifier without a store accepts a replay inside the 300 s window. */
        public val Disabled: WebhookReplayStore = object : WebhookReplayStore {
            override fun recordFirstReceipt(eventId: String, nowMillis: Long): Boolean = true
        }
    }
}

/**
 * Process-local store, the **default**. Entries expire after the retention from first receipt and the map is bounded (oldest first). With several
 * processes or restarts the guarantee is per process: use a shared store for production.
 */
public class InMemoryWebhookReplayStore(
    retentionSeconds: Long = WebhookReplayStore.RETENTION_SECONDS,
    private val maxEntries: Int = 100_000,
) : WebhookReplayStore {
    private val retentionMillis = retentionSeconds * 1000
    private val seen = LinkedHashMap<String, Long>() // insertion order == first-receipt order

    @Synchronized
    override fun recordFirstReceipt(eventId: String, nowMillis: Long): Boolean {
        val it = seen.entries.iterator()
        while (it.hasNext()) {
            if (nowMillis - it.next().value < retentionMillis) break
            it.remove()
        }
        if (seen.containsKey(eventId)) return false
        if (seen.size >= maxEntries) {
            val oldest = seen.entries.iterator()
            oldest.next()
            oldest.remove()
        }
        seen[eventId] = nowMillis
        return true
    }

    @Synchronized
    override fun release(eventId: String) {
        seen.remove(eventId)
    }

    @get:Synchronized
    public val size: Int get() = seen.size
}

/** A verified delivery. */
public data class VerifiedWebhook(
    val eventId: String,
    val tenantId: String,
    val timestamp: Long,
    val body: ByteArray,
    /** `Viadere-Delivery-Id`: stable across retries of one delivery. */
    val deliveryId: String?,
    /** `Viadere-Key-Id`: record it, a change means the secret was rotated. */
    val keyId: String?,
) {
    override fun equals(other: Any?): Boolean = other is VerifiedWebhook && eventId == other.eventId && tenantId == other.tenantId && timestamp == other.timestamp &&
        body.contentEquals(other.body) && deliveryId == other.deliveryId && keyId == other.keyId

    override fun hashCode(): Int = listOf(eventId, tenantId, timestamp, body.contentHashCode(), deliveryId, keyId).hashCode()
}

public data class VerifiedEnvelope(val webhook: VerifiedWebhook, val envelope: AuthDeliveryEnvelope)

/**
 * Verifies Viadere webhooks (signature v2) for a Kotlin/JVM receiver.
 *
 * Build it with the **endpoint URL you registered** (never a proxy-rewritten value), your tenant id and your secrets by key id (`whk_<prefix>_v<n>`;
 * keep the previous one during a rotation). Pass the **raw** body bytes. **The replay store is on by default** (review R23-06); pass a shared one in
 * production and [WebhookReplayStore.Disabled] only in tests. Secrets never appear in `toString`.
 *
 * `opened` is never authentication success: fetch the state from your server, verify your own link or code, then call `complete`.
 */
public class WebhookVerifier(
    endpoint: String,
    private val tenantId: String,
    keys: Map<String, String>,
    private val toleranceSeconds: Long = WebhookSignatureV2.DEFAULT_TOLERANCE_SECONDS,
    private val replayStore: WebhookReplayStore = InMemoryWebhookReplayStore(),
    private val clockMillis: () -> Long = System::currentTimeMillis,
) {
    private val host: String
    private val pathAndQuery: String
    private val keys: Map<String, String> = keys.toMap()

    init {
        val parts = WebhookSignatureV2.endpointParts(endpoint)
        require(parts != null && WebhookSignatureV2.isHostValid(parts.first) && WebhookSignatureV2.isPathValid(parts.second)) { "endpoint must be the https URL registered with Viadere" }
        require(Ids.isTenantId(tenantId)) { "tenantId is not a valid tenant id" }
        require(this.keys.isNotEmpty()) { "keys must hold at least one secret" }
        for ((kid, secret) in this.keys) {
            require(WebhookSignatureV2.isKeyId(kid)) { "\"$kid\" is not a key id (whk_<prefix>_v<n>)" }
            require(secret.isNotEmpty()) { "the secret of $kid is empty" }
        }
        host = parts.first
        pathAndQuery = parts.second
    }

    override fun toString(): String = "WebhookVerifier($host$pathAndQuery, tenant $tenantId, ${keys.size} key(s))"

    /**
     * Verifies signature, timestamp window, tenant and digest, then records the event id. [headers] maps a header name to its values (names are
     * matched case-insensitively; a repeated `Viadere-Signature` is refused as ambiguous).
     */
    public fun verify(headers: Map<String, List<String>>, body: ByteArray): VerifiedWebhook {
        val verified = verifySignature(headers, body)
        record(verified.eventId)
        return verified
    }

    /**
     * Verifies an `auth.delivery.*` delivery and decodes its opaque envelope: no unknown member, version `2026-10-27`, your tenant, a body id equal to
     * the signed `Viadere-Event-Id`. The event id is recorded last, so a forged or malformed delivery cannot burn a genuine id.
     */
    public fun verifyEnvelope(headers: Map<String, List<String>>, body: ByteArray): VerifiedEnvelope {
        val verified = verifySignature(headers, body)
        val envelope = AuthDeliveryEnvelope.decode(body) ?: throw WebhookVerificationException(WebhookFailure.MalformedBody)
        if (envelope.id != verified.eventId || envelope.tenantId != tenantId) throw WebhookVerificationException(WebhookFailure.HeaderBodyMismatch)
        record(verified.eventId)
        return VerifiedEnvelope(verified, envelope)
    }

    /** Forgets an event id so the next retry is processed (when your handler failed before it finished). */
    public fun release(eventId: String) {
        replayStore.release(eventId)
    }

    private fun verifySignature(headers: Map<String, List<String>>, body: ByteArray): VerifiedWebhook {
        fun header(name: String): String? {
            val values = headers.entries.filter { it.key.equals(name, ignoreCase = true) }.flatMap { it.value }
            if (values.size > 1) throw WebhookVerificationException(WebhookFailure.MalformedSignature) // a repeated header is ambiguous
            return values.firstOrNull()
        }
        val signature = header(SIGNATURE) ?: throw WebhookVerificationException(WebhookFailure.MissingHeader)
        val eventId = header(EVENT_ID) ?: throw WebhookVerificationException(WebhookFailure.MissingHeader)
        val tenant = header(TENANT) ?: throw WebhookVerificationException(WebhookFailure.MissingHeader)
        val timestamp = WebhookSignatureV2.verify(
            header = signature,
            body = body,
            contentDigestHeader = header(CONTENT_DIGEST),
            context = SignatureContext("POST", host, pathAndQuery, eventId, tenant),
            expectedTenant = tenantId,
            keys = keys,
            nowSeconds = clockMillis() / 1000,
            toleranceSeconds = toleranceSeconds,
        )
        return VerifiedWebhook(eventId, tenant, timestamp, body, header(DELIVERY_ID), header(KEY_ID))
    }

    private fun record(eventId: String) {
        if (!replayStore.recordFirstReceipt(eventId, clockMillis())) throw WebhookVerificationException(WebhookFailure.DuplicateEvent)
    }

    public companion object {
        public const val SIGNATURE: String = "Viadere-Signature"
        public const val EVENT_ID: String = "Viadere-Event-Id"
        public const val TENANT: String = "Viadere-Tenant"
        public const val CONTENT_DIGEST: String = "Content-Digest"
        public const val DELIVERY_ID: String = "Viadere-Delivery-Id"
        public const val KEY_ID: String = "Viadere-Key-Id"

        /** Wraps single-valued headers (most servers' `Map<String, String>`) for [verify]. */
        public fun headersOf(single: Map<String, String>): Map<String, List<String>> = single.mapValues { listOf(it.value) }
    }
}

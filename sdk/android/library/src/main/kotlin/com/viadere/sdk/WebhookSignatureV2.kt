package com.viadere.sdk

import java.net.URI
import java.net.URISyntaxException
import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** Why a webhook was rejected. Answer `400` and do not process it; a duplicate is acknowledged with `200` (it was already processed). */
public enum class WebhookFailure(public val wire: String) {
    MissingHeader("missing_header"),
    MalformedSignature("malformed_signature"),
    TimestampOutsideTolerance("timestamp_outside_tolerance"),
    NoMatchingSignature("no_matching_signature"),
    TenantMismatch("tenant_mismatch"),
    DigestMismatch("digest_mismatch"),
    MalformedBody("malformed_body"),
    HeaderBodyMismatch("header_body_mismatch"),
    DuplicateEvent("duplicate_event");

    /** The HTTP status to answer: `200` for a duplicate, `400` otherwise. */
    public val suggestedStatus: Int get() = if (this == DuplicateEvent) 200 else 400
}

public class WebhookVerificationException(public val failure: WebhookFailure) : Exception("Webhook rejected: ${failure.wire}")

/** The fields of a request that are signed besides the timestamp, key id and body. `host` and `pathAndQuery` come from the registered endpoint. */
public data class SignatureContext(
    val method: String = "POST",
    val host: String,
    val pathAndQuery: String,
    val eventId: String,
    val tenantId: String,
)

/**
 * Webhook signature `v2` (ADR-0025, `docs/protocol/vectors/webhook-v2.json`).
 *
 * ```
 * Viadere-Signature: t=<unix>,v2=<kid>:<base64url mac>[,v2=<kid>:<base64url mac>...][,v1=<hex>]
 * string to sign (UTF-8, LF-separated, no trailing LF):
 *   VIADERE-WEBHOOK-V2 / METHOD / host / path?query / t / event id / tenant id / kid / lowercase hex SHA-256(body)
 * ```
 *
 * A receiver recomputes the string from the request as received and the endpoint URL **it registered**, once per `v2=` entry whose `kid` it holds,
 * and compares in constant time. A v2 verifier never accepts a `v1=` entry alone. Webhook secrets belong on a server: never ship one in an app.
 */
public object WebhookSignatureV2 {
    public const val SCHEME: String = "VIADERE-WEBHOOK-V2"
    public const val DEFAULT_TOLERANCE_SECONDS: Long = 300

    private val method = Regex("^[A-Z]{1,16}$")
    private val host = Regex("^[a-z0-9.-]+(:[0-9]{1,5})?$")
    private val path = Regex("^/([A-Za-z0-9\\-._~!$&'()*+,;=:@/?]|%[0-9A-Fa-f]{2})*$")
    private val keyId = Regex("^[a-z0-9_]{1,64}$")
    private val mac43 = Regex("^[A-Za-z0-9_-]{43}$")
    private val digits = Regex("^[0-9]{1,12}$")

    public fun isKeyId(value: String): Boolean = keyId.matches(value)

    internal fun isHostValid(value: String): Boolean = host.matches(value)
    internal fun isPathValid(value: String): Boolean = value.length <= 2048 && path.matches(value)

    private fun contextValid(c: SignatureContext): Boolean =
        method.matches(c.method) && host.matches(c.host) && isPathValid(c.pathAndQuery) && Ids.isEventId(c.eventId) && Ids.isTenantId(c.tenantId)

    /** The host and `path?query` of a registered endpoint URL (the port only when it is not the scheme's default), or `null` if it cannot be signed over. */
    public fun endpointParts(endpoint: String): Pair<String, String>? {
        val uri = try {
            URI(endpoint)
        } catch (_: URISyntaxException) {
            return null
        }
        val scheme = uri.scheme?.lowercase()
        if (scheme != "https" && scheme != "http") return null
        val h = uri.host?.lowercase() ?: return null
        val defaultPort = if (scheme == "https") 443 else 80
        val hostPart = if (uri.port == -1 || uri.port == defaultPort) h else "$h:${uri.port}"
        val rawPath = if (uri.rawPath.isNullOrEmpty()) "/" else uri.rawPath
        return hostPart to rawPath + (uri.rawQuery?.let { "?$it" } ?: "")
    }

    /** `sha-256=:<base64 of SHA-256(body)>:` (RFC 9530 `Content-Digest`). */
    public fun contentDigest(body: ByteArray): String = "sha-256=:" + Base64.getEncoder().encodeToString(sha256(body)) + ":"

    /** The string to sign, or `null` when a field is outside its charset. */
    public fun stringToSign(context: SignatureContext, timestamp: Long, kid: String, body: ByteArray): String? {
        if (!contextValid(context) || !keyId.matches(kid) || timestamp <= 0 || timestamp.toString().length > 12) return null
        return listOf(SCHEME, context.method, context.host, context.pathAndQuery, timestamp.toString(), context.eventId, context.tenantId, kid, hex(sha256(body))).joinToString("\n")
    }

    /** The 43-character base64url MAC for one `(kid, secret)`, or `null` when a field is outside its charset. */
    public fun mac(secret: String, context: SignatureContext, timestamp: Long, kid: String, body: ByteArray): String? {
        val message = stringToSign(context, timestamp, kid, body) ?: return null
        val hmac = Mac.getInstance("HmacSHA256")
        hmac.init(SecretKeySpec(secret.toByteArray(Charsets.UTF_8), "HmacSHA256"))
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hmac.doFinal(message.toByteArray(Charsets.UTF_8)))
    }

    /** A `Viadere-Signature` value with one `v2=` entry per `(kid, secret)` (a rotation sends two), for tests and simulators. Never adds a `v1=` entry. */
    public fun signatureHeader(secrets: List<Pair<String, String>>, context: SignatureContext, body: ByteArray, nowSeconds: Long): String? {
        val parts = arrayListOf("t=$nowSeconds")
        for ((kid, secret) in secrets) parts += "v2=$kid:" + (mac(secret, context, nowSeconds, kid, body) ?: return null)
        return parts.joinToString(",")
    }

    /**
     * Verifies one delivery's signature and returns the signed timestamp. Checks run in this order and the failure names the first that failed:
     * malformed, timestamp, tenant, digest, MAC.
     */
    public fun verify(
        header: String,
        body: ByteArray,
        contentDigestHeader: String?,
        context: SignatureContext,
        expectedTenant: String,
        keys: Map<String, String>,
        nowSeconds: Long,
        toleranceSeconds: Long = DEFAULT_TOLERANCE_SECONDS,
    ): Long {
        val tolerance = toleranceSeconds.coerceIn(1, DEFAULT_TOLERANCE_SECONDS)
        if (header.length > 4096 || header.contains('\n') || header.contains('\r')) throw WebhookVerificationException(WebhookFailure.MalformedSignature)
        if (!contextValid(context) || !Ids.isTenantId(expectedTenant)) throw WebhookVerificationException(WebhookFailure.MalformedSignature)
        var timestamp: Long? = null
        val entries = ArrayList<Pair<String, String>>()
        val kids = HashSet<String>()
        for (raw in header.split(",")) {
            val part = raw.trim()
            val eq = part.indexOf('=')
            if (eq < 0) throw WebhookVerificationException(WebhookFailure.MalformedSignature)
            val name = part.substring(0, eq)
            val value = part.substring(eq + 1)
            when (name) {
                "t" -> {
                    if (timestamp != null || !digits.matches(value)) throw WebhookVerificationException(WebhookFailure.MalformedSignature)
                    timestamp = value.toLong()
                }
                "v2" -> {
                    val colon = value.indexOf(':')
                    if (colon < 0) throw WebhookVerificationException(WebhookFailure.MalformedSignature)
                    val kid = value.substring(0, colon)
                    val mac = value.substring(colon + 1)
                    if (!keyId.matches(kid) || !mac43.matches(mac) || !kids.add(kid)) throw WebhookVerificationException(WebhookFailure.MalformedSignature)
                    entries += kid to mac
                }
                else -> Unit // `v1=` and unknown schemes are ignored; a v2 verifier never accepts `v1=` alone.
            }
        }
        val t = timestamp
        if (t == null || entries.isEmpty()) throw WebhookVerificationException(WebhookFailure.MalformedSignature)
        if (kotlin.math.abs(nowSeconds - t) > tolerance) throw WebhookVerificationException(WebhookFailure.TimestampOutsideTolerance)
        if (!constantTimeEquals(context.tenantId, expectedTenant)) throw WebhookVerificationException(WebhookFailure.TenantMismatch)
        // The digest is compared with the one computed from the received bytes; the header is never copied into the string to sign.
        if (contentDigestHeader == null || !constantTimeEquals(contentDigestHeader, contentDigest(body))) throw WebhookVerificationException(WebhookFailure.DigestMismatch)
        var matched = false
        for ((kid, presented) in entries) {
            val secret = keys[kid] ?: continue
            val expected = mac(secret, context, t, kid, body) ?: continue
            if (constantTimeEquals(presented, expected)) matched = true
        }
        if (!matched) throw WebhookVerificationException(WebhookFailure.NoMatchingSignature)
        return t
    }

    private fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    private fun hex(bytes: ByteArray): String = buildString(bytes.size * 2) { for (b in bytes) append("0123456789abcdef"[(b.toInt() shr 4) and 0xF]).append("0123456789abcdef"[b.toInt() and 0xF]) }

    private fun constantTimeEquals(a: String, b: String): Boolean = MessageDigest.isEqual(a.toByteArray(Charsets.UTF_8), b.toByteArray(Charsets.UTF_8))
}

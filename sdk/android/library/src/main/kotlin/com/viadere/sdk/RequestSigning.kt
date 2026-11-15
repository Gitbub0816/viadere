package com.viadere.sdk

import java.math.BigInteger
import java.net.URI
import java.net.URISyntaxException
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.util.Base64

// RFC 9421 HTTP Message Signatures with an RFC 9530 Content-Digest: the Viadere profile for business API requests (docs/SECURITY.md section 2.112).
// Opt-in: what a live key needs on the auth-delivery routes when it is not bound to mutual TLS. `java.security` only (no runtime dependency).
// Checked byte for byte against docs/protocol/vectors/http-signatures-v1.json, like the server, the Swift SDK and the TypeScript SDK.

/**
 * A P-256 request-signing key: the `vsk_...` id the console showed when its public key was registered (Security > Request signing), its public key,
 * and an ECDSA P-256 / SHA-256 signature over a message. [sign] may return DER (what `Signature.getInstance("SHA256withECDSA")`, the Android
 * Keystore and most KMSs return) or raw `r||s` (64 bytes) with either `s`; [RequestSigning] converts it to raw, folds it to low S and checks it
 * against [publicKey] before any header is built. Keep the private key in a KMS, HSM or the Android Keystore: this interface only signs.
 */
public interface RequestSigningKey {
    public val keyId: String
    public val publicKey: ECPublicKey

    /** ECDSA P-256 with SHA-256 over [message] (the key hashes it). */
    public fun sign(message: ByteArray): ByteArray
}

/** A [RequestSigningKey] over a `java.security` EC P-256 private key (software or a provider-backed key such as the Android Keystore). */
public class JcaRequestSigningKey(
    override val keyId: String,
    private val privateKey: PrivateKey,
    override val publicKey: ECPublicKey,
) : RequestSigningKey {
    init {
        require(RequestSigning.isKeyId(keyId)) { "the request-signing key id must be the vsk_ id the console showed" }
    }

    override fun sign(message: ByteArray): ByteArray =
        Signature.getInstance("SHA256withECDSA").run {
            initSign(privateKey)
            update(message)
            sign()
        }
}

/** The signer returned something that is not a valid P-256 signature by its public key. No header is produced and nothing should be sent. */
public class RequestSigningException(message: String) : Exception(message)

/**
 * The Viadere RFC 9421 profile (SECURITY section 2.112):
 *
 * ```
 * Content-Digest:  sha-256=:<base64 SHA-256 of the exact body>:            (only with a body)
 * Signature-Input: sig1=("@method" "@authority" "@path" "@query" "content-digest" "content-type");created=<unix>;expires=<unix>;keyid="vsk_<16 hex>";nonce="<22-64 base64url>";tag="viadere-api-v1"
 * Signature:       sig1=:<base64 raw r||s, 64 bytes, low S>:
 * ```
 *
 * Without a body the components are exactly `"@method" "@authority" "@path" "@query"` and there is no `Content-Digest`. Sign every attempt
 * separately: each retry needs a fresh nonce ([sign] draws one by default).
 */
public object RequestSigning {
    public const val TAG: String = "viadere-api-v1"
    public const val ALGORITHM: String = "ecdsa-p256-sha256"
    public const val LABEL: String = "sig1"
    public const val MAX_LIFETIME_SECONDS: Long = 300
    public val BODY_COMPONENTS: List<String> = listOf("@method", "@authority", "@path", "@query", "content-digest", "content-type")
    public val BODILESS_COMPONENTS: List<String> = listOf("@method", "@authority", "@path", "@query")

    private const val PROOF_DOMAIN = "viadere-request-signing-key-v1"
    private val keyIdPattern = Regex("^vsk_[0-9a-f]{16}$")
    private val noncePattern = Regex("^[A-Za-z0-9_-]{22,64}$")
    private val methodPattern = Regex("^[A-Z]{1,16}$")
    private val printable = Regex("^[\\x20-\\x7e\\n]*$")
    private val random = SecureRandom()

    /** The order of P-256. */
    private val n = BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
    private val halfN = n.shiftRight(1)

    public fun isKeyId(value: String): Boolean = keyIdPattern.matches(value)

    public fun isNonce(value: String): Boolean = noncePattern.matches(value)

    /** `sha-256=:<base64>:` of the exact body bytes (RFC 9530). */
    public fun contentDigest(body: ByteArray): String =
        "sha-256=:" + Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(body)) + ":"

    /** `@path` and `@query` of a request target exactly as on the request line: `/a?b` -> (`/a`, `?b`); no query -> `?`. */
    public fun splitTarget(target: String): Pair<String, String> {
        val mark = target.indexOf('?')
        return if (mark < 0) target to "?" else target.substring(0, mark) to target.substring(mark)
    }

    /** The inner list and parameters of `Signature-Input` (without the `sig1=` label), in the profile's order. */
    public fun signatureParams(components: List<String>, created: Long, expires: Long, keyId: String, nonce: String): String =
        components.joinToString(" ", "(", ")") { "\"$it\"" } + ";created=$created;expires=$expires;keyid=\"$keyId\";nonce=\"$nonce\";tag=\"$TAG\""

    /**
     * The signature base (RFC 9421 section 2.5): one `"<component>": <value>` line per component, then `"@signature-params": <params>`; ASCII,
     * LF-joined, no trailing LF. [contentDigest] and [contentType] are required exactly when the components name them.
     */
    public fun signatureBase(method: String, authority: String, target: String, contentDigest: String?, contentType: String?,
                             components: List<String>, params: String): String {
        val (path, query) = splitTarget(target)
        val values = mapOf("@method" to method, "@authority" to authority, "@path" to path, "@query" to query,
                           "content-digest" to contentDigest, "content-type" to contentType)
        require(components.toSet().size == components.size) { "a component is named twice" }
        val out = StringBuilder()
        for (component in components) {
            val value = requireNotNull(values[component]) { "no value for $component" }
            out.append('"').append(component).append("\": ").append(value).append('\n')
        }
        out.append("\"@signature-params\": ").append(params)
        val base = out.toString()
        require(printable.matches(base)) { "the signature base must be printable ASCII" }
        return base
    }

    /** `@authority`, `@path` and `@query` of an absolute `https` (or `http`) URL exactly as it will be sent: lowercase host, default port omitted. */
    public fun authorityAndTarget(url: String): Pair<String, String> {
        val uri = try {
            URI(url)
        } catch (e: URISyntaxException) {
            throw IllegalArgumentException("not a URL", e)
        }
        val scheme = uri.scheme?.lowercase()
        require(scheme == "https" || scheme == "http") { "the URL must be https" }
        require(uri.rawUserInfo == null && uri.rawFragment == null) { "no user info or fragment" }
        val host = requireNotNull(uri.host?.lowercase()) { "the URL has no host" }
        val defaultPort = if (scheme == "https") 443 else 80
        val authority = if (uri.port == -1 || uri.port == defaultPort) host else "$host:${uri.port}"
        val path = if (uri.rawPath.isNullOrEmpty()) "/" else uri.rawPath
        val target = if (uri.rawQuery == null) path else "$path?${uri.rawQuery}"
        return authority to target
    }

    /**
     * The header fields to add to one attempt, in this order: `Content-Type` and `Content-Digest` (only with a non-empty body), `Signature-Input`,
     * `Signature`. Send the request with exactly these values (the body must be the same bytes). [contentType] defaults to `application/json`.
     * [created] is Unix seconds; [lifetimeSeconds] is 1 to 300.
     */
    public fun sign(
        key: RequestSigningKey,
        method: String,
        url: String,
        body: ByteArray? = null,
        contentType: String? = null,
        created: Long = System.currentTimeMillis() / 1000,
        nonce: String = newNonce(),
        lifetimeSeconds: Long = MAX_LIFETIME_SECONDS,
    ): LinkedHashMap<String, String> {
        require(isKeyId(key.keyId)) { "the request-signing key id must be the vsk_ id the console showed" }
        require(isNonce(nonce)) { "nonce must be 22 to 64 base64url characters" }
        require(lifetimeSeconds in 1..MAX_LIFETIME_SECONDS) { "lifetimeSeconds must be 1 to $MAX_LIFETIME_SECONDS" }
        require(created >= 0) { "created must be Unix seconds" }
        val upper = method.uppercase()
        require(methodPattern.matches(upper)) { "not an HTTP method" }
        val (authority, target) = authorityAndTarget(url)
        val hasBody = body != null && body.isNotEmpty()
        val type = if (hasBody) contentType ?: "application/json" else null
        val digest = if (hasBody) contentDigest(body) else null
        val components = if (hasBody) BODY_COMPONENTS else BODILESS_COMPONENTS
        val params = signatureParams(components, created, created + lifetimeSeconds, key.keyId, nonce)
        val base = signatureBase(upper, authority, target, digest, type, components, params).toByteArray(Charsets.US_ASCII)
        val raw = verifiedRaw(key, base, key.sign(base))
        val headers = LinkedHashMap<String, String>()
        if (type != null) headers["Content-Type"] = type
        if (digest != null) headers["Content-Digest"] = digest
        headers["Signature-Input"] = "$LABEL=$params"
        headers["Signature"] = "$LABEL=:" + Base64.getEncoder().encodeToString(raw) + ":"
        return headers
    }

    /**
     * The console's proof of possession for registering [key]'s public key: base64url (no padding) of the raw low-S signature over
     * `viadere-request-signing-key-v1 LF <challenge> LF <public key, base64url uncompressed point>`.
     */
    public fun signingKeyProof(challenge: String, key: RequestSigningKey): String {
        val message = listOf(PROOF_DOMAIN, challenge, publicKeyBase64Url(key.publicKey)).joinToString("\n").toByteArray(Charsets.UTF_8)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(verifiedRaw(key, message, key.sign(message)))
    }

    /** The registered form of a P-256 public key: base64url (no padding) of the 65-byte uncompressed point `04 || x || y`. */
    public fun publicKeyBase64Url(key: ECPublicKey): String {
        val point = ByteArray(65)
        point[0] = 4
        fixed32(key.w.affineX).copyInto(point, 1)
        fixed32(key.w.affineY).copyInto(point, 33)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(point)
    }

    /** 16 random bytes, base64url without padding (22 characters). */
    public fun newNonce(): String = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(16).also(random::nextBytes))

    /** A DER or raw signature as raw `r||s` (64 bytes) with low S. Throws [RequestSigningException] for anything else. */
    public fun rawLowS(signature: ByteArray): ByteArray {
        val (r, s) = if (signature.size == 64) {
            BigInteger(1, signature.copyOfRange(0, 32)) to BigInteger(1, signature.copyOfRange(32, 64))
        } else {
            parseDer(signature)
        }
        if (r.signum() <= 0 || r >= n || s.signum() <= 0 || s >= n) throw RequestSigningException("signature out of range")
        val low = if (s > halfN) n.subtract(s) else s
        return fixed32(r) + fixed32(low)
    }

    private fun verifiedRaw(key: RequestSigningKey, message: ByteArray, signature: ByteArray): ByteArray {
        val raw = rawLowS(signature)
        val ok = try {
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(key.publicKey)
                update(message)
                verify(toDer(raw))
            }
        } catch (_: Exception) {
            false
        }
        if (!ok) throw RequestSigningException("the signature does not verify with the key's public key")
        return raw
    }

    /** Strict DER `SEQUENCE { INTEGER r, INTEGER s }` with short-form lengths (a P-256 signature is at most 72 bytes). */
    private fun parseDer(der: ByteArray): Pair<BigInteger, BigInteger> {
        fun fail(): Nothing = throw RequestSigningException("not a DER or raw P-256 signature")
        if (der.size < 8 || der.size > 72 || der[0] != 0x30.toByte() || (der[1].toInt() and 0xFF) != der.size - 2) fail()
        var i = 2
        fun integer(): BigInteger {
            if (i + 2 > der.size || der[i] != 0x02.toByte()) fail()
            val length = der[i + 1].toInt() and 0xFF
            if (length < 1 || length > 33 || i + 2 + length > der.size) fail()
            val bytes = der.copyOfRange(i + 2, i + 2 + length)
            // Minimal encoding: no negative value, no superfluous leading zero.
            if (bytes[0] < 0) fail()
            if (length > 1 && bytes[0] == 0.toByte() && bytes[1] >= 0) fail()
            i += 2 + length
            return BigInteger(1, bytes)
        }
        val r = integer()
        val s = integer()
        if (i != der.size) fail()
        return r to s
    }

    private fun toDer(raw: ByteArray): ByteArray {
        fun integer(part: ByteArray): ByteArray {
            var start = 0
            while (start < part.size - 1 && part[start] == 0.toByte()) start++
            val trimmed = part.copyOfRange(start, part.size)
            val body = if (trimmed[0] < 0) byteArrayOf(0) + trimmed else trimmed
            return byteArrayOf(0x02, body.size.toByte()) + body
        }
        val content = integer(raw.copyOfRange(0, 32)) + integer(raw.copyOfRange(32, 64))
        return byteArrayOf(0x30, content.size.toByte()) + content
    }

    private fun fixed32(value: BigInteger): ByteArray {
        val bytes = value.toByteArray()
        return when {
            bytes.size == 32 -> bytes
            bytes.size == 33 && bytes[0] == 0.toByte() -> bytes.copyOfRange(1, 33)
            bytes.size < 32 -> ByteArray(32 - bytes.size) + bytes
            else -> throw RequestSigningException("value does not fit in 32 bytes")
        }
    }
}

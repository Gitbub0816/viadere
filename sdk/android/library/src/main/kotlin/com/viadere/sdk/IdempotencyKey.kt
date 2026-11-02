package com.viadere.sdk

import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Idempotency keys for `POST /v1/business/*`: the same key with the same request replays the original (`200`); the same key with another request is
 * `409 idempotency_conflict`. Same derivation as the Swift and TypeScript SDKs.
 */
public object IdempotencyKey {
    public const val MAX_LENGTH: Int = 128
    private val valid = Regex("^[A-Za-z0-9_.:-]{1,128}$")
    private val random = SecureRandom()

    public fun isValid(key: String): Boolean = valid.matches(key)

    private fun clean(prefix: String): String = prefix.filter { it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it in "_.:-" }.take(40)

    /** A fresh random key (128 bits). Persist it before sending so a crash-and-retry reuses it. */
    public fun generate(prefix: String? = null): String {
        val bytes = ByteArray(16).also(random::nextBytes)
        val hex = bytes.joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }
        val cleaned = prefix?.let(::clean).orEmpty()
        return if (cleaned.isEmpty()) hex else "$cleaned-$hex"
    }

    /**
     * A stable key derived from the business object being acted on (a request id, an order id): every retry of the same logical operation produces the
     * same key without storing anything. The parts are length-prefixed, so `["ab","c"]` and `["a","bc"]` differ.
     */
    public fun deterministic(namespace: String, parts: List<String>): String {
        val digest = MessageDigest.getInstance("SHA-256")
        for (part in listOf(namespace) + parts) {
            val bytes = part.toByteArray(Charsets.UTF_8)
            digest.update("${bytes.size}:".toByteArray(Charsets.UTF_8))
            digest.update(bytes)
        }
        val hex = digest.digest().joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }.take(40)
        val ns = clean(namespace)
        return if (ns.isEmpty()) hex else "$ns-$hex"
    }
}

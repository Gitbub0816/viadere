package com.viadere.sdk

/** One problem found in a request: the field and a code, like the server's `422 validation_failed` details. */
public data class Problem(val field: String, val code: String)

/** `destination` of a create request. */
public data class Destination(
    val linkMode: LinkMode,
    val url: String? = null,
    /** Compact `viadere-destination+jws` (ADR-0031 section 3). */
    val signature: String? = null,
    val linkClientId: String? = null,
    val returnUrl: String? = null,
    val codeChallenge: String? = null,
    /** Only `S256` exists. */
    val codeChallengeMethodS256: Boolean = false,
)

public data class OtpSpec(val code: String, val codeKind: CodeKind)

/**
 * The body of `POST /v1/business/auth-deliveries`. **The tenant is your API key's business, never a field of the payload**: there is no `tenant_id`
 * and no `audience` here, and the server answers `422` if a body carries one. Build it on **your server**; an API key never belongs in an app.
 */
public data class AuthDeliveryCreateRequest(
    val method: Method,
    /** Unique per tenant: `[A-Za-z0-9_.:-]{1,128}`. */
    val requestId: String,
    val subjectRef: String,
    val purpose: Purpose,
    /** A Viadere-owned template id, for example `auth.sign_in_link.v1`. */
    val template: String,
    /** Only keys the template declares; no URL, e-mail address or phone number. */
    val variables: Map<String, String> = emptyMap(),
    val destination: Destination? = null,
    val otp: OtpSpec? = null,
    val correlationId: String? = null,
    val clientTransactionRef: String? = null,
    /** 60 to 86400. */
    val expiresInSeconds: Int? = null,
    val channels: List<Channel>? = null,
    val fallbackEmail: String? = null,
    /** Opaque value from your own initiating session (class T, never shown). */
    val sessionHandle: String? = null,
    val callbackWebhookId: String? = null,
) {
    /** Checks the request against the contract (the same rules the server applies) and returns every problem; empty means valid. */
    public fun validate(): List<Problem> {
        val problems = ArrayList<Problem>()
        if (!Ids.isRequestId(requestId)) problems += Problem("request_id", "invalid_format")
        if (!Ids.isSubjectRef(subjectRef)) problems += Problem("subject_ref", "invalid_format")
        if (template.isEmpty()) problems += Problem("template", "required")
        for ((k, v) in variables) if (v.length !in 1..60) problems += Problem("variables.$k", "invalid_length")
        destination?.let { d ->
            if ((d.url?.length ?: 0) > 2048) problems += Problem("destination.url", "too_long")
            if ((d.signature?.length ?: 0) > 2048) problems += Problem("destination.signature", "too_long")
        }
        otp?.let { if (!OTP_CODE.matches(it.code)) problems += Problem("otp.code", "invalid_format") }
        if ((correlationId?.length ?: 0) > 128) problems += Problem("correlation_id", "too_long")
        if ((clientTransactionRef?.length ?: 0) > 128) problems += Problem("client_transaction_ref", "too_long")
        expiresInSeconds?.let { if (it !in 60..86400) problems += Problem("expires_in_seconds", "out_of_range") }
        sessionHandle?.let { if (!SESSION_HANDLE.matches(it)) problems += Problem("session_handle", "invalid_format") }
        callbackWebhookId?.let { if (!UUID.matches(it)) problems += Problem("callback.webhook_id", "invalid_format") }
        return problems
    }

    /** The JSON body. Throws `IllegalArgumentException` for an invalid request, so nothing malformed is ever sent. */
    public fun toJson(): String {
        val problems = validate()
        require(problems.isEmpty()) { "Request does not match the contract: " + problems.joinToString { "${it.field} (${it.code})" } }
        val o = LinkedHashMap<String, Any?>()
        o["method"] = method.wire
        o["request_id"] = requestId
        o["subject_ref"] = subjectRef
        o["purpose"] = purpose.wire
        o["template"] = template
        if (variables.isNotEmpty()) o["variables"] = variables
        destination?.let { d ->
            val m = LinkedHashMap<String, Any?>()
            m["link_mode"] = d.linkMode.wire
            d.url?.let { m["url"] = it }
            d.signature?.let { m["signature"] = it }
            d.linkClientId?.let { m["link_client_id"] = it }
            d.returnUrl?.let { m["return_url"] = it }
            d.codeChallenge?.let { m["code_challenge"] = it }
            if (d.codeChallengeMethodS256) m["code_challenge_method"] = "S256"
            o["destination"] = m
        }
        otp?.let { o["otp"] = mapOf("code" to it.code, "code_kind" to it.codeKind.wire) }
        correlationId?.let { o["correlation_id"] = it }
        clientTransactionRef?.let { o["client_transaction_ref"] = it }
        expiresInSeconds?.let { o["expires_in_seconds"] = it }
        channels?.let { o["channels"] = it.map(Channel::wire) }
        fallbackEmail?.let { o["fallback"] = mapOf("email" to mapOf("address" to it)) }
        sessionHandle?.let { o["session_handle"] = it }
        callbackWebhookId?.let { o["callback"] = mapOf("webhook_id" to it) }
        val json = StrictJson.write(o)
        require(json.toByteArray(Charsets.UTF_8).size <= MAX_BODY_BYTES) { "Request body is over 16 KiB" }
        return json
    }

    private companion object {
        const val MAX_BODY_BYTES = 16 * 1024
        val OTP_CODE = Regex("^[0-9A-Z]{4,10}$")
        val SESSION_HANDLE = Regex("^[A-Za-z0-9_-]{1,64}$")
        val UUID = Regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
    }
}

/** The body of `POST .../complete`: report **your own** verification outcome. */
public fun completeRequestJson(outcome: CompleteOutcome): String = StrictJson.write(mapOf("outcome" to outcome.wire))

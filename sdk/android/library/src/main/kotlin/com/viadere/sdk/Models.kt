package com.viadere.sdk

// Contract models for the Viadere authentication-delivery API (`contracts/openapi/auth-delivery-v1.yaml`, ADR-0020). Kept in lock-step with the
// contract: `ContractParityTest` fails when an enum drifts. Viadere is a transport: OPENED is never authentication success.

/** The wire form of an enum member. */
public interface WireValue {
    public val wire: String
}

public enum class Method(override val wire: String) : WireValue {
    MagicLink("magic_link"), Otp("otp"), Notice("notice");

    public companion object {
        public fun fromWire(value: String): Method? = entries.firstOrNull { it.wire == value }
    }
}

public enum class Purpose(override val wire: String) : WireValue {
    SignIn("sign_in"), StepUp("step_up"), VerifyContact("verify_contact"), AccountNotice("account_notice");

    public companion object {
        public fun fromWire(value: String): Purpose? = entries.firstOrNull { it.wire == value }
    }
}

/** There is no `sms`. `email` is refused until the email-fallback gate (ADR-0020 section 7) is met. */
public enum class Channel(override val wire: String) : WireValue {
    Push("push"), Inbox("inbox"), Email("email");

    public companion object {
        public fun fromWire(value: String): Channel? = entries.firstOrNull { it.wire == value }
    }
}

public enum class Status(override val wire: String) : WireValue {
    Created("created"), Validated("validated"), Queued("queued"), Sent("sent"), Delivered("delivered"), Opened("opened"),
    Completed("completed"), Expired("expired"), Cancelled("cancelled"), Denied("denied"), Failed("failed");

    /** After a terminal status nothing changes any more. */
    public val isTerminal: Boolean get() = this == Completed || this == Expired || this == Cancelled || this == Denied || this == Failed

    public companion object {
        public fun fromWire(value: String): Status? = entries.firstOrNull { it.wire == value }
    }
}

public enum class CodeKind(override val wire: String) : WireValue { Otp("otp"), Totp("totp") }

public enum class LinkMode(override val wire: String) : WireValue { Business("business"), Viadere("viadere") }

public enum class CompleteOutcome(override val wire: String) : WireValue { Succeeded("succeeded"), Failed("failed") }

/** The `auth.delivery.*` event types of the opaque webhook envelope. */
public enum class WebhookEventType(override val wire: String) : WireValue {
    Created("auth.delivery.created"), Sent("auth.delivery.sent"), Delivered("auth.delivery.delivered"), Opened("auth.delivery.opened"),
    Completed("auth.delivery.completed"), Failed("auth.delivery.failed"), Denied("auth.delivery.denied"), Cancelled("auth.delivery.cancelled"),
    Expired("auth.delivery.expired");

    /** `opened` does not end a delivery: only the business's own `complete` does. */
    public val endsDelivery: Boolean get() = this == Completed || this == Failed || this == Denied || this == Cancelled || this == Expired

    public companion object {
        public fun fromWire(value: String): WebhookEventType? = entries.firstOrNull { it.wire == value }
    }
}

/** Identifier formats of the contract. */
public object Ids {
    private val deliveryId = Regex("^adl_[A-Za-z0-9_-]{22}$")
    private val subjectRef = Regex("^sub_[A-Za-z0-9_-]{43}$")
    private val requestId = Regex("^[A-Za-z0-9_.:-]{1,128}$")
    private val eventId = Regex("^evt_[A-Za-z0-9_-]{1,64}$")
    private val tenantId = Regex("^[A-Za-z0-9_-]{1,64}$")

    public fun isDeliveryId(value: String): Boolean = deliveryId.matches(value)
    public fun isSubjectRef(value: String): Boolean = subjectRef.matches(value)
    public fun isRequestId(value: String): Boolean = requestId.matches(value)
    public fun isEventId(value: String): Boolean = eventId.matches(value)
    public fun isTenantId(value: String): Boolean = tenantId.matches(value)
}

/** The opaque webhook envelope (`contracts/schemas/auth-delivery-event-v1.schema.json`): ids, type, version, tenant and time. No result, no secret. */
public data class AuthDeliveryEnvelope(
    val id: String,
    val type: WebhookEventType,
    val tenantId: String,
    /** The delivery id: fetch the state from your server with `GET /v1/business/auth-deliveries/{requestId}`. */
    val requestId: String,
    val occurredAt: String,
) {
    public companion object {
        public const val VERSION: String = "2026-10-27"

        /** Strictly decodes an envelope, or returns `null`: no unknown member, the exact version, well-formed ids, `result_ref` absent or null. */
        public fun decode(body: ByteArray): AuthDeliveryEnvelope? {
            val parsed = try {
                StrictJson.parse(String(body, Charsets.UTF_8))
            } catch (_: StrictJson.ParseException) {
                return null
            }
            @Suppress("UNCHECKED_CAST")
            val o = parsed as? Map<String, Any?> ?: return null
            val allowed = setOf("id", "type", "version", "tenant_id", "request_id", "occurred_at", "result_ref")
            if (!allowed.containsAll(o.keys) || o["result_ref"] != null) return null
            val id = o["id"] as? String ?: return null
            val type = (o["type"] as? String)?.let(WebhookEventType::fromWire) ?: return null
            val tenant = o["tenant_id"] as? String ?: return null
            val request = o["request_id"] as? String ?: return null
            val at = o["occurred_at"] as? String ?: return null
            if (o["version"] != VERSION || !Ids.isEventId(id) || !Ids.isTenantId(tenant) || !Ids.isDeliveryId(request) || !isRfc3339(at)) return null
            return AuthDeliveryEnvelope(id, type, tenant, request, at)
        }

        private val rfc3339 = Regex("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[+-]\\d{2}:\\d{2})$")
        private fun isRfc3339(value: String): Boolean = rfc3339.matches(value)
    }
}

/** One entry of a delivery's history. */
public data class AuthDeliveryEvent(val status: Status, val at: String, val reason: String?)

/** The business view of a delivery (`GET /v1/business/auth-deliveries/{id}`). Never a secret. */
public data class AuthDeliveryView(
    val id: String,
    val requestId: String,
    val method: Method,
    val purpose: Purpose,
    val status: Status,
    val expiresAt: String,
    val createdAt: String,
    val correlationId: String?,
    val clientTransactionRef: String?,
    val reason: String?,
    val events: List<AuthDeliveryEvent>,
) {
    public companion object {
        /** Decodes the JSON of a server answer, or returns `null` when it is not an auth delivery. */
        public fun decode(json: String): AuthDeliveryView? {
            val parsed = try {
                StrictJson.parse(json)
            } catch (_: StrictJson.ParseException) {
                return null
            }
            @Suppress("UNCHECKED_CAST")
            val o = parsed as? Map<String, Any?> ?: return null
            val id = o["id"] as? String ?: return null
            if (!Ids.isDeliveryId(id)) return null
            val events = (o["events"] as? List<*>)?.map { e ->
                @Suppress("UNCHECKED_CAST")
                val m = e as? Map<String, Any?> ?: return null
                AuthDeliveryEvent((m["status"] as? String)?.let(Status::fromWire) ?: return null, m["at"] as? String ?: return null, m["reason"] as? String)
            } ?: emptyList()
            return AuthDeliveryView(
                id = id,
                requestId = o["request_id"] as? String ?: return null,
                method = (o["method"] as? String)?.let(Method::fromWire) ?: return null,
                purpose = (o["purpose"] as? String)?.let(Purpose::fromWire) ?: return null,
                status = (o["status"] as? String)?.let(Status::fromWire) ?: return null,
                expiresAt = o["expires_at"] as? String ?: return null,
                createdAt = o["created_at"] as? String ?: return null,
                correlationId = o["correlation_id"] as? String,
                clientTransactionRef = o["client_transaction_ref"] as? String,
                reason = o["reason"] as? String,
                events = events,
            )
        }
    }
}

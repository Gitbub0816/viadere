package com.viadere.sdk

import java.net.InetAddress

/** The `/24` of an IPv4 or the `/64` of an IPv6 address (an IPv4-mapped IPv6 counts as its IPv4); `"unknown"` for a missing or invalid address. */
public fun networkPrefix(address: String?): String {
    val text = address?.trim().orEmpty()
    // Only literal addresses: a host name would trigger a DNS lookup.
    val literal = Regex("^[0-9A-Fa-f:.%]+$").matches(text) && (text.contains(':') || Regex("^\\d{1,3}(\\.\\d{1,3}){3}$").matches(text))
    if (!literal) return "unknown"
    val bytes = try {
        InetAddress.getByName(text.substringBefore('%')).address
    } catch (_: Exception) {
        return "unknown"
    }
    return if (bytes.size == 4) {
        "${bytes[0].toInt() and 0xFF}.${bytes[1].toInt() and 0xFF}.${bytes[2].toInt() and 0xFF}.0/24"
    } else {
        (0 until 4).joinToString(":", postfix = "::/64") { (((bytes[2 * it].toInt() and 0xFF) shl 8) or (bytes[2 * it + 1].toInt() and 0xFF)).toString(16) }
    }
}

/** Thrown when more than `maxOpen` deliveries are already open for this account and client network prefix. Nothing was sent. */
public class ThrottledException(public val retryAfterSeconds: Long) : Exception("Too many open deliveries for this account and network; retry in about ${retryAfterSeconds}s.")

/**
 * Per-requester throttle (STAGE1_A2_REV3_CHECK condition C-14, ADR-0020 revision 3.1). Viadere never refuses or cancels a delivery because of a
 * per-customer count and cannot see who started a sign-in; you can. Keep **at most [maxOpen] (3) open deliveries per account and client network
 * prefix** and refuse the next one before sending it. Use it on the server that calls `POST /v1/business/auth-deliveries`:
 *
 * ```
 * val slot = throttle.reserve(subjectRef, clientIp)          // throws ThrottledException
 * try { val view = createDelivery(...); throttle.confirm(slot, view.id, expiresAtMillis, subjectRef, clientIp) }
 * catch (e: Exception) { throttle.release(slot); throw e }
 * // later: throttle.observe(envelope.type, envelope.requestId) for each verified webhook, throttle.release(deliveryId) when you cancel or complete
 * ```
 *
 * The state is in process memory: with several server processes the cap is per process.
 */
public class RequesterThrottle(
    public val maxOpen: Int = 3,
    private val provisionalSeconds: Long = 600,
    private val clockMillis: () -> Long = System::currentTimeMillis,
) {
    private val byKey = HashMap<String, MutableMap<String, Long>>()
    private val keyOf = HashMap<String, String>()
    private var provisional = 0L

    init {
        require(maxOpen >= 1) { "maxOpen must be positive" }
    }

    /** Takes a slot before a create call or throws [ThrottledException]. Returns the provisional slot id. */
    @Synchronized
    public fun reserve(subjectRef: String, clientAddress: String?): String {
        val now = clockMillis()
        val key = key(subjectRef, clientAddress)
        val slots = byKey[key]
        slots?.entries?.removeAll { (id, expires) -> (expires <= now).also { gone -> if (gone) keyOf.remove(id) } }
        val open = slots?.values.orEmpty()
        if (open.size >= maxOpen) throw ThrottledException(maxOf(1L, (open.min() - now + 999) / 1000))
        val slot = "provisional:${++provisional}"
        add(key, slot, now + provisionalSeconds * 1000)
        return slot
    }

    /** Binds a provisional slot to the delivery the API created. A replay of a known delivery does not take a second slot. */
    @Synchronized
    public fun confirm(slot: String, deliveryId: String, expiresAtMillis: Long, subjectRef: String, clientAddress: String?) {
        remove(slot)
        if (keyOf.containsKey(deliveryId)) return
        add(key(subjectRef, clientAddress), deliveryId, expiresAtMillis)
    }

    /** Frees a provisional slot after a failed call, or a delivery that ended. */
    @Synchronized
    public fun release(idOrSlot: String) {
        remove(idOrSlot)
    }

    /** Frees the slot when a verified webhook says the delivery ended. `opened` does not end it: only your `complete` does. */
    public fun observe(type: WebhookEventType, deliveryId: String) {
        if (type.endsDelivery) release(deliveryId)
    }

    private fun key(subjectRef: String, clientAddress: String?): String = "$subjectRef|${networkPrefix(clientAddress)}"

    private fun add(key: String, id: String, expires: Long) {
        byKey.getOrPut(key) { HashMap() }[id] = expires
        keyOf[id] = key
    }

    private fun remove(id: String) {
        val key = keyOf.remove(id) ?: return
        val slots = byKey[key] ?: return
        slots.remove(id)
        if (slots.isEmpty()) byKey.remove(key)
    }
}

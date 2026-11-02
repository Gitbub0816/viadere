package com.viadere.sdk

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

private val root = File(System.getProperty("viadere.repoRoot")!!)

@Suppress("UNCHECKED_CAST")
private fun readJson(relative: String): Map<String, Any?> = StrictJson.parse(File(root, relative).readText()) as Map<String, Any?>

@Suppress("UNCHECKED_CAST")
private fun cases(relative: String): List<Map<String, Any?>> = readJson(relative)["cases"] as List<Map<String, Any?>>

class VectorsTest {
    @Test fun positiveVectorsReproduce() {
        val all = cases("docs/protocol/vectors/webhook-v2.json")
        assertEquals(3, all.size)
        for (c in all) {
            val body = (c["body"] as String).toByteArray()
            val ctx = SignatureContext(c["method"] as String, c["host"] as String, c["path_and_query"] as String, c["event_id"] as String, c["tenant_id"] as String)
            val t = (c["t"] as Long)
            val kid = c["kid"] as String
            assertEquals(c["content_digest"], WebhookSignatureV2.contentDigest(body))
            assertEquals(c["string_to_sign"], WebhookSignatureV2.stringToSign(ctx, t, kid, body))
            assertEquals(c["v2"], "$kid:" + WebhookSignatureV2.mac(c["secret"] as String, ctx, t, kid, body))
        }
    }

    @Test fun negativeVectorsReachTheExpectedOutcome() {
        val all = cases("docs/protocol/vectors/webhook-v2-negative.json")
        assertTrue(all.size >= 30)
        for (c in all) {
            @Suppress("UNCHECKED_CAST")
            val headers = (c["headers"] as Map<String, String>).mapValues { listOf(it.value) }
            @Suppress("UNCHECKED_CAST")
            val keys = c["keys"] as Map<String, String>
            val now = (c["now"] as Long) * 1000
            val verifier = WebhookVerifier(c["endpoint"] as String, c["tenant_id"] as String, keys, replayStore = WebhookReplayStore.Disabled, clockMillis = { now })
            val got = try {
                verifier.verify(headers, (c["body"] as String).toByteArray())
                "ok"
            } catch (e: WebhookVerificationException) {
                e.failure.wire
            }
            assertEquals(c["name"] as String, c["expect"], got)
        }
    }
}

class VerifierTest {
    private val endpoint = "https://hooks.example.com/viadere/events"
    private val keys = mapOf("whk_1a2b3c4d_v1" to "whsec_testsecret_one")
    private val base = cases("docs/protocol/vectors/webhook-v2.json")[0]
    private val t = 1793620800L

    private fun delivery(body: String = base["body"] as String): Pair<Map<String, List<String>>, ByteArray> {
        val bytes = body.toByteArray()
        val ctx = SignatureContext("POST", "hooks.example.com", "/viadere/events", base["event_id"] as String, base["tenant_id"] as String)
        val sig = WebhookSignatureV2.signatureHeader(listOf("whk_1a2b3c4d_v1" to "whsec_testsecret_one"), ctx, bytes, t)!!
        return mapOf(
            "viadere-signature" to listOf(sig), "Viadere-Event-Id" to listOf(base["event_id"] as String), "Viadere-Tenant" to listOf(base["tenant_id"] as String),
            "Content-Digest" to listOf(WebhookSignatureV2.contentDigest(bytes)),
        ) to bytes
    }

    private fun verifier(store: WebhookReplayStore? = null) =
        if (store == null) WebhookVerifier(endpoint, base["tenant_id"] as String, keys, clockMillis = { t * 1000 })
        else WebhookVerifier(endpoint, base["tenant_id"] as String, keys, replayStore = store, clockMillis = { t * 1000 })

    private fun failure(block: () -> Unit): WebhookFailure? = try { block(); null } catch (e: WebhookVerificationException) { e.failure }

    @Test fun decodesTheEnvelope() {
        val (h, b) = delivery()
        val v = verifier().verifyEnvelope(h, b)
        assertEquals(WebhookEventType.Opened, v.envelope.type)
        assertEquals("adl_AAAAAAAAAAAAAAAAAAAAAA", v.envelope.requestId)
    }

    @Test fun replayStoreIsOnByDefault() {
        val verifier = verifier()
        val (h, b) = delivery()
        verifier.verifyEnvelope(h, b)
        val f = assertFails { verifier.verifyEnvelope(h, b) }
        assertEquals(WebhookFailure.DuplicateEvent, f)
        assertEquals(200, f.suggestedStatus)
    }

    @Test fun optOutIsExplicitAndReleaseLetsARetryThrough() {
        val off = verifier(WebhookReplayStore.Disabled)
        val (h, b) = delivery()
        off.verify(h, b); off.verify(h, b)
        val on = verifier()
        val v = on.verify(h, b)
        on.release(v.eventId)
        on.verify(h, b)
    }

    @Test fun malformedBodyDoesNotBurnTheId() {
        val verifier = verifier()
        val bad = (base["body"] as String).replace("}", ",\"extra\":\"x\"}")
        val (hb, bb) = delivery(bad)
        assertEquals(WebhookFailure.MalformedBody, assertFails { verifier.verifyEnvelope(hb, bb) })
        val (h, b) = delivery()
        verifier.verifyEnvelope(h, b)
    }

    @Test fun repeatedSignatureHeaderIsAmbiguous() {
        val (h, b) = delivery()
        val twice = h + ("Viadere-Signature" to listOf(h["viadere-signature"]!![0]))
        assertEquals(WebhookFailure.MalformedSignature, assertFails { verifier().verify(twice, b) })
    }

    @Test fun envelopeDecodingIsStrict() {
        val ok = base["body"] as String
        assertEquals(null, null)
        assertTrue(AuthDeliveryEnvelope.decode(ok.toByteArray()) != null)
        assertNull(AuthDeliveryEnvelope.decode(ok.replace("2026-10-27", "2099-01-01").toByteArray()))
        assertNull(AuthDeliveryEnvelope.decode(ok.replace("}", ",\"result_ref\":\"x\"}").toByteArray()))
        assertNull(AuthDeliveryEnvelope.decode(ok.replace("\"id\":\"evt_0f6c1d2e3a4b4c5d8e9f0a1b2c3d4e5f\",", "\"id\":\"evt_0f6c1d2e3a4b4c5d8e9f0a1b2c3d4e5f\",\"id\":\"evt_x\",").toByteArray()))
        assertNull(AuthDeliveryEnvelope.decode("[]".toByteArray()))
    }

    @Test fun badConstructionAndNoSecretInToString() {
        for (block in listOf<() -> Any>(
            { WebhookVerifier("not a url", "ten_x", keys) },
            { WebhookVerifier(endpoint, "ten_x", emptyMap()) },
            { WebhookVerifier(endpoint, "ten_x", mapOf("Bad Kid" to "s")) },
        )) {
            try { block(); fail("expected IllegalArgumentException") } catch (_: IllegalArgumentException) {}
        }
        assertFalse(verifier().toString().contains("whsec_"))
    }

    @Test fun inMemoryStoreExpiresFromFirstReceipt() {
        val store = InMemoryWebhookReplayStore()
        val h = 3_600_000L
        assertTrue(store.recordFirstReceipt("evt_a", 0))
        assertFalse(store.recordFirstReceipt("evt_a", 71 * h))
        assertTrue(store.recordFirstReceipt("evt_a", 72 * h + 1))
        val small = InMemoryWebhookReplayStore(maxEntries = 3)
        for (i in 0 until 10) small.recordFirstReceipt("evt_$i", i.toLong())
        assertEquals(3, small.size)
    }

    private fun assertFails(block: () -> Unit): WebhookFailure = failure(block) ?: throw AssertionError("expected a webhook failure")
}

class ThrottleAndKeysTest {
    private val subject = "sub_" + "A".repeat(43)

    @Test fun refusesTheFourthOpenDeliveryPerAccountAndPrefix() {
        val th = RequesterThrottle()
        for (i in 0 until 3) {
            val slot = th.reserve(subject, "203.0.113.7")
            th.confirm(slot, "adl_$i", System.currentTimeMillis() + 600_000, subject, "203.0.113.7")
        }
        try { th.reserve(subject, "203.0.113.200"); fail("expected throttle") } catch (e: ThrottledException) { assertTrue(e.retryAfterSeconds >= 1) }
        th.reserve(subject, "198.51.100.1") // another prefix
        th.reserve("sub_" + "B".repeat(43), "203.0.113.7") // another account
        th.observe(WebhookEventType.Opened, "adl_0")
        try { th.reserve(subject, "203.0.113.7"); fail("opened does not free a slot") } catch (_: ThrottledException) {}
        th.observe(WebhookEventType.Denied, "adl_0")
        th.reserve(subject, "203.0.113.7")
    }

    @Test fun slotsExpireAndFailedCallsRelease() {
        var now = 1_000_000L
        val th = RequesterThrottle(maxOpen = 1, clockMillis = { now })
        val slot = th.reserve(subject, null)
        th.release(slot)
        val s2 = th.reserve(subject, null)
        th.confirm(s2, "adl_x", now + 60_000, subject, null)
        try { th.reserve(subject, null); fail() } catch (_: ThrottledException) {}
        now += 61_000
        th.reserve(subject, null)
    }

    @Test fun prefixes() {
        assertEquals("203.0.113.0/24", networkPrefix("203.0.113.7"))
        assertEquals("203.0.113.0/24", networkPrefix("::ffff:203.0.113.7"))
        assertEquals("2001:db8:1:2::/64", networkPrefix("2001:db8:1:2:3:4:5:6"))
        assertEquals("unknown", networkPrefix("example.com"))
        assertEquals("unknown", networkPrefix(null))
    }

    @Test fun idempotencyKeys() {
        assertTrue(Regex("^authdl-[0-9a-f]{40}$").matches(IdempotencyKey.deterministic("authdl", listOf("req-1"))))
        assertNotEquals(IdempotencyKey.deterministic("n", listOf("ab", "c")), IdempotencyKey.deterministic("n", listOf("a", "bc")))
        assertTrue(IdempotencyKey.isValid(IdempotencyKey.generate("a b!c")))
        assertFalse(IdempotencyKey.isValid("has space"))
    }

    @Test fun createRequestValidationAndJson() {
        val ok = AuthDeliveryCreateRequest(Method.MagicLink, "req-1", subject, Purpose.SignIn, "auth.sign_in_link.v1",
            destination = Destination(LinkMode.Business, url = "https://login.example.com/m/abc"), channels = listOf(Channel.Push))
        assertEquals(emptyList<Problem>(), ok.validate())
        val parsed = StrictJson.parse(ok.toJson()) as Map<*, *>
        assertEquals("magic_link", parsed["method"])
        assertFalse(parsed.containsKey("tenant_id"))
        val bad = ok.copy(requestId = "has space", expiresInSeconds = 5, sessionHandle = "bad handle")
        assertEquals(setOf("request_id", "expires_in_seconds", "session_handle"), bad.validate().map { it.field }.toSet())
        try { bad.toJson(); fail() } catch (_: IllegalArgumentException) {}
    }
}

class ContractParityTest {
    private val yaml = File(root, "contracts/openapi/auth-delivery-v1.yaml").readLines()

    private fun enumAfter(schema: String): List<String> {
        val start = yaml.indexOf("    $schema:")
        assertTrue(schema, start >= 0)
        val line = yaml.drop(start).first { it.contains("enum: [") }
        return line.substringAfter("enum: [").substringBefore("]").split(",").map { it.trim() }
    }

    @Test fun enumsMatchTheContract() {
        assertEquals(Method.entries.map { it.wire }, enumAfter("Method"))
        assertEquals(Purpose.entries.map { it.wire }, enumAfter("Purpose"))
        assertEquals(Channel.entries.map { it.wire }, enumAfter("Channel"))
        assertEquals(Status.entries.map { it.wire }, enumAfter("Status"))
    }

    @Test fun eventTypesAndVersionMatchTheSchema() {
        @Suppress("UNCHECKED_CAST")
        val props = readJson("contracts/schemas/auth-delivery-event-v1.schema.json")["properties"] as Map<String, Map<String, Any?>>
        assertEquals(WebhookEventType.entries.map { it.wire }, props["type"]!!["enum"])
        assertEquals(AuthDeliveryEnvelope.VERSION, props["version"]!!["const"])
    }

    @Test fun createRequestMembersMatchTheSchema() {
        @Suppress("UNCHECKED_CAST")
        val props = (readJson("contracts/schemas/auth-delivery-create-request-v1.schema.json")["properties"] as Map<String, Any?>).keys
        val json = StrictJson.parse(
            AuthDeliveryCreateRequest(Method.Otp, "r", "sub_" + "A".repeat(43), Purpose.StepUp, "t", mapOf("a" to "b"),
                Destination(LinkMode.Viadere, "u", "s", "c", "r", "ch", true), OtpSpec("123456", CodeKind.Totp), "c", "x", 60, listOf(Channel.Inbox), "a@b.c", "h",
                "11111111-2222-3333-4444-555555555555").toJson(),
        ) as Map<*, *>
        assertEquals(props, json.keys.map { it as String }.toSet())
    }
}

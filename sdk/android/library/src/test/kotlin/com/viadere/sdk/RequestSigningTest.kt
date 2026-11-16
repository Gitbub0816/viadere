package com.viadere.sdk

import java.io.File
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

// RFC 9421 request signatures, Viadere profile (docs/SECURITY.md section 2.112), against the cross-language vectors generated independently in
// Python (docs/protocol/vectors/http-signatures-v1.json): every positive case byte for byte (signature base, Signature-Input, Signature,
// Content-Digest), and real signatures checked with the JDK's own P1363 verifier over a base this test writes out by hand.

private val repoRoot = File(System.getProperty("viadere.repoRoot")!!)

@Suppress("UNCHECKED_CAST")
private val vectors = StrictJson.parse(File(repoRoot, "docs/protocol/vectors/http-signatures-v1.json").readText()) as Map<String, Any?>

@Suppress("UNCHECKED_CAST")
private val positive = vectors["positive"] as List<Map<String, Any?>>

@Suppress("UNCHECKED_CAST")
private val vectorKey = (vectors["keys"] as List<Map<String, Any?>>)[0]

private val p256: ECParameterSpec =
    AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }.getParameterSpec(ECParameterSpec::class.java)
private val order = BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)

private fun publicKey(base64url: String): ECPublicKey {
    val raw = Base64.getUrlDecoder().decode(base64url)
    assertEquals(65, raw.size)
    val point = ECPoint(BigInteger(1, raw.copyOfRange(1, 33)), BigInteger(1, raw.copyOfRange(33, 65)))
    return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, p256)) as ECPublicKey
}

private fun vectorPrivateKey(): PrivateKey =
    KeyFactory.getInstance("EC").generatePrivate(ECPrivateKeySpec(BigInteger(vectors["signer_private_key_hex"] as String, 16), p256))

/** The JDK's own verifier for raw `r||s` (not the SDK's DER conversion). */
private fun verifiesRaw(key: ECPublicKey, message: ByteArray, raw: ByteArray): Boolean =
    Signature.getInstance("SHA256withECDSAinP1363Format").run {
        initVerify(key)
        update(message)
        verify(raw)
    }

private fun der(r: BigInteger, s: BigInteger): ByteArray {
    fun integer(v: BigInteger): ByteArray = v.toByteArray().let { byteArrayOf(0x02, it.size.toByte()) + it }
    val content = integer(r) + integer(s)
    return byteArrayOf(0x30, content.size.toByte()) + content
}

/** A key that returns fixed bytes: the vector's deterministic (RFC 6979) signature, so every header must match the vector exactly. */
private class FixedKey(override val publicKey: ECPublicKey, private val bytes: ByteArray, override val keyId: String = "vsk_0123456789abcdef") : RequestSigningKey {
    override fun sign(message: ByteArray): ByteArray = bytes
}

@Suppress("UNCHECKED_CAST")
private fun header(c: Map<String, Any?>, name: String): String? =
    ((c["request"] as Map<String, Any?>)["headers"] as List<List<String>>).firstOrNull { it[0] == name }?.get(1)

class RequestSigningVectorsTest {
    private val signable = positive.filter { it["name"] != "parameters_reordered_with_alg" }

    @Test fun thereAreFivePositiveVectorsAndTheProfileConstantsMatch() {
        assertEquals(5, positive.size)
        @Suppress("UNCHECKED_CAST")
        val profile = vectors["profile"] as Map<String, Any?>
        assertEquals(profile["tag"], RequestSigning.TAG)
        assertEquals(profile["algorithm"], RequestSigning.ALGORITHM)
        assertEquals(profile["body_components"], RequestSigning.BODY_COMPONENTS)
        assertEquals(profile["bodiless_components"], RequestSigning.BODILESS_COMPONENTS)
        assertEquals(profile["max_lifetime_seconds"], RequestSigning.MAX_LIFETIME_SECONDS)
    }

    @Test fun theSignatureBaseAndParametersReproduceByteForByte() {
        for (c in signable) {
            @Suppress("UNCHECKED_CAST")
            val request = c["request"] as Map<String, Any?>
            val body = (request["body"] as String).toByteArray(Charsets.UTF_8)
            val digest = if (body.isEmpty()) null else RequestSigning.contentDigest(body)
            assertEquals(c["name"] as String, c["content_digest"], digest)
            assertEquals(c["name"] as String, header(c, "Content-Digest"), digest)
            val components = if (body.isEmpty()) RequestSigning.BODILESS_COMPONENTS else RequestSigning.BODY_COMPONENTS
            val created = c["created"] as Long
            val params = RequestSigning.signatureParams(components, created, created + 300, c["keyid"] as String, c["nonce"] as String)
            assertEquals(c["name"] as String, c["signature_input"], "sig1=$params")
            val base = RequestSigning.signatureBase(request["method"] as String, "viadere.io", request["path_and_query"] as String, digest,
                                                    header(c, "Content-Type"), components, params)
            assertEquals(c["name"] as String, c["signature_base"], base)
        }
    }

    @Test fun signingReproducesEveryHeaderValueByteForByte() {
        val pub = publicKey(vectorKey["public_key"] as String)
        for (c in signable) {
            @Suppress("UNCHECKED_CAST")
            val request = c["request"] as Map<String, Any?>
            val rawSig = Base64.getUrlDecoder().decode(c["signature_raw_b64url"] as String)
            val r = BigInteger(1, rawSig.copyOfRange(0, 32))
            val s = BigInteger(1, rawSig.copyOfRange(32, 64))
            // Raw low S as given, DER low S, and DER high S (what a KMS may return): all fold to the vector's signature.
            for (returned in listOf(rawSig, der(r, s), der(r, order.subtract(s)))) {
                val body = (request["body"] as String).takeIf { it.isNotEmpty() }?.toByteArray(Charsets.UTF_8)
                val headers = RequestSigning.sign(FixedKey(pub, returned), request["method"] as String, "https://viadere.io" + request["path_and_query"],
                                                  body, header(c, "Content-Type"), created = c["created"] as Long, nonce = c["nonce"] as String)
                val name = c["name"] as String
                assertEquals(name, c["signature_input"], headers["Signature-Input"])
                assertEquals(name, c["signature"], headers["Signature"])
                assertEquals(name, c["content_digest"], headers["Content-Digest"])
                assertEquals(name, header(c, "Content-Type"), headers["Content-Type"])
                val expected = if (body == null) listOf("Signature-Input", "Signature") else listOf("Content-Type", "Content-Digest", "Signature-Input", "Signature")
                assertEquals(name, expected, headers.keys.toList())
            }
        }
    }

    @Test fun everyPositiveVectorSignatureVerifiesWithTheJdkOverItsBase() {
        val pub = publicKey(vectorKey["public_key"] as String)
        for (c in positive) {
            val raw = Base64.getUrlDecoder().decode(c["signature_raw_b64url"] as String)
            assertTrue(c["name"] as String, verifiesRaw(pub, (c["signature_base"] as String).toByteArray(Charsets.US_ASCII), raw))
            assertEquals(c["signature"], "sig1=:" + Base64.getEncoder().encodeToString(raw) + ":")
        }
    }
}

class RequestSigningTest {
    private val vectorPub = publicKey(vectorKey["public_key"] as String)
    private val vectorSigner = JcaRequestSigningKey("vsk_0123456789abcdef", vectorPrivateKey(), vectorPub)

    @Test fun theRegisteredPublicKeyFormMatchesTheVectorKey() {
        assertEquals(vectorKey["public_key"], RequestSigning.publicKeyBase64Url(vectorPub))
    }

    @Test fun aRealSignatureIsRawLowSAndVerifiesOverTheProfileBase() {
        val body = """{"a":1}""".toByteArray()
        val now = vectors["now"] as Long
        repeat(32) {
            // ECDSA in the JDK is randomized: 32 signatures make a high S (folded by the SDK) all but certain.
            val headers = RequestSigning.sign(vectorSigner, "post", "https://viadere.io/v1/business/auth-deliveries", body, created = now)
            val input = headers["Signature-Input"]!!
            assertTrue(input, Regex("""^sig1=\("@method" "@authority" "@path" "@query" "content-digest" "content-type"\);created=$now;expires=${now + 300};keyid="vsk_0123456789abcdef";nonce="[A-Za-z0-9_-]{22}";tag="viadere-api-v1"$""").matches(input))
            assertEquals("application/json", headers["Content-Type"])
            assertEquals("sha-256=:" + Base64.getEncoder().encodeToString(java.security.MessageDigest.getInstance("SHA-256").digest(body)) + ":", headers["Content-Digest"])
            val sig = headers["Signature"]!!
            assertTrue(sig.startsWith("sig1=:") && sig.endsWith(":"))
            val raw = Base64.getDecoder().decode(sig.removePrefix("sig1=:").removeSuffix(":"))
            assertEquals(64, raw.size)
            assertTrue("low S", BigInteger(1, raw.copyOfRange(32, 64)) <= order.shiftRight(1))
            val base = "\"@method\": POST\n\"@authority\": viadere.io\n\"@path\": /v1/business/auth-deliveries\n\"@query\": ?\n" +
                "\"content-digest\": ${headers["Content-Digest"]}\n\"content-type\": application/json\n\"@signature-params\": ${input.removePrefix("sig1=")}"
            assertTrue(verifiesRaw(vectorPub, base.toByteArray(Charsets.US_ASCII), raw))
        }
    }

    @Test fun aBodilessRequestSignsFourComponentsAndKeepsTheRawQuery() {
        val headers = RequestSigning.sign(vectorSigner, "GET", "https://Viadere.io:443/v1/business/interactions?limit=20&cursor=a%2Fb", created = 1_800_000_000,
                                          nonce = "cXdlcnR5dWlvcGFzZGZnaA")
        assertNull(headers["Content-Digest"])
        assertNull(headers["Content-Type"])
        val raw = Base64.getDecoder().decode(headers["Signature"]!!.removePrefix("sig1=:").removeSuffix(":"))
        val params = "(\"@method\" \"@authority\" \"@path\" \"@query\");created=1800000000;expires=1800000300;keyid=\"vsk_0123456789abcdef\";nonce=\"cXdlcnR5dWlvcGFzZGZnaA\";tag=\"viadere-api-v1\""
        assertEquals("sig1=$params", headers["Signature-Input"])
        val base = "\"@method\": GET\n\"@authority\": viadere.io\n\"@path\": /v1/business/interactions\n\"@query\": ?limit=20&cursor=a%2Fb\n\"@signature-params\": $params"
        assertTrue(verifiesRaw(vectorPub, base.toByteArray(Charsets.US_ASCII), raw))
        assertEquals("api.example.com:8443" to "/x?", RequestSigning.authorityAndTarget("https://API.example.com:8443/x?"))
        assertEquals("viadere.io" to "/", RequestSigning.authorityAndTarget("https://viadere.io"))
        // An empty body is a bodiless request (no Content-Digest is allowed then).
        val empty = RequestSigning.sign(vectorSigner, "POST", "https://viadere.io/v1/business/auth-deliveries/adl_AAAAAAAAAAAAAAAAAAAAAA/cancel", ByteArray(0))
        assertFalse(empty.containsKey("Content-Digest"))
        assertTrue(empty["Signature-Input"]!!.startsWith("sig1=(\"@method\" \"@authority\" \"@path\" \"@query\");"))
    }

    @Test fun nothingIsProducedWhenTheSignerIsBrokenOrUsesAnotherKey() {
        val other = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val brokenOutputs = listOf(ByteArray(64) { 1 }, ByteArray(64), ByteArray(63), ByteArray(0), byteArrayOf(0x30, 0x02, 0x02, 0x00),
                                   Signature.getInstance("SHA256withECDSA").run { initSign(other.private); update("x".toByteArray()); sign() })
        for (bytes in brokenOutputs) {
            try {
                RequestSigning.sign(FixedKey(vectorPub, bytes), "GET", "https://viadere.io/v1/business/auth-deliveries")
                fail("accepted a broken signer")
            } catch (_: RequestSigningException) {
            }
        }
        // A real key whose registered public key is another one.
        val mismatched = JcaRequestSigningKey("vsk_0123456789abcdef", other.private, vectorPub)
        try {
            RequestSigning.sign(mismatched, "GET", "https://viadere.io/v1/business/auth-deliveries")
            fail("accepted a signature by another key")
        } catch (_: RequestSigningException) {
        }
        // Non-minimal or trailing DER is refused, not reinterpreted.
        val raw = Base64.getUrlDecoder().decode(positive[0]["signature_raw_b64url"] as String)
        val good = der(BigInteger(1, raw.copyOfRange(0, 32)), BigInteger(1, raw.copyOfRange(32, 64)))
        assertArrayEquals(raw, RequestSigning.rawLowS(good))
        for (bad in listOf(good + byteArrayOf(0), good.copyOf().also { it[1] = (it[1] + 1).toByte() }, byteArrayOf(0x30, 0x06, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01))) {
            try {
                RequestSigning.rawLowS(bad)
                fail("accepted malformed DER")
            } catch (_: RequestSigningException) {
            }
        }
    }

    @Test fun invalidInputsAreRefusedBeforeSigning() {
        val calls = intArrayOf(0)
        val counting = object : RequestSigningKey {
            override val keyId = "vsk_0123456789abcdef"
            override val publicKey = vectorPub
            override fun sign(message: ByteArray): ByteArray { calls[0]++; return ByteArray(64) }
        }
        val cases: List<() -> Unit> = listOf(
            { RequestSigning.sign(FixedKey(vectorPub, ByteArray(64), keyId = "mine"), "GET", "https://viadere.io/x") },
            { RequestSigning.sign(counting, "GET", "https://viadere.io/x", nonce = "short") },
            { RequestSigning.sign(counting, "GET", "https://viadere.io/x", lifetimeSeconds = 301) },
            { RequestSigning.sign(counting, "GET", "https://viadere.io/x", lifetimeSeconds = 0) },
            { RequestSigning.sign(counting, "GET", "ftp://viadere.io/x") },
            { RequestSigning.sign(counting, "GET", "https://viadere.io/x#frag") },
            { RequestSigning.sign(counting, "GET", "https://user@viadere.io/x") },
            { RequestSigning.sign(counting, "GE T", "https://viadere.io/x") },
            { RequestSigning.sign(counting, "POST", "https://viadere.io/x", "é".toByteArray(), contentType = "application/jsön") },
            { JcaRequestSigningKey("vsk_short", vectorPrivateKey(), vectorPub) },
        )
        for (case in cases) {
            try {
                case()
                fail("accepted an invalid input")
            } catch (_: IllegalArgumentException) {
            }
        }
        assertEquals("the key is never asked to sign an invalid request", 0, calls[0])
        assertEquals(22, RequestSigning.newNonce().length)
        assertTrue(RequestSigning.isNonce(RequestSigning.newNonce()))
    }

    @Test fun theProofOfPossessionSignsTheConsolesMessage() {
        val proof = RequestSigning.signingKeyProof("1800000000.abc.def", vectorSigner)
        val raw = Base64.getUrlDecoder().decode(proof)
        assertEquals(64, raw.size)
        val message = listOf("viadere-request-signing-key-v1", "1800000000.abc.def", vectorKey["public_key"] as String).joinToString("\n")
        assertTrue(verifiesRaw(vectorPub, message.toByteArray(Charsets.UTF_8), raw))
    }
}

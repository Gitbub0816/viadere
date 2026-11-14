import assert from "node:assert/strict";
import { sign as nodeSign } from "node:crypto";
import { describe, it } from "node:test";
import {
  ApprovalEnrollmentSecret,
  DOMAINS,
  LinkSessionSecret,
  StatementVerificationError,
  base64urlDecode,
  base64urlEncode,
  buildLinkSessionLink,
  canonicalCode,
  canonicalJson,
  canonicalOrigin,
  checkLinkApprovalStatement,
  checkLinkStatementBinding,
  checkVerificationSessionResult,
  decodeSignature,
  displayCode,
  linkPseudonym,
  normalizeLowS,
  parseApprovalEnrollmentLink,
  parseCanonicalObject,
  parseLinkSessionLink,
  parseP256PublicKey,
  parseVerificationSessionLink,
  sha256Hex,
  signApprovalEnrollmentConfirmation,
  signEs256,
  signLinkConfirmation,
  statementDigest,
  verificationResultMatchesRef,
  verifyApprovalEnrollmentStatement,
  verifyConfirmation,
  verifyEs256,
  verifyLinkResult,
  verifyLinkStatement,
  verifyVerificationSessionResult,
  type JsonValue,
} from "../src/index.js";
import { BUSINESS_ID, SUBJECT_REF, UUID_2, newKey, readRepoJson, signStatement } from "./helpers.js";

type Signed = { kid: string; payload: string; publicKey: string; signature: string; signingInput: string };
const vector = readRepoJson<{
  approvalStatement: Signed; approvalStatementDigest: string; bindingTag: string; businessId: string; checkCode: string; code: string; confirmation: Signed; descriptor: Signed;
  link: string; linkDomain: string; pseudonym: string; result: Signed; sas: string; secret: string; sessionId: string; statement: Signed; statementDigest: string; subjectRef: string;
}>("docs/protocol/vectors/link-session-v1.json");

function code(expected: string) {
  return (e: unknown) => e instanceof StatementVerificationError && e.code === expected;
}

/** Re-encodes a statement with one payload member changed, keeping the old signature. */
function tamper<S extends { payload: string }>(signed: S, change: (o: Record<string, JsonValue>) => void): S {
  const o = JSON.parse(Buffer.from(signed.payload, "base64url").toString("utf8")) as Record<string, JsonValue>;
  change(o);
  return { ...signed, payload: Buffer.from(canonicalJson(o), "utf8").toString("base64url") };
}

describe("encodings (SECURITY.md 2.1, 2.2)", () => {
  it("base64url is strict: no padding, no standard alphabet", () => {
    assert.deepEqual([...base64urlDecode("AQID")!], [1, 2, 3]);
    assert.equal(base64urlDecode("AQID="), undefined);
    assert.equal(base64urlDecode("A+/D"), undefined);
    assert.equal(base64urlDecode("A"), undefined);
  });

  it("canonical JSON: sorted keys, the escapes, integers only", () => {
    assert.equal(canonicalJson({ b: 1, a: "x/\"\\\n\u0001é", c: [true, null] }), '{"a":"x/\\"\\\\\\n\\u0001é","b":1,"c":[true,null]}');
    assert.throws(() => canonicalJson({ a: 1.5 }), RangeError);
    const enc = (s: string) => Buffer.from(s, "utf8");
    assert.deepEqual({ ...parseCanonicalObject(enc('{"a":1,"b":"x"}')) }, { a: 1, b: "x" });
    for (const bad of ['{"b":1,"a":2}', '{"a": 1}', '{"a":1.0}', '{"a":1e2}', '{"a":-0}', '{"a":1,"a":1}', '{"a":"\\u0041"}', '{"a":9007199254740993}', "[1]", '{"a":1}\n']) {
      assert.equal(parseCanonicalObject(enc(bad)), undefined, bad);
    }
  });

  it("the vector's signing inputs are domain || canonical payload", () => {
    for (const [signed, domain] of [[vector.statement, DOMAINS.linkStatement], [vector.result, DOMAINS.linkResult], [vector.confirmation, DOMAINS.linkConfirmation], [vector.approvalStatement, DOMAINS.approvalEnrollment]] as const) {
      const payload = Buffer.from(signed.payload, "base64url").toString("utf8");
      assert.equal(domain + payload, signed.signingInput);
      assert.equal(canonicalJson(JSON.parse(payload) as JsonValue), payload);
      assert.equal(parseP256PublicKey(signed.publicKey)!.kid, signed.kid, "kid = base64url(SHA-256(SPKI))");
    }
  });

  it("ECDSA raw r||s: both S forms verify and normalise to one encoding; DER and other lengths are refused", async () => {
    const key = parseP256PublicKey(vector.statement.publicKey)!;
    const message = Buffer.from(vector.statement.signingInput, "utf8");
    assert.ok(verifyEs256(key, message, vector.statement.signature));
    const low = decodeSignature(vector.statement.signature)!;
    assert.equal(base64urlEncode(low), vector.statement.signature, "the vector is low-S");
    // The high-S twin (r, n - s) is a valid signature too: accepted, and folded back to the same canonical bytes.
    const n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
    const s = BigInt("0x" + Buffer.from(low.subarray(32)).toString("hex"));
    const high = Buffer.concat([Buffer.from(low.subarray(0, 32)), Buffer.from((n - s).toString(16).padStart(64, "0"), "hex")]);
    const highWire = base64urlEncode(high);
    assert.notEqual(highWire, vector.statement.signature);
    assert.ok(verifyEs256(key, message, highWire));
    assert.deepEqual(Buffer.from(normalizeLowS(high)), Buffer.from(low));
    // DER (what `crypto.sign` returns by default) is refused.
    const mine = newKey();
    const der = nodeSign("sha256", message, mine.privateKey);
    assert.equal(verifyEs256(parseP256PublicKey(mine.publicKey)!, message, der.toString("base64url")), false);
    assert.equal(decodeSignature(vector.statement.signature.slice(0, 84)), undefined);
    assert.equal(decodeSignature(vector.statement.signature + "="), undefined);
    // A signer that returns DER (a KMS) is converted; the output is always the canonical low-S wire form.
    for (let i = 0; i < 8; i++) {
      const { signature } = await signEs256({ publicKey: mine.publicKey, sign: (m) => new Uint8Array(nodeSign("sha256", m, mine.privateKey)) }, message);
      assert.equal(base64urlEncode(decodeSignature(signature)!), signature);
      assert.ok(verifyEs256(parseP256PublicKey(mine.publicKey)!, message, signature));
    }
    // A signer whose signature does not match its public key is refused before anything is sent.
    await assert.rejects(signEs256({ publicKey: newKey().publicKey, sign: mine.signer.sign }, message), RangeError);
  });

  it("refuses a public key that is not a point on P-256", () => {
    assert.equal(parseP256PublicKey(base64urlEncode(Buffer.concat([Buffer.from([4]), Buffer.alloc(64, 1)]))), undefined);
    assert.equal(parseP256PublicKey("AAAA"), undefined);
  });
});

describe("link sessions against docs/protocol/vectors/link-session-v1.json", () => {
  const secret = new LinkSessionSecret(vector.secret);

  it("binding tag, check code, SAS and pseudonym", () => {
    assert.equal(secret.bindingTag(vector.statement), vector.bindingTag);
    assert.ok(secret.verifyBindingTag(vector.bindingTag, vector.statement));
    assert.equal(secret.verifyBindingTag(vector.bindingTag, vector.approvalStatement), false);
    assert.equal(new LinkSessionSecret().verifyBindingTag(vector.bindingTag, vector.statement), false);
    assert.equal(secret.checkCode, vector.checkCode);
    assert.equal(secret.expectedSas(vector.statement), vector.sas);
    assert.ok(secret.verifySas(`${vector.sas.slice(0, 3)} ${vector.sas.slice(3)}`, vector.statement));
    assert.equal(secret.verifySas("000000", vector.statement), false);
    assert.equal(linkPseudonym(vector.subjectRef), vector.pseudonym);
    assert.equal(statementDigest(vector.statement), vector.statementDigest);
    assert.equal(statementDigest(vector.approvalStatement), vector.approvalStatementDigest);
    // The enrollment secret uses other domain strings: the same bytes give another tag.
    assert.notEqual(new ApprovalEnrollmentSecret(vector.secret).bindingTag(vector.statement), vector.bindingTag);
  });

  it("the secret never prints, and only canonical 32-byte values are accepted", () => {
    assert.equal(String(secret), "[secret]");
    assert.equal(JSON.stringify({ secret }), '{"secret":"[secret]"}');
    assert.equal(secret.base64url, vector.secret);
    assert.throws(() => new LinkSessionSecret("short"), RangeError);
    assert.notEqual(new LinkSessionSecret().base64url, new LinkSessionSecret().base64url);
  });

  it("builds and strictly parses the link", () => {
    assert.equal(buildLinkSessionLink(vector.code, secret, vector.linkDomain), vector.link);
    assert.deepEqual(parseLinkSessionLink(vector.link, vector.linkDomain), { code: vector.code, secret: vector.secret });
    assert.deepEqual(parseLinkSessionLink(`https://${vector.linkDomain}/k/${vector.code}`, vector.linkDomain), { code: vector.code });
    for (const bad of [
      vector.link.replace(vector.linkDomain, "evil.example"), vector.link.replace("https://", "http://"), vector.link.replace(vector.linkDomain, `www.${vector.linkDomain}`),
      vector.link.replace(vector.linkDomain, `${vector.linkDomain}:8443`), vector.link.replace("https://", "https://user@"), vector.link.replace("/k/", "/a/"),
      vector.link.replace(vector.code, vector.code.toLowerCase()), `https://${vector.linkDomain}/k/${vector.code}?x=1`, `https://${vector.linkDomain}/k/${vector.code}/more`,
      vector.link.replace(vector.linkDomain, vector.linkDomain.toUpperCase()),
    ]) assert.equal(parseLinkSessionLink(bad, vector.linkDomain), undefined, bad);
    const kid = vector.statement.kid;
    assert.deepEqual(parseApprovalEnrollmentLink(`https://viadere.com/a/${vector.code}?rk=${kid}`, "viadere.com"), { code: vector.code, rootKid: kid });
    assert.equal(parseApprovalEnrollmentLink(`https://viadere.com/a/${vector.code}?rk=short`, "viadere.com"), undefined);
    assert.equal(parseVerificationSessionLink(`https://viadere.com/v/${vector.code}`, "viadere.com"), vector.code);
    assert.equal(parseVerificationSessionLink(`https://viadere.com/v/${vector.code}#es=${vector.secret}`, "viadere.com"), undefined);
    assert.equal(canonicalCode("k7qf-m2xa"), vector.code);
    assert.equal(canonicalCode("K7QF-M2X0"), undefined, "0 is not in the alphabet");
    assert.equal(displayCode(vector.code), "K7QF-M2XA");
  });

  it("verifies the device's statement, its binding and the approval statement it commits to", () => {
    const statement = verifyLinkStatement(vector.statement);
    assert.equal(statement.sessionId, vector.sessionId);
    assert.equal(statement.subjectRef, vector.subjectRef);
    assert.equal(statement.kid, vector.statement.kid);
    assert.equal(statement.approvalStatementDigest, vector.approvalStatementDigest);
    checkLinkStatementBinding(statement, { sessionId: vector.sessionId, businessId: vector.businessId, subjectRef: vector.subjectRef, capabilities: [...statement.capabilities].reverse() });
    assert.throws(() => checkLinkStatementBinding(statement, { sessionId: UUID_2.replace("5a", "5b"), businessId: vector.businessId, subjectRef: vector.subjectRef, capabilities: statement.capabilities }), code("wrong_session"));
    assert.throws(() => checkLinkStatementBinding(statement, { sessionId: vector.sessionId, businessId: "00000000-0000-4000-8000-000000000000", subjectRef: vector.subjectRef, capabilities: statement.capabilities }), code("wrong_business"));
    assert.throws(() => checkLinkStatementBinding(statement, { sessionId: vector.sessionId, businessId: vector.businessId, subjectRef: SUBJECT_REF, capabilities: statement.capabilities }), code("wrong_subject"));
    assert.throws(() => checkLinkStatementBinding(statement, { sessionId: vector.sessionId, businessId: vector.businessId, subjectRef: vector.subjectRef, capabilities: [...statement.capabilities, "message.send"].filter((c, i, a) => a.indexOf(c) === i).slice(0, 1) }), code("wrong_capabilities"));
    const approval = checkLinkApprovalStatement(statement, vector.approvalStatement)!;
    assert.equal(approval.kid, vector.approvalStatement.kid);
    assert.equal(approval.assurance, "biometric");
    assert.throws(() => checkLinkApprovalStatement(statement, undefined), code("approval_statement_mismatch"));
    assert.throws(() => checkLinkApprovalStatement({ ...statement, approvalStatementDigest: "0".repeat(64) }, vector.approvalStatement), code("approval_statement_mismatch"));
    assert.deepEqual(verifyApprovalEnrollmentStatement(vector.approvalStatement).enrollmentId, vector.sessionId);
  });

  it("refuses a tampered or re-signed statement", async () => {
    assert.throws(() => verifyLinkStatement(tamper(vector.statement, (o) => (o.subject_ref = SUBJECT_REF))), code("bad_signature"));
    assert.throws(() => verifyLinkStatement(tamper(vector.statement, (o) => (o.extra = 1))), code("malformed"));
    assert.throws(() => verifyLinkStatement({ ...vector.statement, payload: vector.statement.payload + "=" }), code("malformed"));
    assert.throws(() => verifyLinkStatement({ payload: vector.statement.payload, signature: vector.result.signature }), code("bad_signature"));
    // A statement signed for another purpose (domain separation) never verifies as a link statement.
    const device = newKey();
    const payload = JSON.parse(Buffer.from(vector.statement.payload, "base64url").toString("utf8")) as Record<string, JsonValue>;
    const other = await signStatement({ ...payload, kid: device.kid, public_key: device.publicKey }, DOMAINS.linkConfirmation, device.signer);
    assert.throws(() => verifyLinkStatement(other), code("bad_signature"));
    // A kid that is not the id of the key the statement carries is malformed.
    const lying = await signStatement({ ...payload, kid: vector.result.kid, public_key: device.publicKey }, DOMAINS.linkStatement, device.signer);
    assert.throws(() => verifyLinkStatement(lying), code("malformed"));
  });

  it("verifies Viadere's link result only against a pinned link-descriptor key", () => {
    const result = verifyLinkResult(vector.result, [newKey().publicKey, vector.result.publicKey]);
    assert.equal(result.sessionId, vector.sessionId);
    assert.equal(result.businessId, vector.businessId);
    assert.equal(result.subjectRef, vector.subjectRef);
    assert.equal(result.statementDigest, vector.statementDigest);
    assert.equal(result.approvalStatementDigest, vector.approvalStatementDigest);
    assert.throws(() => verifyLinkResult(vector.result, [newKey().publicKey]), code("untrusted_signer"));
    assert.throws(() => verifyLinkResult(vector.result, []), code("untrusted_signer"));
    assert.throws(() => verifyLinkResult(tamper(vector.result, (o) => (o.subject_ref = SUBJECT_REF)), [vector.result.publicKey]), code("bad_signature"));
    // The descriptor is signed by the same key under another domain: it is not a result.
    assert.throws(() => verifyLinkResult(vector.descriptor, [vector.descriptor.publicKey]), code("bad_signature"));
  });

  it("verifies the vector's confirmation and signs one that verifies the same way", async () => {
    const o = verifyConfirmation(vector.confirmation, "link", vector.confirmation.publicKey);
    assert.equal(o.statement_digest, vector.statementDigest);
    assert.equal(o.session_id, vector.sessionId);
    assert.throws(() => verifyConfirmation(vector.confirmation, "link", newKey().publicKey), code("key_mismatch"));
    assert.throws(() => verifyConfirmation(vector.confirmation, "approval-enrollment", vector.confirmation.publicKey), code("bad_signature"));
    const mine = newKey();
    const statement = verifyLinkStatement(vector.statement);
    const now = new Date(Number(o.confirmed_at) * 1000);
    const confirmation = await signLinkConfirmation(statement, vector.statement, o.verification as "sas_typed" | "sas_compared", mine.signer, now);
    const mineO = verifyConfirmation(confirmation, "link", mine.publicKey);
    // Byte for byte the vector's payload, except the confirming key.
    assert.deepEqual({ ...mineO, confirm_kid: o.confirm_kid }, { ...o });
    assert.equal(confirmation.kid, mine.kid);
    const approval = verifyApprovalEnrollmentStatement(vector.approvalStatement);
    const approvalConfirmation = await signApprovalEnrollmentConfirmation(approval, vector.approvalStatement, mine.signer, now);
    const a = verifyConfirmation(approvalConfirmation, "approval-enrollment", mine.publicKey);
    assert.deepEqual({ ...a }, { v: 1, type: "approval-enrollment-confirmation", business_id: vector.businessId, subject_ref: vector.subjectRef, enrollment_id: vector.sessionId, kid: approval.kid, statement_digest: vector.approvalStatementDigest, confirm_kid: mine.kid, confirmed_at: o.confirmed_at });
  });
});

describe("verification-session result (VIADERE-VERIFY-SESSION-RESULT-V1; no shared vector: round trip against the normative format)", () => {
  const viadere = newKey();
  const resultRef = "res_" + "R".repeat(43);
  const payload = (over: Record<string, JsonValue> = {}): Record<string, JsonValue> => ({
    v: 1, type: "verify-session-result", session_id: UUID_2, business_id: BUSINESS_ID, request_id: "req_" + "A".repeat(22), subject_ref: SUBJECT_REF, capability: "age.minimum",
    parameters: { years: 21 }, purpose_code: "age_restricted_purchase", origin: "https://shop.northwind.example", outcome: "verified", result_ref_digest: sha256Hex(resultRef), completed_at: 1_800_000_200,
    signer_kid: viadere.kid, ...over,
  });
  const expected = { sessionId: UUID_2, businessId: BUSINESS_ID, origin: "https://shop.northwind.example", capability: "age.minimum" };

  it("verifies a result, its binding to the session and the result reference", async () => {
    const signed = await signStatement(payload(), DOMAINS.verifySessionResult, viadere.signer);
    // The canonical payload is exactly the documented member order (sorted keys).
    assert.match(Buffer.from(signed.payload, "base64url").toString("utf8"), /^\{"business_id":.*"capability":.*"completed_at":.*"origin":.*"outcome":"verified","parameters":\{"years":21\},"purpose_code":.*"request_id":.*"result_ref_digest":.*"session_id":.*"signer_kid":.*"subject_ref":.*"type":"verify-session-result","v":1\}$/);
    const result = verifyVerificationSessionResult(signed, [viadere.publicKey]);
    assert.equal(result.outcome, "verified");
    assert.deepEqual(result.parameters, { years: 21 });
    checkVerificationSessionResult(result, { ...expected, origin: "https://SHOP.northwind.example/" });
    assert.ok(verificationResultMatchesRef(result, resultRef));
    assert.equal(verificationResultMatchesRef(result, "res_" + "S".repeat(43)), false);
    assert.throws(() => checkVerificationSessionResult(result, { ...expected, sessionId: BUSINESS_ID }), code("wrong_session"));
    assert.throws(() => checkVerificationSessionResult(result, { ...expected, businessId: UUID_2 }), code("wrong_business"));
    assert.throws(() => checkVerificationSessionResult(result, { ...expected, origin: "https://evil.example" }), code("wrong_origin"));
    assert.throws(() => checkVerificationSessionResult(result, { ...expected, capability: "identity.name" }), code("wrong_capability"));
  });

  it("refuses an unpinned signer, a wrong domain, a tampered payload and every malformed member", async () => {
    const signed = await signStatement(payload(), DOMAINS.verifySessionResult, viadere.signer);
    assert.throws(() => verifyVerificationSessionResult(signed, [newKey().publicKey]), code("untrusted_signer"));
    assert.throws(() => verifyVerificationSessionResult(tamper(signed, (o) => (o.outcome = "not_verified")), [viadere.publicKey]), code("bad_signature"));
    // Signed by the same key for the link protocol: never a verification result.
    const asLink = await signStatement(payload(), DOMAINS.linkResult, viadere.signer);
    assert.throws(() => verifyVerificationSessionResult(asLink, [viadere.publicKey]), code("bad_signature"));
    const asDescriptor = await signStatement(payload(), "VIADERE-VERIFY-SESSION-DESCRIPTOR-V1\n", viadere.signer);
    assert.throws(() => verifyVerificationSessionResult(asDescriptor, [viadere.publicKey]), code("bad_signature"));
    // An attacker's own key with a kid that claims to be the pinned key.
    const attacker = newKey();
    const forged = await signStatement(payload(), DOMAINS.verifySessionResult, attacker.signer);
    assert.throws(() => verifyVerificationSessionResult({ ...forged, kid: viadere.kid }, [viadere.publicKey]), code("bad_signature"));
    const malformed: Record<string, JsonValue>[] = [
      payload({ v: 2 }), payload({ type: "verify-session-descriptor" }), payload({ session_id: UUID_2.toUpperCase() }), payload({ business_id: "x" }), payload({ request_id: "req_short" }),
      payload({ subject_ref: "sub_x" }), payload({ capability: "made.up" }), payload({ parameters: { Years: 21 } }), payload({ parameters: { years: [21] } }), payload({ purpose_code: "Bad Code" }),
      payload({ origin: "https://shop.northwind.example/" }), payload({ origin: "http://shop.northwind.example" }), payload({ outcome: "maybe" }), payload({ result_ref_digest: "abc" }), payload({ completed_at: 0 }),
      payload({ signer_kid: attacker.kid }), payload({ extra: true }),
    ];
    const missing = payload();
    delete missing.outcome;
    malformed.push(missing);
    for (const bad of malformed) {
      const signedBad = await signStatement(bad, DOMAINS.verifySessionResult, viadere.signer);
      assert.throws(() => verifyVerificationSessionResult(signedBad, [viadere.publicKey]), code("malformed"), JSON.stringify(bad));
    }
    assert.throws(() => verifyVerificationSessionResult(null as never, [viadere.publicKey]), code("malformed"));
  });

  it("canonical origins", () => {
    assert.equal(canonicalOrigin("https://Shop.Example/"), "https://shop.example");
    for (const bad of ["http://shop.example", "https://shop.example:8443", "https://shop.example/a", "https://shop.example?x", "https://u@shop.example", "https://10.0.0.1", "https://localhost"]) assert.equal(canonicalOrigin(bad), undefined, bad);
  });
});

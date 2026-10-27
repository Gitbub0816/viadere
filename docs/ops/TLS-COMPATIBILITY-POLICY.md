# TLS compatibility policy (SEC-TR-001/002/003)

**Status:** proposed, owner: Head of Security & Infrastructure; review: before launch and every 6 months. Enforced in
`Infra/terraform/cloudflare.tf` (variable `min_tls_version`).

## Policy

1. TLS 1.3 is enabled on every public hostname and is what the iOS app, the Swift SDK and all modern browsers use.
2. **TLS 1.2 is allowed for client connections** (`min_tls_version = 1.2`) because some business backends calling the API and
   some older HTTP libraries cannot yet negotiate 1.3. This is the only compatibility exception.
3. TLS 1.2 is restricted to ECDHE key exchange with AEAD ciphers (AES-GCM, ChaCha20-Poly1305). No CBC, no static RSA key exchange,
   no 3DES/RC4/export suites, no TLS compression, no insecure renegotiation (Cloudflare does not offer it).
4. SSL 3, TLS 1.0 and 1.1 are refused (the minimum cannot be set below 1.2).
5. TLS 1.3 AEAD suites (AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305) are all allowed; we do not claim that mandating AES-256 alone is
   stronger (SEC-TR-002).
6. HSTS: `max-age=31536000; includeSubDomains`, rolled out starting at 300 s. Preload only after review.
7. Cloudflare to origin: Full (strict), TLS 1.3 only at the Fly proxy (`tls_options.versions`).
8. The app uses SPKI pinning for the API hostname (Packages/ViadereKit); a certificate change at Cloudflare or Fly must follow the
   pin-rotation procedure in `docs/ops/RUNBOOKS.md` (vendor outage / certificate sections) before it happens.

## Review gate to move to TLS 1.3 only

Set `min_tls_version = "1.3"` when, over 30 consecutive days, Cloudflare analytics show TLS 1.2 below 1% of API requests **and** no
verified business integration depends on it (SDK telemetry plus a 60-day customer notice). Record the decision as an ADR.

## Evidence

`openssl s_client -tls1_1` fails; `-tls1_2` succeeds with an ECDHE-GCM suite only; `-tls1_3` succeeds; SSL Labs/testssl.sh report
attached to each review; the Terraform plan diff is the change record.

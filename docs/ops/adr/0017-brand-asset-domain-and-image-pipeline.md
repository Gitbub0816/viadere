# ADR-0017: Brand asset domain and image pipeline (PNG and JPEG only, re-encoded, SVG refused)

- **Status:** proposed (2026-10-30)
- **Plan reference:** `docs/FEATURE-EXPANSION-PLAN-v4.md` sections 4.6, conflicts K6, K8, WP-2.1, WP-2.2, open decisions O4, O9, O11; spec B2.2, B2.3, B4
- **Related:** `SECURITY.md` §2.93, `Packages/ViadereCore/Sources/ViadereCore/BrandKits/BrandAssetPolicy.swift`, WP-C3 (`LINK_DOMAIN` injection pattern), WP-B2 (`ObjectStore`, Blob adapter, managed identity)
- **Review:** after device profiling (O4); if the owner asks for SVG logos (WP-2.9)

## Context

Brand Kits bring the first business-uploaded media into Viadere. Today there is no object storage or image code on the server, the API sets `Cross-Origin-Resource-Policy: same-origin` and `default-src 'none'`, the console allows images from `'self'` only, and the API origin serves the AASA file. Linux Swift has no ImageIO. SVG and HTML are executable content in browsers; image decoders are a classic memory-safety attack surface; metadata (EXIF GPS, ICC, text chunks) leaks data and can carry polyglots.

## Decision

1. **Formats:** accept **PNG and JPEG only**. SVG is refused with a clear reason (`svg_refused`); HTML/XML (`markup_refused`), GIF, WebP, HEIC, PDF and unknown types are refused. The declared `Content-Type` and the magic bytes must agree (`BrandAssetPolicy.precheck`).
2. **Bounds before work:** upload size capped before the body is read (initial 2 MB); declared dimensions checked before any pixel buffer is allocated (`checkSourceDimensions`: at most 8192 px per side and 25 megapixels; overflow-safe). Initial slot ceilings: logo 512 px, mark 256 px, background and art 1600 px (O4).
3. **Re-encode always:** decode with bounded memory, resize to the slot (never upscale), and encode a **fresh PNG**, which drops EXIF, ICC, text chunks and trailing bytes. The original is deleted after processing. The library choice (pure-Swift decoders versus a sandboxed codec container) is verified against upstream at build time (CLAUDE.md rule 1) with a fuzz corpus as acceptance gate (truncated, polyglot, decompression bomb, EXIF/GPS, ICC, animated, mislabeled MIME, SVG, HTML-as-PNG). AV scanning is optional defense in depth (O11).
4. **Content addressing:** stored and served as `brand/{business}/{sha256}.png` in a private container, public path `https://{ASSET_DOMAIN}/b/{sha256}.png`. Manifests reference assets by `{sha256, w, h, bytes}` (`BrandAssetRef`); the device verifies the bytes' hash before use, so a stale or hostile URL cannot change content.
5. **Dedicated asset domain:** a separate registrable host configured like `LINK_DOMAIN` (`ASSET_DOMAIN`), Cloudflare in front of the private Blob container; never cookie-bearing, never in AASA, no directory listing, no query parameters. Responses: `Content-Type: image/png`, `X-Content-Type-Options: nosniff`, `Cross-Origin-Resource-Policy: cross-origin`, immutable one-year cache. Only the Studio preview pages gain `img-src` for this host.
6. **Never blocking:** any missing, stale or unverifiable asset renders neutral immediately; no approval, sign-in or alert flow waits for branding (B4.4).

## Consequences

- No SVG logos in Phase 2; businesses export a PNG. A restricted SVG-to-raster path stays optional (WP-2.9) behind a decision and the same fuzz gate.
- One new storage container, one new hostname and two new KMS keys (`brand-manifest`, `loop-publication`) in `Infra/azure` (WP-2.1), with the policy check updated (no public container).
- The pure decisions (formats, sniffing, bounds, target sizes, URL form) are Core code with tests; decoding and storage are server code.

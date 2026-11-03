// The KMS, Azure identity, outbound guard and token-auth PostgreSQL pieces live in `ViadereServiceSupport`, which the private authority links
// without linking this module (ADR-0019 §2). Re-exported so the api, worker and migrator keep using them unqualified.
@_exported import ViadereServiceSupport

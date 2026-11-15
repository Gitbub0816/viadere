# Key rotation (spec section 25 deliverable)

The procedures live in one place, `docs/ops/KEY-ROTATION.md` (the name the ADRs cite): sections 1 to 6 for the ordinary tier's service secrets, sections 7 to 12 for the
authority tier (routine signing-key rotation with the 24 h publication lead, seal-key creation and lifetime, standby rollover, **seal key exposed**, shared keys and the
GHCR pull credential). This file exists so the spec's path resolves; do not copy the procedures here.

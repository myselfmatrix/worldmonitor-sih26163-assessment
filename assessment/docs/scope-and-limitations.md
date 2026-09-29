# Scope & limitations

## Authorization & safety statement

All assessment and PoC validation in this project is performed against an
**authorized local / self-hosted** World Monitor environment. **No production
user data or production systems (worldmonitor.app) are tested.** No weaponized
exploitation functionality is included; PoCs drive the project's own module
in-process against a synthetic upstream with mocked DNS and transport, and report
the observed egress policy.

## In scope

- The self-hosted / Docker deployment code paths (Node sidecar, nginx, compose).
- Static review of hosted edge functions and shared security helpers for comparison.
- Safe, local, deterministic reproduction and remediation of F1.

## Out of scope

- Any live testing of worldmonitor.app or third-party services it consumes.
- Real user data, authentication against real accounts, or production infrastructure.
- Denial-of-service against any real system.

## Limitations

- F1 reproduction uses a synthetic upstream, not a live feed publisher.
- The remediation's allowlist default is a compact built-in set, not the full
  428-host hosted registry (not importable in the single-file Docker sidecar);
  operators extend it via `WM_RSS_ALLOWED_DOMAINS`.
- F2 (ingress rate limiting) and F4 (static CSP nonce) are documented hardening
  recommendations, not applied in this branch.
- Two pre-existing failures in the upstream sidecar suite (node-26/Windows quirk)
  are unrelated to this work and left untouched.
- CVSS reflects the self-hosted threat model; it is computed from a stated vector
  and presented separately from finding confidence.

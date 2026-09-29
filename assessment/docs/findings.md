# Findings

Full, lifecycle-tracked records live in `assessment/data/findings.json` and are
rendered into `assessment/reports/report.md` / `report.html`. Summary:

| ID | Title | Confidence | CVSS (primary) | Lifecycle |
| --- | --- | --- | --- | --- |
| **F1** | Self-hosted Docker RSS proxy egress-control gap (no allowlist + no size cap) | High | 7.5 High | **RETESTED** |
| F2 | No rate limiting on the self-hosted Docker `/api/` ingress | High | n/a (recommendation) | VALIDATED |
| F4 | Static, constant CSP nonce (`nonce-wm-static-bootstrap`) | High | n/a (Low, recommendation) | VALIDATED |

- **F1** is the primary case study: discovered → reproduced → remediated → re-tested,
  with controlled local evidence. See `f1-rss-proxy.md`.
- **F2 / F4** are documented hardening recommendations validated by source review;
  they are not remediated in this branch.

## Areas reviewed and found robust (no valid finding)

Recorded so the assessment is honest about what was checked:

- **Session tokens** (`api/_session.js`) — HMAC-SHA256, constant-time compare,
  canonical-base64url enforcement, fail-closed on missing secret.
- **Per-user access control** (briefs, shipping webhooks) — HMAC-signed URL tokens
  and owner-fingerprint checks; no IDOR/BOLA found.
- **CORS** (`api/_cors.js`) — strict anchored allowlist; Google-Translate/host-dot
  edge cases handled.
- **Secrets** — no live secrets committed; env-driven config; dedicated lint gates.
- **XSS sinks** — output-escaped renderers (`server/_shared/brief-render.js`,
  `api/story.js`, `api/og-story.js`); a safe-HTML lint gate is enforced.
- **Hosted RSS proxy** (`api/rss-proxy.js`) — allowlist + size cap + per-hop re-check
  already correct (the reference F1 is brought into parity with).

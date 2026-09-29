# F1 — Self-hosted Docker RSS Proxy Security Control Gap

> Authorized local assessment only. All reproduction is against a self-hosted /
> local environment with mocked network transport. No production systems
> (worldmonitor.app) or production user data were tested. **This is not a public
> production vulnerability.**

## 1. Vulnerability title

Self-hosted Docker RSS proxy egress-control gap — missing destination-domain
allowlist and response-size cap (CWE-918 SSRF-adjacent open proxy, CWE-400 /
CWE-770 uncontrolled resource consumption).

## 2. Description

World Monitor ships two RSS proxy implementations:

- **Hosted (Vercel edge):** [`api/rss-proxy.js`](../../api/rss-proxy.js) enforces a
  destination-domain allowlist (`isAllowedDomain`, re-checked on every redirect
  hop) and a hard 5 MB response cap (`MAX_FEED_BYTES`).
- **Self-hosted (Node sidecar):** the `/api/rss-proxy` route in
  [`src-tauri/sidecar/local-api-server.mjs`](../../src-tauri/sidecar/local-api-server.mjs)
  historically enforced only the SSRF IP guard (`isSafeUrl`). It would fetch any
  caller-named **public** URL and buffer the entire upstream body with no cap.

On the Docker deployment, [`docker/nginx.conf`](../../docker/nginx.conf) injects
the sidecar transport token (`X-WorldMonitor-Local-Token`) on **every** public
`/api/` request, so the route is reachable without caller credentials on a
self-hosted instance.

## 3. Affected components

- `src-tauri/sidecar/local-api-server.mjs` — route `/api/rss-proxy`
- `docker/nginx.conf` — public `/api/` ingress + transport-token injection
- `docker/entrypoint.sh` — `LOCAL_API_TOKEN` provisioning
- `docker-compose.yml` — app container has no `mem_limit` (amplifies availability impact)

## 4. Root cause

The two implementations diverged. The egress-policy controls added to the hosted
edge function (allowlist + size cap + per-hop redirect re-validation) were never
mirrored in the self-hosted Node sidecar, which relied on the SSRF IP guard alone.
The SSRF guard blocks private/reserved IPs but does nothing about **public**
destinations or **response size**.

## 5. Security impact

- **Confidentiality — Low.** Private/reserved ranges stay SSRF-blocked, so internal
  metadata/services are not reachable. The app is usable as a public-web egress relay
  (requests carry the server's egress identity).
- **Integrity — Low.** Application data is not modified; the misuse is egress/proxying.
- **Availability — High.** Unbounded buffering (measured ~327 MB process RSS for one
  64 MB response) with no container memory limit and no route rate limit enables
  memory exhaustion of the container and its co-located services.

## 6. Controlled reproduction summary

`assessment/poc/f1-rss-proxy-poc.mjs` loads **two** copies of the sidecar — the
baseline module at git tag `BASELINE-SIH26163` and the remediated working tree —
and issues the same request to each with DNS and the HTTPS transport stubbed
(no packet leaves the host). Observed:

| Metric | BEFORE (baseline) | AFTER (remediated) |
| --- | --- | --- |
| Non-allowlisted host fetched | yes | no |
| HTTP status | 200 | 403 |
| Bytes returned | ~64 MB | 0 (rejected) |
| Process RSS growth | ~327 MB | ~0 MB |

## 7. Evidence

Collected automatically into `assessment/data/evidence.json` by
`assessment/engine/collect-evidence.mjs`:

- **E-F1-01** — BEFORE/AFTER controlled PoC result (status + bytes + RSS growth).
- **E-F1-02** — F1 regression suite result (9/9 PASS).
- **E-F1-03** — SHA-256 digests of the remediated sidecar and the hosted reference.

## 8. Severity / CVSS v3.1

Computed by `assessment/engine/cvss.mjs` from an explicit vector (never invented):

- **Primary:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` = **7.5 (High)**
- **Conservative:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` = **5.3 (Medium)**
  (availability treated as partial, e.g. when a container `mem_limit` is set)

Threat model: the self-hosted Docker deployment where the ingress injects the
transport token for every caller (PR:N). Severity is presented **separately** from
finding confidence (High).

## 9. Remediation

Brought the sidecar route to parity with the hosted egress policy
(see `assessment/docs/remediation.md`):

1. Destination-domain allowlist (`WM_RSS_ALLOWED_DOMAINS`, www-tolerant, default-deny).
2. Per-hop redirect re-validation (allowlist + SSRF) with a bounded hop count.
3. Hard 5 MB response cap (`MAX_RSS_RESPONSE_BYTES`) that aborts the stream mid-flight.
4. Preserved SSRF IP guard, address pinning, and legitimate feed functionality.

Files changed: `src-tauri/sidecar/local-api-server.mjs`.

## 10. Re-test

`assessment/tests/f1-rss-proxy.security.test.mjs` — 9 cases, all PASS:
allowed→accepted, disallowed→403, malformed→rejected, SSRF→403, redirect-to-allowed
→followed, redirect-to-disallowed→403, body-below-cap→accepted, body-above-cap→502.
The existing sidecar suite still passes 92/92 of its non-pre-existing cases (2
failures exist on the untouched baseline and are unrelated to this change).

## 11. Limitations

Reproduction uses a synthetic upstream (stubbed DNS + HTTPS), not a live feed
publisher. The allowlist default is a compact built-in set that operators extend
via `WM_RSS_ALLOWED_DOMAINS`; it is intentionally not the full 428-host hosted
registry (that file is not copied into the single-file Docker sidecar image).
F2 (ingress rate limiting) is a documented recommendation, not applied here.

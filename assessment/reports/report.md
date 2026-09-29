# SIH26163 — Security Assessment of the World Monitor application

**Organization:** NTRO  
**Target:** World Monitor (self-hosted / local Docker deployment)  
**Baseline:** `BASELINE-SIH26163`

> Authorized local / self-hosted assessment only. No production systems or user data are tested.

_Generated 2026-09-29T18:37:15.025Z._

## 1. Executive summary

This report documents an authorized local security assessment of the self-hosted World Monitor deployment, following a full DISCOVER → ANALYZE → DETECT → SAFE-VALIDATE → COLLECT-EVIDENCE → ASSESS-RISK → REMEDIATE → RE-TEST workflow. The primary finding **F1** — a self-hosted RSS-proxy egress-control gap — was discovered, safely reproduced, remediated, and re-tested in a controlled local environment.

| Metric | Value |
| --- | --- |
| Total findings | 3 |
| Confirmed | 1 |
| Remediated | 1 |
| Re-tested (PASS) | 1 |
| Security domains assessed | 10 |
| F1 CVSS v3.1 (primary) | 7.5 (High) |
| F1 CVSS v3.1 (conservative) | 5.3 (Medium) |

## 2. Scope & methodology

Domains assessed: Authentication & session management; Authorization / access control; Input validation & data handling; API security; Client-side security controls; Secure communication; Data storage & privacy; Secrets / configuration; SSRF / injection / IDOR / misconfiguration; Deployment / Docker / nginx configuration.

Attack surface (from the repository): **166 API routes** (37 RPC, 129 REST), **4 Docker services** (worldmonitor, ais-relay, redis, redis-rest), **8 configuration surfaces**, **5 frontend entry points**.

## 3. Findings


### F1 — Self-hosted Docker RSS proxy egress-control gap (missing domain allowlist and response-size cap)

- **Lifecycle:** RETESTED (DISCOVERED → CANDIDATE → VALIDATED → CONFIRMED → REMEDIATED → RETESTED)
- **Confidence:** High  |  **Severity (CVSS):** 7.5 High  |  **Domain:** API security / Deployment configuration
- **CWE:** CWE-918 (SSRF-adjacent open proxy), CWE-400 (Uncontrolled Resource Consumption), CWE-770 (Allocation without Limits)
- **Affected:** `src-tauri/sidecar/local-api-server.mjs (route: /api/rss-proxy)`, `docker/nginx.conf (public /api/ ingress + token injection)`, `docker/entrypoint.sh (LOCAL_API_TOKEN provisioning)`, `docker-compose.yml (app container has no mem_limit)`
- **Hosted control reference:** `api/rss-proxy.js (isAllowedDomain + MAX_FEED_BYTES=5MB + per-redirect re-check)`

**Description.** During authorized local assessment of the self-hosted Docker deployment, the RSS proxy route in the Node sidecar was found to fetch any caller-named public URL and to buffer the entire upstream body without a size cap. The hosted Vercel implementation (api/rss-proxy.js) enforces a destination-domain allowlist and a 5 MB response cap; the self-hosted sidecar path lacked both. Because docker/nginx.conf injects the sidecar transport token on every public /api/ request, the route is reachable without caller credentials on a self-hosted instance.

**Root cause.** The two RSS proxy implementations diverged: the egress-policy controls (allowlist + size cap + per-hop redirect re-validation) present in the hosted edge function were never mirrored in the self-hosted Node sidecar route, which relied on the SSRF IP guard alone.

**Impact.** _confidentiality:_ Low — SSRF IP guard still blocks private/reserved ranges, so internal metadata/services are not reachable; the app is usable as a public-web egress relay.  _integrity:_ Low — outbound requests carry the server's egress identity (proxy misuse), app data is not modified.  _availability:_ High — unbounded buffering (measured ~327 MB process RSS for one 64 MB response) with no container memory limit and no route rate limit enables memory exhaustion.

**CVSS v3.1.** Primary `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` = 7.5 (High); conservative `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` = 5.3 (Medium). Severity is distinct from confidence (High).

**Remediation.** Bring the sidecar RSS route to parity with the hosted egress policy.
  - Destination-domain allowlist (WM_RSS_ALLOWED_DOMAINS, www-tolerant, default-deny) enforced before any outbound request.
  - Per-hop redirect re-validation so a redirect cannot escape the allowlist or SSRF policy.
  - Hard 5 MB response-size cap (MAX_RSS_RESPONSE_BYTES) that aborts the stream mid-flight instead of buffering unbounded.
  - Preserved SSRF IP guard and address pinning; preserved legitimate feed functionality.
  - _Files changed:_ `src-tauri/sidecar/local-api-server.mjs`

**Re-test.** PASS — non-allowlisted host rejected with 403 before any outbound request; oversized body aborted at the 5 MB cap; legitimate allowlisted feeds and redirects still work.

**Evidence.**
  - `E-F1-01` (2026-09-29T18:37:14.285Z) — Controlled BEFORE/AFTER PoC: same request issued to the baseline sidecar module (git tag BASELINE-SIH26163) and the remediated working-tree module, with DNS and the HTTPS transport stubbed (no packet leaves the host). → {"target":"attacker-chosen.example","requestedBodyMb":64,"hostedCapBytes":5242880,"before":{"label":"BEFORE (BASELINE-SIH26163)","status":200,"bytes":67108864,"mib":64,"rssGrowthMb":327,"outboundToTar
  - `E-F1-02` (2026-09-29T18:37:14.805Z) — F1 remediation regression suite (allowlist, redirect re-validation, SSRF, response-size cap, legitimate-feed positive cases). → {"tests":9,"pass":9,"fail":0,"verdict":"PASS"}
  - `E-F1-03` (2026-09-29T18:37:14.805Z) — SHA-256 digests of the remediated self-hosted route and the hosted reference implementation whose controls it now mirrors. → {"remediatedSidecar":{"file":"src-tauri/sidecar/local-api-server.mjs","digest":"sha256:6b4dd772229bbeed4e125fc543766957f9255350c81308ef7db5a093c0e68545"},"hostedReference":{"file":"api/rss-proxy.js","

### F2 — No rate limiting on the self-hosted Docker /api/ ingress

- **Lifecycle:** VALIDATED (DISCOVERED → CANDIDATE → VALIDATED)
- **Confidence:** High  |  **Severity (CVSS):** see text  |  **Domain:** API security / Deployment configuration
- **CWE:** CWE-770 (Allocation of Resources Without Limits or Throttling)
- **Affected:** `docker/nginx.conf (location /api/ has no limit_req/limit_conn)`

**Description.** The self-hosted nginx ingress proxies /api/ to the sidecar without limit_req/limit_conn. This amplifies F1 (an oversized fetch can be repeated cheaply) and permits unthrottled abuse of proxied routes on self-hosted instances.

**Root cause.** The hosted deployment relies on an Upstash-backed limiter that self-hosted ingress does not reproduce at the edge.

**Impact.** _availability:_ Medium — enables repeated resource-amplification requests.

**Remediation.** Add an nginx limit_req_zone + per-location limit_req (documented recommendation; not applied in this assessment branch to avoid changing operator-tunable capacity policy).

**Re-test.** N/A — documented hardening recommendation.

### F4 — Static, constant CSP nonce ('nonce-wm-static-bootstrap')

- **Lifecycle:** VALIDATED (DISCOVERED → CANDIDATE → VALIDATED)
- **Confidence:** High  |  **Severity (CVSS):** see text  |  **Domain:** Client-side security controls
- **CWE:** CWE-693 (Protection Mechanism Failure)
- **Affected:** `vercel.json (CSP header)`, `index.html and ~15 templates using nonce="wm-static-bootstrap"`

**Description.** The CSP script nonce is a hardcoded literal shipped in static HTML rather than a per-response value. It does not grant injection by itself (no HTML-injection sink was found, and script-src also uses 'strict-dynamic' + hashes), so practical risk is low, but the nonce provides no defense value against a future injection sink.

**Root cause.** A build-time constant is used where a per-response random nonce is intended.

**Impact.** _confidentiality:_ Low  _integrity:_ Low

**Remediation.** Generate a per-response nonce at the edge/nginx layer, or rely solely on hashes + 'strict-dynamic' (documented recommendation).

**Re-test.** N/A — documented hardening recommendation.

## 4. Limitations & authorization

All validation was performed against an authorized local / self-hosted environment with mocked network transport. No production systems (worldmonitor.app) or production user data were tested. Findings F2 and F4 are documented hardening recommendations, not applied in this branch. The CVSS scores are computed from the stated vectors by `assessment/engine/cvss.mjs`; severity reflects the self-hosted threat model and is presented separately from finding confidence.

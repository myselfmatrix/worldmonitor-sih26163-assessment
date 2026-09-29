# Remediation — F1

**File changed:** `src-tauri/sidecar/local-api-server.mjs` (self-hosted sidecar).

## Root cause

The self-hosted `/api/rss-proxy` route relied on the SSRF IP guard alone and did
not mirror the hosted edge function's destination-domain allowlist or response-size
cap. The SSRF guard blocks private IPs but not public destinations or body size.

## Changes

1. **Egress-policy helpers** (near the SSRF block):
   - `MAX_RSS_RESPONSE_BYTES = 5 * 1024 * 1024` — parity with the hosted `MAX_FEED_BYTES`.
   - `MAX_RSS_REDIRECTS = 3`, `RSS_REDIRECT_STATUSES`.
   - `DEFAULT_RSS_ALLOWED_DOMAINS` (compact safe default) + `getRssAllowedDomains()`
     reading `WM_RSS_ALLOWED_DOMAINS` (comma-separated; additive by default,
     replace with `WM_RSS_ALLOWED_DOMAINS_STRICT=1`).
   - `rssHostMatchForms()` / `isRssDomainAllowed()` — www-tolerant, default-deny.

2. **`fetchWithTimeout` response cap:** an optional `maxResponseBytes` aborts the
   HTTPS stream mid-flight (`req.destroy(err)` with `code = ERR_RESPONSE_TOO_LARGE`)
   instead of buffering without bound.

3. **`/api/rss-proxy` route** rewritten as a bounded loop that, on every hop:
   - runs the SSRF check (`isSafeUrl`),
   - enforces the domain allowlist,
   - pins to a validated address,
   - fetches with the 5 MB cap,
   - follows up to 3 redirects, re-validating each next hop, then re-checks policy.

4. **Test seam:** `isRssDomainAllowed`, `getRssAllowedDomains`, `rssHostMatchForms`,
   `MAX_RSS_RESPONSE_BYTES`, `MAX_RSS_REDIRECTS` exported via `__testing__`.

## Design decisions

- **Env-configurable allowlist instead of copying the 428-host hosted registry.**
  The Docker image copies only the single sidecar file, so the hosted allowlist
  module is not importable at runtime. A compact built-in default keeps RSS working
  out of the box; operators extend it via `WM_RSS_ALLOWED_DOMAINS`. This closes the
  "any public host" gap without weakening the hosted model.
- **Additive-by-default env merge.** Operators broaden the safe baseline; they do not
  silently narrow it. `WM_RSS_ALLOWED_DOMAINS_STRICT=1` opts into full replacement
  (used by the deterministic tests).
- **Redirects are followed, not dropped**, so legitimate feed redirects still work,
  but every hop is re-validated so a redirect cannot escape the policy.

## What was intentionally NOT changed here

- **F2 (nginx ingress rate limiting)** — a capacity-policy change left to operators;
  documented as a recommendation.
- The hosted edge function (`api/rss-proxy.js`) — already correct; used as the
  reference for parity.

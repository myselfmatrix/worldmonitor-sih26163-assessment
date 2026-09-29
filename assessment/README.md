# World Monitor — SIH26163 Security Assessment

An authorized, evidence-driven security assessment of the **self-hosted / local**
World Monitor deployment, built for Smart India Hackathon 2026 problem statement
**SIH26163** (Organization: **NTRO**).

> **Authorization & safety.** All assessment and PoC validation in this project is
> performed against an authorized local / self-hosted environment. **No production
> user data or production systems (worldmonitor.app) are tested.** No weaponized
> exploitation functionality is included.

## 1. Overview

This is not a generic vulnerability scanner. It is a complete, reproducible
assessment workflow —
`DISCOVER → ANALYZE → DETECT → SAFE-VALIDATE → COLLECT-EVIDENCE → ASSESS-RISK →
REMEDIATE → RE-TEST → REPORT` — built around one confirmed, remediated, re-tested
finding (**F1**) plus two documented hardening recommendations.

## 2. SIH26163 context

- **Title:** Security Assessment of the World Monitor application
- **Organization:** NTRO · **Category:** Software · **Theme:** Smart Automation
- **Target:** the open-source World Monitor repository, self-hosted locally.

## 3. Security / authorization notice

See `assessment/docs/scope-and-limitations.md`. In short: authorized local
assessment only; no production testing; original vulnerable behavior preserved on
git tag `BASELINE-SIH26163`.

## 4. Architecture

Self-contained Node toolkit under `assessment/` (no extra dependencies). Full map
in `assessment/docs/architecture.md`.

## 5. Assessment methodology

See `assessment/docs/methodology.md` — the nine-stage workflow and the finding
lifecycle (`DISCOVERED → CANDIDATE → VALIDATED → CONFIRMED → REMEDIATED → RETESTED`).

## 6. F1 finding

Self-hosted Docker RSS proxy egress-control gap — missing destination-domain
allowlist and response-size cap. Full write-up: `assessment/docs/f1-rss-proxy.md`.
**CVSS v3.1: 7.5 (High)** primary / 5.3 (Medium) conservative — computed, not invented.

## 7. Evidence

Generated into `assessment/data/evidence.json` by executing the PoC and the
regression suite (timestamps + SHA-256 digests). BEFORE: non-allowlisted host
fetched, ~64 MB body, ~327 MB RSS growth. AFTER: HTTP 403 before any outbound
request; oversized body aborted at 5 MB. **Controlled local evidence — not a public
production vulnerability.**

## 8. Remediation

Root-cause fix in `src-tauri/sidecar/local-api-server.mjs`: domain allowlist +
per-hop redirect re-validation + 5 MB stream-abort cap, preserving the SSRF guard
and legitimate feeds. Details: `assessment/docs/remediation.md`.

## 9. Re-test

9-case regression suite + BEFORE/AFTER PoC, both PASS. Existing sidecar suite:
92 pass / 2 pre-existing-baseline failures (unrelated). See
`assessment/docs/retest.md`.

## 10. UI

`assessment/dashboard/index.html` — a security console with Executive Dashboard,
Attack Surface, Findings, F1 Detail (hosted-vs-self-hosted + before/after +
controlled evidence), Remediation, Reports, and a Demo script. Opens directly in a
browser (reads `data.js`, no server needed).

## 11. Setup

```
# Node 24+ (repo .nvmrc); this assessment toolkit needs no npm install.
git clone https://github.com/koala73/worldmonitor
cd worldmonitor
git tag BASELINE-SIH26163   # if not already present (preserves original behavior)
```

## 12. Testing

```
# F1 regression suite
node --test assessment/tests/f1-rss-proxy.security.test.mjs

# Existing sidecar suite (unchanged target tests)
node --test src-tauri/sidecar/local-api-server.test.mjs

# CVSS calculator self-check
node assessment/engine/cvss.mjs
```

## 13. Generate everything (evidence + reports + dashboard data)

```
node assessment/run.mjs
# then open assessment/dashboard/index.html or assessment/reports/report.html
```

## 14. Repository structure

`assessment/{run.mjs, engine/, poc/, tests/, data/, dashboard/, reports/, docs/}`.
The only change to the target app is the F1 remediation in
`src-tauri/sidecar/local-api-server.mjs` (+ two existing sidecar tests updated to
opt fixture hosts into the allowlist).

## 15. Limitations & ethical testing statement

Documented in `assessment/docs/scope-and-limitations.md`. This project does **not**
imply that every item in the tool is a confirmed World Monitor vulnerability: F1 is
confirmed and remediated in the self-hosted path; F2/F4 are recommendations. All
work is authorized, local, and non-destructive.

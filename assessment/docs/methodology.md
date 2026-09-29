# Assessment methodology

An evidence-driven workflow, applied to the authorized local / self-hosted
World Monitor deployment:

```
DISCOVER → ANALYZE → DETECT → SAFE-VALIDATE → COLLECT-EVIDENCE
        → ASSESS-RISK → REMEDIATE → RE-TEST → REPORT
```

| Stage | What we did | Artifact |
| --- | --- | --- |
| **Discover** | Enumerated API routes, Docker services, config surfaces, frontend entries from the repo. | `assessment/engine/discover.mjs` |
| **Analyze** | Reviewed auth/session, CORS, rate-limit, SSRF, secrets, and the two RSS-proxy implementations. | `assessment/docs/findings.md` |
| **Detect** | Identified the hosted-vs-self-hosted egress-control divergence (F1). | F1 finding record |
| **Safe-validate** | Reproduced F1 with a synthetic upstream, stubbed DNS + transport — no network egress. | `assessment/poc/f1-rss-proxy-poc.mjs` |
| **Collect evidence** | Ran the PoC + regression suite, recorded results with timestamps and SHA-256 digests. | `assessment/data/evidence.json` |
| **Assess risk** | Scored F1 with CVSS v3.1 from an explicit vector; separated severity from confidence. | `assessment/engine/cvss.mjs` |
| **Remediate** | Implemented the root-cause fix in the sidecar route. | `src-tauri/sidecar/local-api-server.mjs` |
| **Re-test** | 9-case regression suite + BEFORE/AFTER PoC comparison. | `assessment/tests/f1-rss-proxy.security.test.mjs` |
| **Report** | Generated JSON/Markdown/HTML from stored findings + evidence. | `assessment/engine/report.mjs` |

## Finding lifecycle

`DISCOVERED → CANDIDATE → VALIDATED → CONFIRMED → REMEDIATED → RETESTED`

A finding is only advanced to **CONFIRMED** when supporting evidence exists — never
because a static pattern matched. F1 reached **RETESTED**; F2 and F4 are **VALIDATED**
hardening recommendations.

## Safety rules honoured

- No requests to worldmonitor.app or any third-party production system.
- No access to real user data.
- No weaponized functionality; the PoC drives the project's own module in-process
  with a synthetic upstream and reports the observed egress policy.
- The original vulnerable behavior is preserved on tag `BASELINE-SIH26163`.

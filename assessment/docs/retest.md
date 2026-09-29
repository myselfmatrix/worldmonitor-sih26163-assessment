# Re-test — F1

Re-test is reproducible with two commands in the authorized local environment.

## 1. Regression suite (AFTER-fix behavior)

```
node --test assessment/tests/f1-rss-proxy.security.test.mjs
```

9 cases, all PASS:

| Case | Expected |
| --- | --- |
| allowlist predicate (unit) | www-tolerant, default-deny |
| allowed domain | 200 accepted |
| disallowed domain | 403, no outbound request |
| malformed / non-http URL | 400/403 |
| SSRF (localhost / private / metadata IP) | 403 |
| redirect → allowed host | followed, 200 |
| redirect → disallowed host | 403, target never contacted |
| body below 5 MB cap | 200 accepted |
| body above 5 MB cap | 502, stream aborted |

## 2. BEFORE / AFTER controlled PoC

```
node assessment/poc/f1-rss-proxy-poc.mjs
```

Loads the baseline module (tag `BASELINE-SIH26163`) and the remediated tree and
prints both side by side. Latest recorded result:

| Metric | BEFORE | AFTER |
| --- | --- | --- |
| Non-allowlisted host fetched | yes | no |
| HTTP status | 200 | 403 |
| Bytes returned | ~64 MB | 0 |
| Process RSS growth | ~327 MB | ~0 MB |

## 3. No regressions in the existing suite

```
node --test src-tauri/sidecar/local-api-server.test.mjs
```

Result: 92 pass / 2 fail. The 2 failures are **pre-existing on the untouched
`BASELINE-SIH26163`** (a node-26/Windows relay-mock quirk in an unrelated Docker
test) and are not caused by this change — verified by running the same suite with
the fix stashed.

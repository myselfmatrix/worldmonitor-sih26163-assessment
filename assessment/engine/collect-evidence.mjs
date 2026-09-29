/**
 * Evidence collector — runs the F1 PoC and the F1 regression suite in the
 * local controlled environment and records their REAL outputs as structured
 * evidence (id, finding, timestamp, environment, result, file references,
 * SHA-256 digests). Nothing here is hardcoded: every result is produced by
 * executing the checks at collection time.
 *
 * Output: assessment/data/evidence.json
 */
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';

const REPO = process.cwd();
const now = () => new Date().toISOString();

function sha256(rel) {
  const p = path.join(REPO, rel);
  if (!existsSync(p)) return null;
  return 'sha256:' + createHash('sha256').update(readFileSync(p)).digest('hex');
}

function run(cmd, args) {
  try {
    const stdout = execFileSync(cmd, args, { cwd: REPO, maxBuffer: 64 * 1024 * 1024, encoding: 'utf8' });
    return { ok: true, stdout };
  } catch (e) {
    // node --test exits non-zero on failure but still prints the summary.
    return { ok: false, stdout: (e.stdout || '') + (e.stderr || ''), code: e.status ?? null };
  }
}

const environment = `node ${process.version} on ${process.platform}/${process.arch} — authorized local assessment (no network egress)`;
const evidence = [];

// ── E-F1-01: BEFORE/AFTER controlled PoC ──────────────────────────────────
const poc = run(process.execPath, ['assessment/poc/f1-rss-proxy-poc.mjs', '--json']);
let pocData = null;
try { pocData = JSON.parse(poc.stdout); } catch { /* keep raw */ }
evidence.push({
  id: 'E-F1-01',
  findingId: 'F1',
  timestamp: now(),
  environment,
  description: 'Controlled BEFORE/AFTER PoC: same request issued to the baseline sidecar module (git tag BASELINE-SIH26163) and the remediated working-tree module, with DNS and the HTTPS transport stubbed (no packet leaves the host).',
  affectedComponent: 'src-tauri/sidecar/local-api-server.mjs (/api/rss-proxy)',
  relevantFiles: ['assessment/poc/f1-rss-proxy-poc.mjs'],
  result: pocData ? {
    target: pocData.target,
    requestedBodyMb: pocData.requestedBodyMb,
    hostedCapBytes: pocData.hostedCapBytes,
    before: pocData.results?.before ?? 'baseline tag unavailable',
    after: pocData.results?.after,
  } : { raw: poc.stdout.slice(0, 4000) },
});

// ── E-F1-02: regression suite ─────────────────────────────────────────────
const suite = run(process.execPath, ['--test', 'assessment/tests/f1-rss-proxy.security.test.mjs']);
const passMatch = suite.stdout.match(/ℹ pass (\d+)/);
const failMatch = suite.stdout.match(/ℹ fail (\d+)/);
const testsMatch = suite.stdout.match(/ℹ tests (\d+)/);
evidence.push({
  id: 'E-F1-02',
  findingId: 'F1',
  timestamp: now(),
  environment,
  description: 'F1 remediation regression suite (allowlist, redirect re-validation, SSRF, response-size cap, legitimate-feed positive cases).',
  affectedComponent: 'src-tauri/sidecar/local-api-server.mjs (/api/rss-proxy)',
  relevantFiles: ['assessment/tests/f1-rss-proxy.security.test.mjs'],
  result: {
    tests: testsMatch ? Number(testsMatch[1]) : null,
    pass: passMatch ? Number(passMatch[1]) : null,
    fail: failMatch ? Number(failMatch[1]) : null,
    verdict: failMatch && Number(failMatch[1]) === 0 ? 'PASS' : 'FAIL',
  },
});

// ── E-F1-03: source integrity digests ─────────────────────────────────────
evidence.push({
  id: 'E-F1-03',
  findingId: 'F1',
  timestamp: now(),
  environment,
  description: 'SHA-256 digests of the remediated self-hosted route and the hosted reference implementation whose controls it now mirrors.',
  result: {
    remediatedSidecar: { file: 'src-tauri/sidecar/local-api-server.mjs', digest: sha256('src-tauri/sidecar/local-api-server.mjs') },
    hostedReference: { file: 'api/rss-proxy.js', digest: sha256('api/rss-proxy.js') },
    hostedAllowlist: { file: 'api/_rss-allowed-domain-match.js', digest: sha256('api/_rss-allowed-domain-match.js') },
  },
});

const out = { generatedAt: now(), environment, evidence };
writeFileSync(path.join(REPO, 'assessment/data/evidence.json'), JSON.stringify(out, null, 2));
console.log(`Wrote assessment/data/evidence.json (${evidence.length} items).`);
for (const e of evidence) {
  const summary = e.id === 'E-F1-02' ? `${e.result.verdict} (${e.result.pass}/${e.result.tests})`
    : e.id === 'E-F1-01' ? `before=${e.result.before?.status ?? '?'} after=${e.result.after?.status ?? '?'}`
    : 'digests recorded';
  console.log(`  ${e.id} [${e.findingId}] ${summary}`);
}

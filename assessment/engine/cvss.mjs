/**
 * Minimal, correct CVSS v3.1 base-score calculator (no dependencies).
 * Implements the spec formula (https://www.first.org/cvss/v3.1/specification-document).
 * Used to score findings from an explicit, documented vector — never an invented number.
 */

const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  PR: { N: 0.85, L: 0.62, H: 0.27, Lc: 0.68, Hc: 0.5 }, // *c = when Scope Changed
  UI: { N: 0.85, R: 0.62 },
  CIA: { N: 0, L: 0.22, H: 0.56 },
};

function roundUp1(x) {
  // Spec-defined roundup to one decimal place.
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

export function parseVector(vector) {
  const parts = String(vector).replace(/^CVSS:3\.1\//, '').split('/');
  const m = {};
  for (const p of parts) {
    const [k, v] = p.split(':');
    if (k && v) m[k] = v;
  }
  return m;
}

export function severityLabel(score) {
  if (score === 0) return 'None';
  if (score < 4) return 'Low';
  if (score < 7) return 'Medium';
  if (score < 9) return 'High';
  return 'Critical';
}

export function baseScore(vector) {
  const m = parseVector(vector);
  const scopeChanged = m.S === 'C';
  const iss = 1 - (1 - W.CIA[m.C]) * (1 - W.CIA[m.I]) * (1 - W.CIA[m.A]);
  const impact = scopeChanged
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  const pr = scopeChanged ? { N: 0.85, L: 0.68, H: 0.5 }[m.PR] : W.PR[m.PR];
  const exploitability = 8.22 * W.AV[m.AV] * W.AC[m.AC] * pr * W.UI[m.UI];
  let base;
  if (impact <= 0) base = 0;
  else base = scopeChanged
    ? roundUp1(Math.min(1.08 * (impact + exploitability), 10))
    : roundUp1(Math.min(impact + exploitability, 10));
  return {
    vector: `CVSS:3.1/${['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'].map((k) => `${k}:${m[k]}`).join('/')}`,
    baseScore: Number(base.toFixed(1)),
    severity: severityLabel(base),
    subScores: {
      impact: Number(impact.toFixed(2)),
      exploitability: Number(exploitability.toFixed(2)),
      iss: Number(iss.toFixed(2)),
    },
  };
}

// ── F1 documented vector ──────────────────────────────────────────────────
// Threat model: an authorized-assessment view of the SELF-HOSTED Docker
// deployment, where docker/nginx.conf injects the sidecar transport token on
// every public /api/ request, so the RSS route is reachable without caller
// credentials. Each metric is justified; nothing is assumed to inflate.
export const F1_CVSS = {
  primary: {
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
    rationale: {
      AV: 'Network — the route is reachable over the container HTTP ingress.',
      AC: 'Low — a single crafted URL parameter; no special conditions.',
      PR: 'None — the Docker ingress injects the transport token for every caller.',
      UI: 'None — no victim interaction required.',
      S: 'Unchanged (conservative) — impact scored within the app container. S:C is arguable because co-located supervisord services share the host memory; that would raise the score.',
      C: 'None — private/reserved IPs remain SSRF-blocked, so app secrets/metadata are not reachable via this gap.',
      I: 'None — the app data store is not modified; the misuse is egress/proxying, captured qualitatively.',
      A: 'High — unbounded response buffering (measured ~327 MB RSS for one 64 MB body) with no container memory limit and no route rate limit enables memory exhaustion.',
    },
  },
  // Conservative alternative if availability impact is treated as partial.
  conservative: {
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L',
    note: 'Use when the amplification is judged to degrade rather than deny service (e.g. a container mem_limit is set).',
  },
};

export function f1Score() {
  return {
    primary: { ...F1_CVSS.primary, ...baseScore(F1_CVSS.primary.vector) },
    conservative: { ...F1_CVSS.conservative, ...baseScore(F1_CVSS.conservative.vector) },
  };
}

// Self-check when run directly, plus two spec reference vectors.
if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('cvss.mjs')) {
  const checks = [
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 7.5],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 6.1],
  ];
  let ok = true;
  for (const [v, expected] of checks) {
    const got = baseScore(v).baseScore;
    const pass = got === expected;
    ok = ok && pass;
    console.log(`${pass ? 'OK ' : 'FAIL'} ${v} => ${got} (expected ${expected})`);
  }
  console.log('\nF1 score:', JSON.stringify(f1Score().primary, null, 2));
  process.exit(ok ? 0 : 1);
}

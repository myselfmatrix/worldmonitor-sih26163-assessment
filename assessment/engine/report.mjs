/**
 * Report generator. Assembles the canonical findings, collected evidence,
 * attack-surface discovery, and computed CVSS into:
 *   - assessment/data/assessment.json  (single source of truth for the dashboard)
 *   - assessment/reports/report.md
 *   - assessment/reports/report.html
 * Everything is derived from stored data — no duplicated prose.
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import path from 'node:path';
import { discover } from './discover.mjs';
import { baseScore, f1Score } from './cvss.mjs';

const REPO = process.cwd();
const read = (rel) => JSON.parse(readFileSync(path.join(REPO, rel), 'utf8'));

const findingsDoc = read('assessment/data/findings.json');
const evidenceDoc = existsSync(path.join(REPO, 'assessment/data/evidence.json'))
  ? read('assessment/data/evidence.json') : { evidence: [] };
const surface = discover(REPO);
const f1 = f1Score();

// Attach computed CVSS + evidence to each finding.
for (const f of findingsDoc.findings) {
  if (f.cvss?.primaryVector) {
    f.cvss.computed = baseScore(f.cvss.primaryVector);
    if (f.cvss.conservativeVector) f.cvss.computedConservative = baseScore(f.cvss.conservativeVector);
  }
  f.evidence = evidenceDoc.evidence.filter((e) => e.findingId === f.id);
}

const confirmed = findingsDoc.findings.filter((f) => ['CONFIRMED', 'REMEDIATED', 'RETESTED'].includes(f.lifecycle));
const remediated = findingsDoc.findings.filter((f) => ['REMEDIATED', 'RETESTED'].includes(f.lifecycle));
const retested = findingsDoc.findings.filter((f) => f.lifecycle === 'RETESTED');

const assessment = {
  generatedAt: new Date().toISOString(),
  meta: findingsDoc.assessment,
  summary: {
    totalFindings: findingsDoc.findings.length,
    confirmed: confirmed.length,
    remediated: remediated.length,
    retested: retested.length,
    domainsAssessed: findingsDoc.assessment.domainsAssessed.length,
    f1CvssPrimary: f1.primary.baseScore,
    f1CvssPrimarySeverity: f1.primary.severity,
    f1CvssConservative: f1.conservative.baseScore,
  },
  cvss: { f1 },
  attackSurface: surface,
  findings: findingsDoc.findings,
  evidence: evidenceDoc.evidence,
};

mkdirSync(path.join(REPO, 'assessment/reports'), { recursive: true });
writeFileSync(path.join(REPO, 'assessment/data/assessment.json'), JSON.stringify(assessment, null, 2));

// ── Markdown ───────────────────────────────────────────────────────────────
function md() {
  const m = findingsDoc.assessment;
  const L = [];
  L.push(`# ${m.id} — ${m.title}`);
  L.push(`\n**Organization:** ${m.organization}  \n**Target:** ${m.target}  \n**Baseline:** \`${m.baselineRef}\``);
  L.push(`\n> ${m.environment}`);
  L.push(`\n_Generated ${assessment.generatedAt}._`);

  L.push(`\n## 1. Executive summary\n`);
  L.push(`This report documents an authorized local security assessment of the self-hosted World Monitor deployment, following a full DISCOVER → ANALYZE → DETECT → SAFE-VALIDATE → COLLECT-EVIDENCE → ASSESS-RISK → REMEDIATE → RE-TEST workflow. The primary finding **F1** — a self-hosted RSS-proxy egress-control gap — was discovered, safely reproduced, remediated, and re-tested in a controlled local environment.`);
  L.push(`\n| Metric | Value |\n| --- | --- |`);
  L.push(`| Total findings | ${assessment.summary.totalFindings} |`);
  L.push(`| Confirmed | ${assessment.summary.confirmed} |`);
  L.push(`| Remediated | ${assessment.summary.remediated} |`);
  L.push(`| Re-tested (PASS) | ${assessment.summary.retested} |`);
  L.push(`| Security domains assessed | ${assessment.summary.domainsAssessed} |`);
  L.push(`| F1 CVSS v3.1 (primary) | ${f1.primary.baseScore} (${f1.primary.severity}) |`);
  L.push(`| F1 CVSS v3.1 (conservative) | ${f1.conservative.baseScore} (${f1.conservative.severity}) |`);

  L.push(`\n## 2. Scope & methodology\n`);
  L.push(`Domains assessed: ${m.domainsAssessed.join('; ')}.`);
  L.push(`\nAttack surface (from the repository): **${surface.counts.apiRoutes} API routes** (${surface.counts.rpcRoutes} RPC, ${surface.counts.restRoutes} REST), **${surface.counts.dockerServices} Docker services** (${surface.dockerServices.join(', ')}), **${surface.counts.configSurfaces} configuration surfaces**, **${surface.counts.frontendEntries} frontend entry points**.`);

  L.push(`\n## 3. Findings\n`);
  for (const f of findingsDoc.findings) {
    const sev = f.cvss?.computed ? `${f.cvss.computed.baseScore} ${f.cvss.computed.severity}` : 'see text';
    L.push(`\n### ${f.id} — ${f.title}`);
    L.push(`\n- **Lifecycle:** ${f.lifecycle} (${f.lifecycleHistory.join(' → ')})`);
    L.push(`- **Confidence:** ${f.confidence}  |  **Severity (CVSS):** ${sev}  |  **Domain:** ${f.domain}`);
    L.push(`- **CWE:** ${(f.cwe || []).join(', ')}`);
    L.push(`- **Affected:** ${f.affectedComponents.map((c) => `\`${c}\``).join(', ')}`);
    if (f.hostedControlReference) L.push(`- **Hosted control reference:** \`${f.hostedControlReference}\``);
    L.push(`\n**Description.** ${f.description}`);
    L.push(`\n**Root cause.** ${f.rootCause}`);
    if (f.impact) L.push(`\n**Impact.** ` + Object.entries(f.impact).map(([k, v]) => `_${k}:_ ${v}`).join('  '));
    if (f.cvss?.primaryVector) {
      L.push(`\n**CVSS v3.1.** Primary \`${f.cvss.primaryVector}\` = ${f.cvss.computed.baseScore} (${f.cvss.computed.severity}); conservative \`${f.cvss.conservativeVector}\` = ${f.cvss.computedConservative.baseScore} (${f.cvss.computedConservative.severity}). Severity is distinct from confidence (${f.confidence}).`);
    }
    if (f.remediation) {
      L.push(`\n**Remediation.** ${f.remediation.summary}`);
      if (f.remediation.changes) for (const c of f.remediation.changes) L.push(`  - ${c}`);
      if (f.remediation.filesChanged?.length) L.push(`  - _Files changed:_ ${f.remediation.filesChanged.map((c) => `\`${c}\``).join(', ')}`);
    }
    if (f.retest?.result) L.push(`\n**Re-test.** ${f.retest.result}`);
    const ev = evidenceDoc.evidence.filter((e) => e.findingId === f.id);
    if (ev.length) {
      L.push(`\n**Evidence.**`);
      for (const e of ev) L.push(`  - \`${e.id}\` (${e.timestamp}) — ${e.description} → ${JSON.stringify(e.result).slice(0, 200)}`);
    }
  }

  L.push(`\n## 4. Limitations & authorization\n`);
  L.push(`All validation was performed against an authorized local / self-hosted environment with mocked network transport. No production systems (worldmonitor.app) or production user data were tested. Findings F2 and F4 are documented hardening recommendations, not applied in this branch. The CVSS scores are computed from the stated vectors by \`assessment/engine/cvss.mjs\`; severity reflects the self-hosted threat model and is presented separately from finding confidence.`);
  return L.join('\n') + '\n';
}

// ── HTML (self-contained) ───────────────────────────────────────────────────
function esc(s) { return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
function html() {
  const m = findingsDoc.assessment;
  const cards = findingsDoc.findings.map((f) => {
    const sev = f.cvss?.computed ? `${f.cvss.computed.baseScore} ${f.cvss.computed.severity}` : '—';
    return `<section class="card"><h3>${esc(f.id)} — ${esc(f.title)}</h3>
      <p class="tags"><span class="tag life">${esc(f.lifecycle)}</span>
        <span class="tag">Confidence: ${esc(f.confidence)}</span>
        <span class="tag sev">CVSS: ${esc(sev)}</span>
        <span class="tag">${esc(f.domain)}</span></p>
      <p>${esc(f.description)}</p>
      <p><strong>Root cause.</strong> ${esc(f.rootCause)}</p>
      ${f.remediation ? `<p><strong>Remediation.</strong> ${esc(f.remediation.summary)}</p>` : ''}
      ${f.retest?.result ? `<p><strong>Re-test.</strong> ${esc(f.retest.result)}</p>` : ''}
    </section>`;
  }).join('\n');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(m.id)} Security Assessment Report</title>
<style>
:root{--bg:#0b1020;--panel:#141b33;--ink:#e8ecf8;--mut:#93a0c8;--acc:#5b8cff;--ok:#39d98a;--warn:#ffb020;--crit:#ff5470;}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,Segoe UI,sans-serif;padding:0 16px}
.wrap{max-width:960px;margin:0 auto;padding:32px 0 64px}
h1{font-size:26px;margin:0 0 4px}h3{margin:0 0 8px;font-size:17px}
.sub{color:var(--mut);margin:0 0 20px}
.note{background:#10192f;border:1px solid #24304f;border-left:3px solid var(--acc);border-radius:8px;padding:10px 14px;color:var(--mut);margin:16px 0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:20px 0}
.kpi{background:var(--panel);border:1px solid #24304f;border-radius:10px;padding:14px}
.kpi b{display:block;font-size:24px}.kpi span{color:var(--mut);font-size:12px}
.card{background:var(--panel);border:1px solid #24304f;border-radius:10px;padding:16px;margin:14px 0}
.tags{display:flex;flex-wrap:wrap;gap:6px;margin:6px 0 10px}
.tag{background:#0f1830;border:1px solid #2b3a63;color:var(--mut);border-radius:999px;padding:2px 10px;font-size:12px}
.tag.life{color:var(--ok);border-color:#1f5c43}.tag.sev{color:var(--warn);border-color:#5c4a1f}
code{background:#0f1830;padding:1px 5px;border-radius:5px}
</style></head><body><div class="wrap">
<h1>${esc(m.id)} — ${esc(m.title)}</h1>
<p class="sub">${esc(m.organization)} · Target: ${esc(m.target)} · Baseline <code>${esc(m.baselineRef)}</code> · Generated ${esc(assessment.generatedAt)}</p>
<div class="note">${esc(m.environment)}</div>
<div class="grid">
  <div class="kpi"><b>${assessment.summary.totalFindings}</b><span>Findings</span></div>
  <div class="kpi"><b>${assessment.summary.confirmed}</b><span>Confirmed</span></div>
  <div class="kpi"><b>${assessment.summary.remediated}</b><span>Remediated</span></div>
  <div class="kpi"><b>${assessment.summary.retested}</b><span>Re-tested PASS</span></div>
  <div class="kpi"><b>${f1.primary.baseScore}</b><span>F1 CVSS (${esc(f1.primary.severity)})</span></div>
  <div class="kpi"><b>${surface.counts.apiRoutes}</b><span>API routes</span></div>
</div>
<h2>Findings</h2>
${cards}
<div class="note">CVSS computed from stated vectors by assessment/engine/cvss.mjs. Severity is separate from confidence. Authorized local assessment only — no production systems or user data tested.</div>
</div></body></html>`;
}

writeFileSync(path.join(REPO, 'assessment/reports/report.md'), md());
writeFileSync(path.join(REPO, 'assessment/reports/report.html'), html());
// Emit a script-loadable copy so the dashboard renders over file:// (no fetch/CORS).
mkdirSync(path.join(REPO, 'assessment/dashboard'), { recursive: true });
writeFileSync(path.join(REPO, 'assessment/dashboard/data.js'),
  'window.ASSESSMENT = ' + JSON.stringify(assessment, null, 2) + ';\n');
console.log('Wrote assessment/data/assessment.json, assessment/reports/report.{md,html}, assessment/dashboard/data.js');
console.log(`Summary: ${assessment.summary.totalFindings} findings, ${assessment.summary.retested} re-tested PASS, F1 CVSS ${f1.primary.baseScore} ${f1.primary.severity}.`);

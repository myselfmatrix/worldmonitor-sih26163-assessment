#!/usr/bin/env node
/**
 * One-command assessment pipeline:
 *   collect real evidence (PoC + regression suite) -> generate reports + dashboard data.
 * Authorized local assessment only.
 */
import { execFileSync } from 'node:child_process';

function step(name, args) {
  process.stdout.write(`\n▶ ${name}\n`);
  execFileSync(process.execPath, args, { cwd: process.cwd(), stdio: 'inherit' });
}

console.log('SIH26163 assessment pipeline — authorized local environment (no network egress)');
step('Collect evidence (BEFORE/AFTER PoC + F1 regression suite)', ['assessment/engine/collect-evidence.mjs']);
step('Generate assessment.json + reports (MD/HTML) + dashboard data', ['assessment/engine/report.mjs']);
console.log('\n✔ Done. Open assessment/dashboard/index.html or assessment/reports/report.html.');

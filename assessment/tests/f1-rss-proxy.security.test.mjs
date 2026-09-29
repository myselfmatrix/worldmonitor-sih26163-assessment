/**
 * SIH26163 — F1 RSS-proxy egress-policy regression suite (AFTER-fix behavior).
 *
 * Authorized local assessment only. Every request is served by an in-process
 * sidecar with DNS and the HTTPS transport stubbed — no packet leaves the
 * machine, and worldmonitor.app is never contacted.
 *
 * This suite pins the remediation of F1 (self-hosted Docker RSS proxy lacked
 * the destination-domain allowlist and response-size cap that the hosted
 * api/rss-proxy.js enforces). It asserts the FIXED behavior:
 *
 *   allowed domain            -> accepted
 *   disallowed domain         -> 403 (allowlist)
 *   malformed URL             -> rejected
 *   SSRF (localhost/private)  -> 403 (pre-existing guard, still holds)
 *   redirect -> allowed host  -> followed
 *   redirect -> disallowed    -> 403 (per-hop re-validation)
 *   body below cap            -> accepted
 *   body above cap            -> 502 (streaming abort, not buffered unbounded)
 *
 * The BEFORE (vulnerable) behavior is preserved on git tag BASELINE-SIH26163
 * and reproduced by assessment/poc/f1-rss-proxy-poc.mjs.
 */
import { strict as assert } from 'node:assert';
import test from 'node:test';
import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns/promises';
import { EventEmitter } from 'node:events';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp, mkdir, rm } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

const SIDECAR = pathToFileURL(
  path.join(process.cwd(), 'src-tauri/sidecar/local-api-server.mjs'),
).href;
const { createLocalApiServer } = await import(SIDECAR);

const TOKEN = 'sih26163-test-token';
// The sidecar default-denies when LOCAL_API_TOKEN is unset; align it with the
// bearer token the test client presents so we exercise the RSS route, not auth.
process.env.LOCAL_API_TOKEN = TOKEN;
const PUBLIC_IP = '93.184.216.34'; // reserved documentation range, never routed

function authFetch(url) {
  return fetch(url, { headers: { authorization: `Bearer ${TOKEN}` } });
}

async function makeApiDir() {
  const root = await mkdtemp(path.join(os.tmpdir(), 'sih-f1-'));
  const apiDir = path.join(root, 'api');
  await mkdir(apiDir, { recursive: true });
  return { apiDir, cleanup: () => rm(root, { recursive: true, force: true }) };
}

/**
 * Install a synthetic HTTPS transport. `plan(hostname)` returns the response
 * for that host: { status, headers, body } or { status, location } for a
 * redirect, or { bytes } to stream `bytes` bytes of body in 512 KiB chunks
 * (used for the size-cap test; respects req.destroy so the abort is real).
 */
function installTransport(plan) {
  const original = https.request;
  const hosts = [];
  https.request = (options, onResponse) => {
    hosts.push(options.hostname);
    if (typeof options.lookup === 'function') {
      options.lookup(options.hostname, { family: options.family }, () => {});
    }
    const spec = plan(options.hostname);
    const req = new EventEmitter();
    let destroyed = false;
    req.setTimeout = () => {};
    req.write = () => {};
    req.end = () => {
      queueMicrotask(() => {
        const res = new EventEmitter();
        res.statusCode = spec.status ?? 200;
        res.statusMessage = spec.statusMessage ?? 'OK';
        res.headers = { 'content-type': 'application/rss+xml', ...(spec.headers || {}) };
        if (spec.location) res.headers.location = spec.location;
        onResponse(res);
        if (typeof spec.bytes === 'number') {
          const CHUNK = Buffer.alloc(512 * 1024, 0x41);
          let sent = 0;
          const pump = () => {
            if (destroyed) return;
            if (sent >= spec.bytes) { res.emit('end'); return; }
            res.emit('data', CHUNK);
            sent += CHUNK.length;
            queueMicrotask(pump);
          };
          pump();
        } else {
          if (spec.body != null) res.emit('data', Buffer.from(spec.body));
          res.emit('end');
        }
      });
    };
    req.destroy = (err) => { destroyed = true; if (err) req.emit('error', err); };
    return req;
  };
  return { restore: () => { https.request = original; }, hosts };
}

async function withServer(run) {
  const api = await makeApiDir();
  const prevResolve4 = dns.resolve4;
  const prevResolve6 = dns.resolve6;
  dns.resolve4 = async () => [PUBLIC_IP];
  dns.resolve6 = async () => { const e = new Error('no AAAA'); e.code = 'ENODATA'; throw e; };
  const app = await createLocalApiServer({
    port: 0, apiDir: api.apiDir, logger: { log() {}, warn() {}, error() {} },
  });
  const { port } = await app.start();
  try {
    await run(port);
  } finally {
    dns.resolve4 = prevResolve4;
    dns.resolve6 = prevResolve6;
    await app.close();
    await api.cleanup();
  }
}

function withStrictAllowlist(list, run) {
  const prev = process.env.WM_RSS_ALLOWED_DOMAINS;
  const prevStrict = process.env.WM_RSS_ALLOWED_DOMAINS_STRICT;
  process.env.WM_RSS_ALLOWED_DOMAINS = list;
  process.env.WM_RSS_ALLOWED_DOMAINS_STRICT = '1';
  const restore = () => {
    if (prev === undefined) delete process.env.WM_RSS_ALLOWED_DOMAINS;
    else process.env.WM_RSS_ALLOWED_DOMAINS = prev;
    if (prevStrict === undefined) delete process.env.WM_RSS_ALLOWED_DOMAINS_STRICT;
    else process.env.WM_RSS_ALLOWED_DOMAINS_STRICT = prevStrict;
  };
  return Promise.resolve(run()).finally(restore);
}

const feed = (port, url) =>
  authFetch(`http://127.0.0.1:${port}/api/rss-proxy?url=${encodeURIComponent(url)}`);

// ── Unit: allowlist predicate ─────────────────────────────────────────────
test('F1-unit: allowlist predicate is www-tolerant and default-deny', async () => {
  const mod = await import(SIDECAR);
  const { isRssDomainAllowed } = mod.__testing__;
  const allow = new Set(['feeds.bbci.co.uk', 'example.org']);
  assert.equal(isRssDomainAllowed('feeds.bbci.co.uk', allow), true);
  assert.equal(isRssDomainAllowed('www.example.org', allow), true, 'www. tolerated');
  assert.equal(isRssDomainAllowed('example.org', allow), true);
  assert.equal(isRssDomainAllowed('attacker.example', allow), false, 'default deny');
  assert.equal(isRssDomainAllowed('evilexample.org', allow), false, 'no suffix confusion');
});

// ── Allowed vs disallowed domain ──────────────────────────────────────────
test('F1: allowed domain is accepted', async () => {
  await withStrictAllowlist('allowed.example', () => withServer(async (port) => {
    const t = installTransport(() => ({ status: 200, body: '<rss><channel/></rss>' }));
    try {
      const res = await feed(port, 'https://allowed.example/feed.xml');
      assert.equal(res.status, 200);
      assert.equal(await res.text(), '<rss><channel/></rss>');
    } finally { t.restore(); }
  }));
});

test('F1: disallowed domain is rejected with 403 (the fix)', async () => {
  await withStrictAllowlist('allowed.example', () => withServer(async (port) => {
    const t = installTransport(() => ({ status: 200, body: 'SHOULD-NOT-BE-FETCHED' }));
    try {
      const res = await feed(port, 'https://attacker-chosen.example/anything');
      assert.equal(res.status, 403);
      assert.equal(t.hosts.length, 0, 'no outbound request was made to the disallowed host');
      assert.match(res.headers.get('content-security-policy') || '', /sandbox/);
    } finally { t.restore(); }
  }));
});

// ── Malformed / non-http input ────────────────────────────────────────────
test('F1: malformed and non-http URLs are rejected', async () => {
  await withStrictAllowlist('allowed.example', () => withServer(async (port) => {
    for (const bad of ['not-a-url', 'ftp://allowed.example/x', 'file:///etc/passwd']) {
      const res = await feed(port, bad);
      assert.ok(res.status === 400 || res.status === 403, `${bad} -> ${res.status}`);
    }
    const missing = await authFetch(`http://127.0.0.1:${port}/api/rss-proxy`);
    assert.equal(missing.status, 400);
  }));
});

// ── SSRF guard still holds ahead of the allowlist ─────────────────────────
test('F1: SSRF targets (localhost / private) are rejected', async () => {
  await withStrictAllowlist('allowed.example', () => withServer(async (port) => {
    for (const url of ['http://localhost/x', 'http://127.0.0.1/x', 'http://169.254.169.254/latest/meta-data/']) {
      const res = await feed(port, url);
      assert.equal(res.status, 403, `${url} should be SSRF-blocked`);
    }
  }));
});

// ── Redirect re-validation ────────────────────────────────────────────────
test('F1: redirect to an allowed host is followed', async () => {
  await withStrictAllowlist('allowed.example,mirror.example', () => withServer(async (port) => {
    const t = installTransport((host) =>
      host === 'allowed.example'
        ? { status: 302, location: 'https://mirror.example/real.xml' }
        : { status: 200, body: '<rss>mirrored</rss>' });
    try {
      const res = await feed(port, 'https://allowed.example/feed.xml');
      assert.equal(res.status, 200);
      assert.equal(await res.text(), '<rss>mirrored</rss>');
      assert.deepEqual(t.hosts, ['allowed.example', 'mirror.example']);
    } finally { t.restore(); }
  }));
});

test('F1: redirect to a disallowed host is rejected (per-hop re-validation)', async () => {
  await withStrictAllowlist('allowed.example', () => withServer(async (port) => {
    const t = installTransport((host) =>
      host === 'allowed.example'
        ? { status: 302, location: 'https://attacker-chosen.example/x' }
        : { status: 200, body: 'LEAK' });
    try {
      const res = await feed(port, 'https://allowed.example/feed.xml');
      assert.equal(res.status, 403);
      assert.deepEqual(t.hosts, ['allowed.example'], 'never connected to the redirect target');
    } finally { t.restore(); }
  }));
});

// ── Response-size cap ─────────────────────────────────────────────────────
test('F1: body below the cap is accepted', async () => {
  await withStrictAllowlist('allowed.example', () => withServer(async (port) => {
    const t = installTransport(() => ({ status: 200, bytes: 1 * 1024 * 1024 })); // 1 MB < 5 MB
    try {
      const res = await feed(port, 'https://allowed.example/feed.xml');
      assert.equal(res.status, 200);
      assert.equal((await res.text()).length, 1 * 1024 * 1024);
    } finally { t.restore(); }
  }));
});

test('F1: body above the cap is aborted, not buffered unbounded (the fix)', async () => {
  await withStrictAllowlist('allowed.example', () => withServer(async (port) => {
    const t = installTransport(() => ({ status: 200, bytes: 32 * 1024 * 1024 })); // 32 MB > 5 MB
    try {
      const res = await feed(port, 'https://allowed.example/feed.xml');
      assert.equal(res.status, 502);
      const body = await res.json();
      assert.match(body.error, /maximum allowed size/i);
    } finally { t.restore(); }
  }));
});

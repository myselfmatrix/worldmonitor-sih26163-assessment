/**
 * Attack-surface discovery for the World Monitor assessment.
 * Reads the real repository (no network) and returns structured surface data
 * that the report and dashboard render. Facts only — counts and names come
 * from the filesystem, never invented.
 */
import { readdirSync, statSync, existsSync, readFileSync } from 'node:fs';
import path from 'node:path';

function walk(dir, acc = []) {
  if (!existsSync(dir)) return acc;
  for (const entry of readdirSync(dir)) {
    const full = path.join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) walk(full, acc);
    else acc.push(full);
  }
  return acc;
}

function toRoute(repo, file) {
  const rel = path.relative(path.join(repo, 'api'), file).split(path.sep).join('/');
  return '/api/' + rel.replace(/\.(ts|js)$/, '').replace(/\/index$/, '');
}

export function discover(repo = process.cwd()) {
  // ── API routes ──────────────────────────────────────────────────────────
  const apiFiles = walk(path.join(repo, 'api'))
    .filter((f) => /\.(ts|js)$/.test(f))
    .filter((f) => !/\.test\.|\.d\.ts$/.test(f))
    .filter((f) => !path.basename(f).startsWith('_')); // helpers, not routes
  const routes = apiFiles.map((f) => toRoute(repo, f)).sort();
  const rpcRoutes = routes.filter((r) => r.includes('[rpc]'));
  const restRoutes = routes.filter((r) => !r.includes('[rpc]'));

  // ── Docker services ─────────────────────────────────────────────────────
  let dockerServices = [];
  const composePath = path.join(repo, 'docker-compose.yml');
  if (existsSync(composePath)) {
    const yml = readFileSync(composePath, 'utf8');
    // Take the services: block only, stopping at the next top-level key
    // (e.g. volumes:/networks:) so volume names are not mistaken for services.
    const afterServices = yml.split(/^services:/m)[1] ?? '';
    const svcBlock = afterServices.split(/^\S/m)[0] ?? afterServices;
    for (const line of svcBlock.split('\n')) {
      const m = line.match(/^ {2}([a-z0-9_-]+):\s*$/i);
      if (m) dockerServices.push(m[1]);
    }
  }

  // ── Configuration surfaces ──────────────────────────────────────────────
  const configSurfaces = [
    'vercel.json', 'middleware.ts', 'docker/nginx.conf', 'docker/nginx.conf.template',
    'docker-compose.yml', 'docker/entrypoint.sh', '.env.example', 'src-tauri/tauri.conf.json',
  ].filter((p) => existsSync(path.join(repo, p)));

  // ── Frontend entry points ───────────────────────────────────────────────
  const frontendEntries = readdirSync(repo)
    .filter((f) => f.endsWith('.html'))
    .sort();

  // ── Security-sensitive helpers (for source-review view) ─────────────────
  const securityHelpers = [
    'api/_api-key.js', 'api/_cors.js', 'api/_rate-limit.js', 'api/_client-ip.js',
    'api/_session.js', 'api/rss-proxy.js', 'api/_rss-allowed-domain-match.js',
    'src-tauri/sidecar/local-api-server.mjs',
  ].filter((p) => existsSync(path.join(repo, p)));

  return {
    generatedAt: new Date().toISOString(),
    counts: {
      apiRoutes: routes.length,
      rpcRoutes: rpcRoutes.length,
      restRoutes: restRoutes.length,
      dockerServices: dockerServices.length,
      configSurfaces: configSurfaces.length,
      frontendEntries: frontendEntries.length,
    },
    dockerServices,
    configSurfaces,
    frontendEntries,
    securityHelpers,
    focusRoute: {
      route: '/api/rss-proxy',
      hostedImpl: 'api/rss-proxy.js',
      selfHostedImpl: 'src-tauri/sidecar/local-api-server.mjs',
      note: 'Primary case study (F1): hosted vs self-hosted egress-control divergence.',
    },
    sampleRestRoutes: restRoutes.slice(0, 24),
  };
}

if (process.argv[1]?.endsWith('discover.mjs')) {
  console.log(JSON.stringify(discover(), null, 2));
}

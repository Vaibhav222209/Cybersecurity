import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createPlatform } from '../server/platform.js';

async function lab(t, options = {}) {
  const platform = createPlatform({ dbPath: ':memory:', demo: false, ...options });
  await platform.start(0);
  t.after(() => platform.stop());
  return platform;
}

async function request(platform, path, body, options = {}) {
  const response = await fetch(`${platform.url}${path}`, {
    method: body === undefined ? 'GET' : 'POST',
    headers: { ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...options.headers },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { status: response.status, data: await response.json(), headers: response.headers };
}

test('imported log events match threat intelligence and preserve real event provenance', async (t) => {
  const platform = await lab(t);
  const imported = await request(platform, '/api/indicators', { type: 'domain', value: 'malware.example.org', threat: 'Malware callback destination', confidence: 95 });
  assert.equal(imported.status, 201);
  const result = await request(platform, '/api/ingest', {
    assetId: 'asset-dev', sourceIp: '192.0.2.51', domain: 'MALWARE.EXAMPLE.ORG',
    severity: 'info', category: 'dns', message: 'Imported resolver event with known destination', origin: 'lab-history',
  });
  assert.equal(result.status, 202);
  assert.equal(result.data.logs[0].action, 'detected');
  assert.equal(result.data.logs[0].severity, 'critical');
  assert.equal(result.data.logs[0].origin, 'ingested');
  const snapshot = (await request(platform, '/api/state')).data;
  assert.equal(snapshot.incidents.length, 1);
  assert.equal(snapshot.incidents[0].playbookId, 'pb-malware');
  assert.equal(snapshot.metrics.events24h, 1);
});

test('five failed authentication events correlate into a brute-force incident', async (t) => {
  const platform = await lab(t);
  const events = Array.from({ length: 5 }, (_, index) => ({ sourceIp: '192.0.2.54', assetId: 'asset-finance', category: 'authentication', message: `Failed login attempt ${index + 1}` }));
  const result = await request(platform, '/api/ingest', { events });
  assert.equal(result.status, 202);
  assert.equal(result.data.logs[4].technique, 'T1110 · Brute Force');
  assert.equal(result.data.logs[4].action, 'detected');
  assert.equal(platform.state().incidents[0].playbookId, 'pb-brute-force');
});

test('isolation, quarantine, restore, and blocking enforce actual workload HTTP denial', async (t) => {
  const platform = await lab(t);
  assert.equal((await request(platform, '/lab/asset-finance/home')).status, 200);
  const isolation = await request(platform, '/api/assets/asset-finance/action', { action: 'isolate' });
  assert.equal(isolation.status, 200);
  assert.equal(isolation.data.verifiedStatus, 423);
  assert.equal((await request(platform, '/lab/asset-finance/home')).status, 423);
  assert.equal((await request(platform, '/lab/asset-finance/health')).status, 200);
  assert.equal((await request(platform, '/api/assets/asset-finance/action', { action: 'quarantine' })).data.asset.status, 'quarantined');
  assert.equal((await request(platform, '/api/assets/asset-finance/action', { action: 'restore' })).data.verifiedStatus, 200);
  assert.equal((await request(platform, '/lab/asset-finance/home')).status, 200);
  const block = await request(platform, '/api/block', { sourceIp: '203.0.113.61' });
  assert.equal(block.status, 200);
  assert.equal(block.data.verifiedStatus, 403);
  assert.equal((await request(platform, '/lab/asset-finance/home', undefined, { headers: { 'x-lab-source-ip': '203.0.113.61' } })).status, 403);
  assert.equal((await request(platform, '/lab/asset-finance/home', undefined, { headers: { 'x-lab-source-ip': '203.0.113.62' } })).status, 200);
  assert.ok(platform.state().logs.some((log) => log.action === 'blocked' && log.sourceIp === '203.0.113.61'));
  assert.equal(platform.state().blockedSources[0].sourceIp, '203.0.113.61');
  assert.equal((await request(platform, '/api/unblock', { sourceIp: '203.0.113.61' })).status, 200);
  assert.equal((await request(platform, '/lab/asset-finance/home', undefined, { headers: { 'x-lab-source-ip': '203.0.113.61' } })).status, 200);
});

test('scan probes real endpoints; each mitigation changes the workload and passes a new probe', async (t) => {
  const platform = await lab(t);
  const scan = await request(platform, '/api/scan', { assetId: 'asset-dev' });
  assert.equal(scan.status, 200);
  assert.equal(scan.data.findings.length, 3);
  assert.ok(scan.data.findings.every((finding) => finding.status === 'open' && finding.evidence.includes('/lab/asset-dev/')));
  assert.equal(platform.state().incidents.length, 0, 'Authorized VAPT probes must not create attack incidents');
  const ids = scan.data.findings.map((finding) => finding.id);
  for (const id of ids) {
    const mitigation = await request(platform, `/api/findings/${id}/mitigate`, {});
    assert.equal(mitigation.status, 200);
    assert.equal(mitigation.data.finding.status, 'mitigated');
    assert.ok(mitigation.data.finding.verifiedAt);
  }
  const home = await request(platform, '/lab/asset-dev/home');
  assert.equal(home.headers.get('x-frame-options'), 'DENY');
  assert.ok(home.headers.get('content-security-policy'));
  assert.equal((await request(platform, '/lab/asset-dev/debug')).status, 403);
  const loginStatuses = [];
  for (let i = 0; i < 6; i++) loginStatuses.push((await request(platform, '/lab/asset-dev/login', { username: 'tester', password: 'invalid' }, { headers: { 'x-lab-source-ip': '192.0.2.75' } })).status);
  assert.deepEqual(loginStatuses, [401, 401, 401, 401, 401, 429]);
  const retest = await request(platform, '/api/scan', { assetId: 'asset-dev' });
  assert.equal(retest.status, 200);
  assert.ok(retest.data.findings.every((finding) => finding.status === 'mitigated'));
  assert.equal(platform.state().findings.length, 3, 'Scans update existing findings rather than duplicating them');
  assert.equal(platform.state().metrics.criticalFindings, 0);
});

test('lab attack scenarios make real requests and their response reflects deny rules', async (t) => {
  const platform = await lab(t);
  const scenario = await request(platform, '/api/demo/scenario', { scenario: 'brute-force' });
  assert.equal(scenario.status, 200);
  assert.deepEqual(scenario.data.responses, Array(8).fill(401));
  assert.equal(platform.state().logs.length, 8);
  assert.ok(platform.state().incidents.some((incident) => incident.playbookId === 'pb-brute-force'));
  await request(platform, '/api/block', { sourceIp: scenario.data.sourceIp });
  const blocked = await request(platform, '/api/demo/scenario', { scenario: 'brute-force' });
  assert.deepEqual(blocked.data.responses, Array(8).fill(403));
  assert.ok(platform.state().audit.some((item) => item.action === 'Local lab scenario executed'));
});

test('SQLite preserves evidence, deny rules, mitigations, and playbook progress across restarts', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'aegis-backend-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const dbPath = join(directory, 'lab.db');
  const first = createPlatform({ dbPath, demo: false });
  await first.start(0);
  await request(first, '/api/scan', { assetId: 'asset-gateway' });
  const finding = first.state().findings.find((item) => item.check === 'public-debug');
  await request(first, `/api/findings/${finding.id}/mitigate`, {});
  await request(first, '/api/block', { sourceIp: '198.51.100.80' });
  await request(first, '/api/assets/asset-finance/action', { action: 'quarantine' });
  const playbook = first.state().playbooks[0];
  await request(first, `/api/playbooks/${playbook.id}/steps/${playbook.steps[0].id}`, { completed: true });
  const logCount = first.state().metrics.events24h;
  await first.stop();
  const second = await lab(t, { dbPath });
  assert.equal(second.state().assets.find((item) => item.id === 'asset-finance').status, 'quarantined');
  assert.equal(second.state().findings.find((item) => item.id === finding.id).status, 'mitigated');
  assert.equal(second.state().playbooks.find((item) => item.id === playbook.id).steps[0].completed, true);
  assert.equal(second.state().metrics.events24h, logCount);
  assert.equal((await request(second, '/lab/asset-finance/home')).status, 423);
  assert.equal((await request(second, '/lab/asset-gateway/debug')).status, 403);
  assert.equal((await request(second, '/lab/asset-gateway/home', undefined, { headers: { 'x-lab-source-ip': '198.51.100.80' } })).status, 403);
});

test('validation rejects invalid and partial batches, arbitrary scan targets, unsafe mutations, and missing tokens', async (t) => {
  const platform = await lab(t, { ingestToken: 'local-test-token' });
  assert.equal((await request(platform, '/api/ingest', { message: 'event' })).status, 401);
  const auth = { headers: { Authorization: 'Bearer local-test-token' } };
  const batch = await request(platform, '/api/ingest', { events: [{ message: 'good' }, { sourceIp: 'invalid-ip', message: 'bad' }] }, auth);
  assert.equal(batch.status, 400);
  assert.equal(platform.state().logs.length, 0);
  assert.equal((await request(platform, '/api/ingest', { severity: 'extreme' }, auth)).status, 400);
  assert.equal((await request(platform, '/api/ingest', { timestamp: 'yesterday' }, auth)).status, 400);
  assert.equal((await request(platform, '/api/ingest', { message: 'valid-token event' }, auth)).status, 202);
  assert.equal((await request(platform, '/api/scan', { url: 'http://169.254.169.254/' })).status, 400);
  assert.equal((await request(platform, '/api/scan', { assetId: 'unknown-asset' })).status, 404);
  assert.equal((await request(platform, '/api/assets/asset-dev/action', { action: 'delete' })).status, 400);
  assert.equal((await request(platform, '/api/indicators', { type: 'domain', value: 'https://example.org/path' })).status, 400);
  assert.equal((await request(platform, '/api/block', { sourceIp: '192.0.2.1' }, { headers: { Origin: 'https://unrelated.example' } })).status, 403);
  await request(platform, '/api/assets/asset-dev/action', { action: 'isolate' });
  assert.equal((await request(platform, '/api/scan', { assetId: 'asset-dev' })).status, 409);
});

test('SSE begins with full live state and publishes newly accepted events', async (t) => {
  const platform = await lab(t);
  const abort = new AbortController();
  const response = await fetch(`${platform.url}/api/events`, { signal: abort.signal });
  assert.equal(response.headers.get('content-type'), 'text/event-stream');
  const reader = response.body.getReader();
  const initial = new TextDecoder().decode((await reader.read()).value);
  assert.match(initial, /event: state/);
  assert.match(initial, /"mode":"local-lab"/);
  await request(platform, '/api/ingest', { message: 'SSE assertion event', sourceIp: '192.0.2.90' });
  const update = new TextDecoder().decode((await reader.read()).value);
  assert.match(update, /SSE assertion event/);
  await reader.cancel();
  abort.abort();
});

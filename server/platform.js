import express from 'express';
import { DatabaseSync } from 'node:sqlite';
import { existsSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isIP } from 'node:net';
import { randomUUID, timingSafeEqual } from 'node:crypto';
import { playbooks as standardPlaybooks } from './playbooks.js';

const SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info']);
const INCIDENT_STATUSES = new Set(['open', 'investigating', 'contained', 'resolved']);
const TYPES = new Set(['ip', 'domain', 'hash']);
const LOCAL_ADDRESSES = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);
const iso = () => new Date().toISOString();
const uid = (prefix) => `${prefix}-${randomUUID().slice(0, 8)}`;
const stripMapped = (ip) => ip?.replace(/^::ffff:/, '') || '127.0.0.1';

class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

function string(value, name, max = 500, fallback) {
  if (value === undefined && fallback !== undefined) return fallback;
  if (typeof value !== 'string' || !value.trim() || value.length > max) {
    throw new ApiError(400, `${name} must be a nonempty string of at most ${max} characters.`);
  }
  return value.trim();
}

const seedAssets = () => [
  { id: 'asset-gateway', name: 'atlas-gateway', ip: '10.10.0.1', os: 'Ubuntu 24.04', type: 'Gateway', riskScore: 42 },
  { id: 'asset-finance', name: 'finance-ws-01', ip: '10.10.0.12', os: 'Windows 11 lab workload', type: 'Workstation', riskScore: 78 },
  { id: 'asset-dev', name: 'dev-server-02', ip: '10.10.0.24', os: 'Ubuntu 24.04 lab workload', type: 'Server', riskScore: 63 },
  { id: 'asset-analyst', name: 'analyst-mbp', ip: '10.10.0.33', os: 'macOS lab workload', type: 'Workstation', riskScore: 18 },
].map((asset) => ({ ...asset, status: 'online', lastSeen: iso(), managed: true }));

const seedIndicators = () => [
  { type: 'ip', value: '198.51.100.66', threat: 'Lab command-and-control callback', confidence: 98 },
  { type: 'ip', value: '203.0.113.42', threat: 'Lab credential attack source', confidence: 94 },
  { type: 'ip', value: '192.0.2.88', threat: 'Lab reconnaissance source', confidence: 86 },
  { type: 'domain', value: 'beacon.lab.invalid', threat: 'Lab malware beacon domain', confidence: 96 },
  { type: 'domain', value: 'login-update.lab.invalid', threat: 'Lab phishing destination', confidence: 91 },
  { type: 'hash', value: 'a'.repeat(64), threat: 'Harmless lab artifact identifier', confidence: 100 },
].map((item) => ({ id: uid('ioc'), ...item, source: 'Local lab intelligence (reserved test indicators)', lastSeen: iso() }));

/**
 * A local-only SIEM and vulnerability lab. All remediation and containment affect
 * registered HTTP lab workloads, never the host firewall or arbitrary targets.
 */
export function createPlatform({ dbPath = 'data/aegis.db', demo = true, ingestToken = process.env.INGEST_TOKEN || '' } = {}) {
  if (dbPath !== ':memory:') mkdirSync(dirname(resolve(dbPath)), { recursive: true });
  const db = new DatabaseSync(dbPath);
  db.exec(`
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS objects (collection TEXT NOT NULL, id TEXT NOT NULL, body TEXT NOT NULL, PRIMARY KEY(collection,id));
    CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS event_buckets (hour TEXT PRIMARY KEY, events INTEGER NOT NULL DEFAULT 0, threats INTEGER NOT NULL DEFAULT 0);
  `);
  const queries = {
    save: db.prepare('INSERT INTO objects(collection,id,body) VALUES(?,?,?) ON CONFLICT(collection,id) DO UPDATE SET body=excluded.body'),
    all: db.prepare('SELECT body FROM objects WHERE collection=?'),
    remove: db.prepare('DELETE FROM objects WHERE collection=? AND id=?'),
    setting: db.prepare('SELECT value FROM settings WHERE key=?'),
    set: db.prepare('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value'),
    bucket: db.prepare('INSERT INTO event_buckets(hour,events,threats) VALUES(?,1,?) ON CONFLICT(hour) DO UPDATE SET events=events+1, threats=threats+excluded.threats'),
  };
  const collections = ['assets', 'logs', 'incidents', 'findings', 'indicators', 'playbooks', 'audit', 'configs', 'blocked'];
  const data = Object.fromEntries(collections.map((collection) => [collection, new Map(queries.all.all(collection).map(({ body }) => { const item = JSON.parse(body); return [item.id, item]; }))]));
  const values = (collection) => [...data[collection].values()];
  function save(collection, item) {
    data[collection].set(item.id, item);
    queries.save.run(collection, item.id, JSON.stringify(item));
    return item;
  }
  const setting = (key) => queries.setting.get(key)?.value;
  const setSetting = (key, value) => queries.set.run(key, String(value));
  function trim(collection, max) {
    while (data[collection].size > max) {
      const first = values(collection).reduce((oldest, item) => !oldest || item.timestamp < oldest.timestamp ? item : oldest, null).id;
      data[collection].delete(first);
      queries.remove.run(collection, first);
    }
  }
  if (!data.assets.size) {
    seedAssets().forEach((asset) => {
      save('assets', asset);
      save('configs', { id: asset.id, securityHeaders: false, debugEnabled: true, loginRateLimit: false });
    });
  }
  if (!data.playbooks.size) standardPlaybooks.forEach((playbook) => save('playbooks', structuredClone(playbook)));
  if (!setting('indicatorsSeeded')) {
    seedIndicators().forEach((indicator) => save('indicators', indicator));
    setSetting('indicatorsSeeded', true);
  }

  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', false);
  app.use(express.json({ limit: '256kb', strict: true }));
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    if (req.path.startsWith('/api/')) res.setHeader('Cache-Control', 'no-store');
    next();
  });
  let server;
  let baseUrl;
  let simulation;
  let closed = false;
  let tick = 0;
  let publishScheduled = false;
  const streams = new Set();
  const failedLogins = new Map();
  const recentAuth = new Map();
  const recentlyDetected = new Map();

  function audit(action, target, result) {
    save('audit', { id: uid('audit'), timestamp: iso(), action, target, result });
    trim('audit', 250);
  }
  function assetFor(id) {
    const asset = data.assets.get(id);
    if (!asset) throw new ApiError(404, 'Registered lab asset not found.');
    return asset;
  }
  function normalizedLog(input) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw new ApiError(400, 'Each event must be an object.');
    const asset = assetFor(string(input.assetId, 'assetId', 80, 'asset-gateway'));
    const sourceIp = string(input.sourceIp, 'sourceIp', 45, '127.0.0.1');
    if (!isIP(sourceIp)) throw new ApiError(400, 'sourceIp must be a valid IPv4 or IPv6 address.');
    const severity = input.severity ?? 'info';
    if (!SEVERITIES.has(severity)) throw new ApiError(400, 'severity must be critical, high, medium, low, or info.');
    const timestamp = input.timestamp ?? iso();
    if (typeof timestamp !== 'string' || Number.isNaN(Date.parse(timestamp)) || Math.abs(Date.parse(timestamp) - Date.now()) > 7 * 24 * 3600 * 1000) {
      throw new ApiError(400, 'timestamp must be a valid date within seven days of the current time.');
    }
    const extra = {};
    for (const key of ['domain', 'hash']) if (input[key] !== undefined) extra[key] = string(input[key], key, 256);
    return {
      id: uid('log'), timestamp: new Date(timestamp).toISOString(), severity, sourceIp,
      assetId: asset.id, assetName: asset.name, category: string(input.category, 'category', 80, 'application'),
      message: string(input.message, 'message', 1200, 'Lab workload request'), action: 'allowed', rule: 'Event collection',
      technique: '', origin: input.origin || 'ingested', ...extra,
    };
  }
  function createIncident(log, title, description, playbookId, technique) {
    const existing = values('incidents').find((item) => item.assetId === log.assetId && item.sourceIp === log.sourceIp && item.playbookId === playbookId && item.status !== 'resolved');
    if (existing) return existing;
    const incident = save('incidents', {
      id: uid('inc'), title, severity: log.severity === 'critical' ? 'critical' : 'high', status: 'open',
      assetId: log.assetId, assetName: log.assetName, sourceIp: log.sourceIp, createdAt: log.timestamp,
      technique, description, playbookId,
    });
    audit('Detection created incident', incident.id, title);
    return incident;
  }
  function appendLog(input, { forceAction, bypassDetection = false } = {}) {
    const log = normalizedLog(input);
    if (!bypassDetection) {
      const indicator = values('indicators').find((ioc) =>
        (ioc.type === 'ip' && ioc.value === log.sourceIp) ||
        (ioc.type === 'domain' && ioc.value.toLowerCase() === log.domain?.toLowerCase()) ||
        (ioc.type === 'hash' && ioc.value.toLowerCase() === log.hash?.toLowerCase()));
      if (indicator) {
        const malware = /malware|command|beacon|artifact/i.test(indicator.threat);
        const credentialAttack = /credential|brute.force/i.test(indicator.threat);
        log.severity = malware ? 'critical' : 'high';
        log.action = 'detected';
        log.rule = `Threat intelligence match: ${indicator.type}`;
        log.technique = malware ? 'T1071 · Application Layer Protocol' : credentialAttack ? 'T1110 · Brute Force' : 'T1595 · Active Scanning';
        indicator.lastSeen = log.timestamp;
        save('indicators', indicator);
        createIncident(log, malware ? 'Suspicious command-and-control callback' : credentialAttack ? 'Known credential attack source observed' : 'Known suspicious source observed',
          `${log.origin === 'ingested' ? 'Imported telemetry' : 'A local lab event'} matched ${indicator.value}: ${indicator.threat}. Review event evidence before selecting a response.`,
          malware ? 'pb-malware' : credentialAttack ? 'pb-brute-force' : 'pb-recon', log.technique);
      }
      if (log.category === 'authentication' && /failed|invalid|denied/i.test(log.message)) {
        const key = `${log.assetId}:${log.sourceIp}`;
        const attempts = [...(recentAuth.get(key) || []), Date.now()].filter((time) => Date.now() - time < 60_000);
        recentAuth.set(key, attempts);
        if (attempts.length >= 5) {
          log.severity = 'high';
          log.action = 'detected';
          log.rule = 'Five failed authentications in 60 seconds';
          log.technique = 'T1110 · Brute Force';
          createIncident(log, 'Repeated credential attack detected',
            `${attempts.length} failed authentication events in one minute against ${log.assetName} from ${log.sourceIp}. Evidence source: ${log.origin === 'ingested' ? 'imported telemetry' : 'local lab requests'}.`,
            'pb-brute-force', log.technique);
        }
      }
      if (log.category === 'reconnaissance') {
        log.severity = 'medium';
        log.action = 'detected';
        log.rule = 'Sensitive debug endpoint accessed';
        log.technique = 'T1595 · Active Scanning';
        const key = `${log.assetId}:${log.sourceIp}`;
        if (Date.now() - (recentlyDetected.get(key) || 0) > 30_000) {
          createIncident(log, 'Exposed debug endpoint accessed', log.origin === 'ingested' ? 'An imported reconnaissance event reported a debug endpoint access. Review the original telemetry to verify exposure.' : 'A real request reached the deliberately vulnerable local debug route.', 'pb-recon', log.technique);
          recentlyDetected.set(key, Date.now());
        }
      }
    }
    if (forceAction) log.action = forceAction;
    save('logs', log);
    trim('logs', 5000);
    const hour = log.timestamp.slice(0, 13);
    queries.bucket.run(hour, log.action !== 'allowed' ? 1 : 0);
    const asset = data.assets.get(log.assetId);
    if (log.timestamp > asset.lastSeen) asset.lastSeen = log.timestamp;
    save('assets', asset);
    schedulePublish();
    return log;
  }
  function state() {
    const allLogs = values('logs').sort((a, b) => b.timestamp.localeCompare(a.timestamp));
    const incidents = values('incidents').sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    const findings = values('findings').sort((a, b) => ({ critical: 0, high: 1, medium: 2, low: 3 }[a.severity] ?? 4) - ({ critical: 0, high: 1, medium: 2, low: 3 }[b.severity] ?? 4));
    const now = Date.now();
    const dayHour = new Date(now - 24 * 3600 * 1000).toISOString().slice(0, 13);
    const totals = db.prepare('SELECT COALESCE(SUM(events),0) as events FROM event_buckets WHERE hour >= ?').get(dayHour);
    const recent = allLogs.filter((log) => now - Date.parse(log.timestamp) < 10_000);
    const series = Array.from({ length: 12 }, (_, i) => {
      const from = now - (12 - i) * 30_000;
      const to = from + 30_000;
      const points = allLogs.filter((log) => Date.parse(log.timestamp) >= from && Date.parse(log.timestamp) < to);
      return { time: new Date(to).toISOString().slice(11, 19), events: points.length, threats: points.filter((log) => log.action !== 'allowed').length };
    });
    return {
      metrics: {
        events24h: Number(totals.events), activeThreats: incidents.filter((incident) => ['open', 'investigating'].includes(incident.status)).length,
        criticalFindings: findings.filter((finding) => finding.status === 'open' && finding.severity === 'critical').length,
        protectedAssets: values('assets').filter((asset) => asset.managed).length, eps: Math.round(recent.length / 10 * 10) / 10,
        blockedSources: data.blocked.size, health: 'healthy',
      },
      series, logs: allLogs.slice(0, 1000), incidents, assets: values('assets'), findings,
      indicators: values('indicators'), playbooks: values('playbooks'), audit: values('audit').sort((a, b) => b.timestamp.localeCompare(a.timestamp)).slice(0, 100),
      blockedSources: values('blocked').map(({ sourceIp, createdAt }) => ({ sourceIp, createdAt })),
      mode: 'local-lab',
    };
  }
  function publish() {
    if (closed || !streams.size) return;
    const event = `event: state\ndata: ${JSON.stringify(state())}\n\n`;
    for (const res of streams) {
      if (!res.writableEnded) res.write(event);
    }
  }
  function schedulePublish() {
    if (publishScheduled || closed) return;
    publishScheduled = true;
    queueMicrotask(() => { publishScheduled = false; publish(); });
  }
  const handler = (fn) => (req, res, next) => Promise.resolve().then(() => fn(req, res)).catch(next);
  function requireIngestToken(req) {
    if (!ingestToken) return;
    const supplied = req.headers.authorization?.replace(/^Bearer\s+/i, '') || '';
    const wantedBytes = Buffer.from(ingestToken);
    const givenBytes = Buffer.from(supplied);
    if (givenBytes.length !== wantedBytes.length || !timingSafeEqual(givenBytes, wantedBytes)) throw new ApiError(401, 'A valid ingest bearer token is required.');
  }
  function managementOnly(req, res, next) {
    if (!LOCAL_ADDRESSES.has(req.socket.remoteAddress)) return res.status(403).json({ error: 'Management actions are restricted to the local lab host.' });
    const origin = req.get('origin');
    if (origin) {
      try {
        const originUrl = new URL(origin);
        const localOrigin = ['localhost', '127.0.0.1', '[::1]'].includes(originUrl.hostname) && ['3001', '5173', String(server?.address()?.port)].includes(originUrl.port);
        if (!localOrigin && originUrl.host !== req.get('host')) return res.status(403).json({ error: 'Management requests must originate from the local dashboard.' });
      } catch { return res.status(403).json({ error: 'Invalid Origin header.' }); }
    }
    next();
  }
  app.get('/api/health', (req, res) => res.json({ status: 'healthy', mode: 'local-lab', database: 'sqlite', version: '1.0.0' }));
  app.get('/api/state', (req, res) => res.json(state()));
  app.get('/api/events', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders();
    res.write(`retry: 3000\nevent: state\ndata: ${JSON.stringify(state())}\n\n`);
    streams.add(res);
    const heartbeat = setInterval(() => res.write(': keepalive\n\n'), 15_000);
    heartbeat.unref();
    req.on('close', () => { clearInterval(heartbeat); streams.delete(res); });
  });
  app.post('/api/ingest', handler((req, res) => {
    requireIngestToken(req);
    const events = Array.isArray(req.body?.events) ? req.body.events : [req.body];
    if (!events.length || events.length > 100) throw new ApiError(400, 'Send between 1 and 100 events per batch.');
    // Validate the entire batch before accepting any event.
    events.forEach(normalizedLog);
    const accepted = events.map((event) => appendLog({ ...event, origin: 'ingested' }));
    res.status(202).json({ message: `${accepted.length} event(s) accepted.`, accepted: accepted.length, logs: accepted });
  }));
  app.use('/api', (req, res, next) => req.method === 'GET' ? next() : managementOnly(req, res, next));

  app.post('/api/assets/:id/action', handler((req, res) => {
    const asset = assetFor(req.params.id);
    const action = req.body?.action;
    if (!['isolate', 'quarantine', 'restore'].includes(action)) throw new ApiError(400, 'action must be isolate, quarantine, or restore.');
    const previous = asset.status;
    asset.status = ({ isolate: 'isolated', quarantine: 'quarantined', restore: 'online' })[action];
    save('assets', asset);
    const verify = baseUrl ? awaitStatus(`/lab/${asset.id}/home`, { headers: { 'x-lab-source-ip': probeSource() } }) : Promise.resolve(null);
    return verify.then((status) => {
      const expected = action === 'restore' ? 200 : 423;
      if (status !== null && status !== expected) {
        asset.status = previous; save('assets', asset);
        throw new ApiError(500, 'Lab containment verification failed; the prior status was restored.');
      }
      if (action !== 'restore') {
        for (const incident of values('incidents').filter((item) => item.assetId === asset.id && ['open', 'investigating'].includes(item.status))) {
          incident.status = 'contained'; save('incidents', incident);
        }
      }
      audit(`Asset ${action}`, asset.name, `Lab workload ${asset.status}; HTTP verification ${status ?? 'not listening'}`);
      schedulePublish();
      res.json({ message: `${asset.name} ${asset.status}. Containment is enforced on its registered lab workload.`, asset, verifiedStatus: status });
    });
  }));
  app.post('/api/block', handler(async (req, res) => {
    const sourceIp = string(req.body?.sourceIp, 'sourceIp', 45);
    if (!isIP(sourceIp)) throw new ApiError(400, 'sourceIp must be a valid IP address.');
    save('blocked', { id: sourceIp, sourceIp, createdAt: iso() });
    const candidate = values('assets').find((asset) => asset.status === 'online');
    const status = candidate && baseUrl ? await awaitStatus(`/lab/${candidate.id}/home`, { headers: { 'x-lab-source-ip': sourceIp } }) : null;
    if (status !== null && status !== 403) throw new ApiError(500, 'Lab source blocking verification failed.');
    audit('Source IP blocked', sourceIp, `Deny rule saved for every lab workload; HTTP verification ${status ?? 'no online asset'}`);
    schedulePublish();
    res.json({ message: `${sourceIp} is blocked at the local lab gateway.`, verifiedStatus: status });
  }));
  app.post('/api/unblock', handler((req, res) => {
    const sourceIp = string(req.body?.sourceIp, 'sourceIp', 45);
    if (!isIP(sourceIp)) throw new ApiError(400, 'sourceIp must be a valid IP address.');
    if (!data.blocked.has(sourceIp)) throw new ApiError(404, 'This source IP has no lab deny rule.');
    data.blocked.delete(sourceIp); queries.remove.run('blocked', sourceIp);
    audit('Source IP unblocked', sourceIp, 'Lab gateway deny rule removed by operator');
    schedulePublish();
    res.json({ message: `${sourceIp} is no longer blocked at the local lab gateway.` });
  }));
  app.post('/api/incidents/:id/status', handler((req, res) => {
    const incident = data.incidents.get(req.params.id);
    if (!incident) throw new ApiError(404, 'Incident not found.');
    if (!INCIDENT_STATUSES.has(req.body?.status)) throw new ApiError(400, 'status must be open, investigating, contained, or resolved.');
    incident.status = req.body.status;
    save('incidents', incident);
    audit('Incident status changed', incident.id, incident.status);
    schedulePublish();
    res.json({ message: 'Incident status updated.', incident });
  }));
  app.post('/api/playbooks/:id/steps/:stepId', handler((req, res) => {
    const playbook = data.playbooks.get(req.params.id);
    const step = playbook?.steps.find((item) => item.id === req.params.stepId);
    if (!step) throw new ApiError(404, 'Playbook step not found.');
    if (typeof req.body?.completed !== 'boolean') throw new ApiError(400, 'completed must be true or false.');
    step.completed = req.body.completed;
    save('playbooks', playbook);
    audit('Playbook step updated', `${playbook.title}: ${step.title}`, step.completed ? 'Completed by operator' : 'Reopened by operator');
    schedulePublish();
    res.json({ message: 'Playbook progress saved. Steps record operator progress and do not perform actions automatically.', playbook });
  }));
  app.post('/api/indicators', handler((req, res) => {
    const type = req.body?.type;
    if (!TYPES.has(type)) throw new ApiError(400, 'type must be ip, domain, or hash.');
    let value = string(req.body?.value, 'value', 256);
    if (type === 'ip' && !isIP(value)) throw new ApiError(400, 'The indicator must be a valid IP address.');
    if (type === 'domain') {
      value = value.toLowerCase();
      if (!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(value)) throw new ApiError(400, 'The indicator must be a valid fully qualified domain name.');
    }
    if (type === 'hash') {
      value = value.toLowerCase();
      if (!/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/.test(value)) throw new ApiError(400, 'The hash must be hexadecimal MD5, SHA-1, or SHA-256.');
    }
    const confidence = req.body?.confidence ?? 80;
    if (!Number.isInteger(confidence) || confidence < 0 || confidence > 100) throw new ApiError(400, 'confidence must be an integer between 0 and 100.');
    if (values('indicators').some((item) => item.type === type && item.value === value)) throw new ApiError(409, 'This indicator is already registered.');
    const indicator = save('indicators', { id: uid('ioc'), type, value, threat: string(req.body?.threat, 'threat', 250, 'Operator-imported suspicious indicator'), confidence, source: 'Operator import', lastSeen: iso() });
    audit('Threat indicator imported', value, `${type} indicator saved with confidence ${confidence}%`);
    schedulePublish();
    res.status(201).json({ message: 'Threat indicator imported. Future matching events will generate a detection.', indicator });
  }));

  function labSource(req) {
    if (LOCAL_ADDRESSES.has(req.socket.remoteAddress) && req.get('x-lab-source-ip') && isIP(req.get('x-lab-source-ip'))) return req.get('x-lab-source-ip');
    return stripMapped(req.socket.remoteAddress);
  }
  app.use('/lab/:assetId', (req, res, next) => {
    let asset;
    try { asset = assetFor(req.params.assetId); } catch (error) { return next(error); }
    req.labAsset = asset;
    req.labSourceIp = labSource(req);
    req.labProbe = LOCAL_ADDRESSES.has(req.socket.remoteAddress) && req.get('x-lab-probe') === 'true';
    if (req.path === '/health') return next();
    if (asset.status !== 'online') {
      appendLog({ assetId: asset.id, sourceIp: req.labSourceIp, severity: 'low', category: 'containment', origin: 'lab', message: `Lab request denied: asset ${asset.status}` }, { forceAction: 'blocked', bypassDetection: true });
      return res.status(423).json({ error: `Lab workload is ${asset.status}.`, assetId: asset.id });
    }
    if (data.blocked.has(req.labSourceIp)) {
      appendLog({ assetId: asset.id, sourceIp: req.labSourceIp, severity: 'medium', category: 'network', origin: 'lab', message: 'Lab gateway denied a blocked source IP' }, { forceAction: 'blocked', bypassDetection: true });
      return res.status(403).json({ error: 'Source IP is blocked at the local lab gateway.' });
    }
    const config = data.configs.get(asset.id);
    if (config.securityHeaders) {
      res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
      res.setHeader('X-Frame-Options', 'DENY');
      res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    }
    next();
  });
  app.get('/lab/:assetId/health', (req, res) => res.json({ healthy: true, assetId: req.labAsset.id, containment: req.labAsset.status, mode: 'local-lab' }));
  app.get('/lab/:assetId/home', (req, res) => {
    appendLog({ assetId: req.labAsset.id, sourceIp: req.labSourceIp, category: req.labProbe ? 'vulnerability-scan' : 'network', origin: 'lab', message: 'Local lab HTTP request GET /home · 200' }, { bypassDetection: req.labProbe });
    res.json({ service: req.labAsset.name, message: 'Registered local lab workload', mode: 'local-lab' });
  });
  app.get('/lab/:assetId/debug', (req, res) => {
    const enabled = data.configs.get(req.labAsset.id).debugEnabled;
    appendLog({ assetId: req.labAsset.id, sourceIp: req.labSourceIp, severity: enabled ? 'medium' : 'info', category: req.labProbe ? 'vulnerability-scan' : enabled ? 'reconnaissance' : 'network', origin: 'lab', message: `Local lab debug route request · ${enabled ? '200 exposed' : '403 protected'}` }, { bypassDetection: req.labProbe });
    if (!enabled) return res.status(403).json({ error: 'Debug endpoint disabled by mitigation.' });
    res.json({ debug: true, hostname: req.labAsset.name, serviceVersion: 'deliberately-vulnerable-lab-1.0', configuration: 'Non-sensitive lab debug information; no secrets are exposed.' });
  });
  app.post('/lab/:assetId/login', (req, res) => {
    const key = `${req.labAsset.id}:${req.labSourceIp}`;
    const times = (failedLogins.get(key) || []).filter((time) => Date.now() - time < 60_000);
    const limited = data.configs.get(req.labAsset.id).loginRateLimit && times.length >= 5;
    if (!limited) times.push(Date.now());
    failedLogins.set(key, times);
    appendLog({ assetId: req.labAsset.id, sourceIp: req.labSourceIp, severity: limited ? 'medium' : 'low', category: req.labProbe ? 'vulnerability-scan' : 'authentication', origin: 'lab', message: limited ? 'Failed lab login denied by rate limiter · 429' : 'Failed lab login: invalid credentials · 401' }, { forceAction: limited ? 'blocked' : undefined, bypassDetection: req.labProbe });
    if (limited) res.setHeader('Retry-After', '60');
    res.status(limited ? 429 : 401).json({ error: limited ? 'Too many failed lab logins; retry after 60 seconds.' : 'Invalid lab credentials. No real accounts are used.' });
  });
  const labFetch = async (path, options = {}) => {
    if (!baseUrl) throw new ApiError(503, 'Start the local lab server before running this operation.');
    // Paths are built only from registered asset IDs and fixed endpoint names.
    const response = await fetch(`${baseUrl}${path}`, { ...options, signal: AbortSignal.timeout(3000), redirect: 'error' });
    await response.text();
    return response;
  };
  const awaitStatus = async (path, options) => (await labFetch(path, options)).status;
  function probeSource() {
    // Private instrumentation labels over an actual loopback connection. They do
    // not bind to or contact these addresses, and never override remote clients.
    for (let attempt = 0; attempt < 62_500; attempt++) {
      const sequence = tick++;
      const source = `127.254.${Math.floor(sequence / 250) % 250}.${1 + sequence % 250}`;
      if (!data.blocked.has(source)) return source;
    }
    throw new ApiError(409, 'Every lab verification source is blocked; review gateway deny rules.');
  }
  function updateAssetRisk(assetId) {
    const asset = data.assets.get(assetId);
    const open = values('findings').filter((finding) => finding.assetId === assetId && finding.status === 'open');
    asset.riskScore = Math.min(100, open.reduce((score, finding) => score + ({ critical: 45, high: 28, medium: 16, low: 6 }[finding.severity] || 0), 5));
    save('assets', asset);
  }
  const CHECKS = [
    { key: 'security-headers', title: 'Missing browser security headers', severity: 'medium', cvss: 5.3,
      description: 'The local HTTP workload does not send Content-Security-Policy and X-Frame-Options, increasing exposure to content injection and clickjacking.',
      remediation: 'Enable a restrictive Content-Security-Policy, deny framing, and restrict browser permissions in the lab response middleware.' },
    { key: 'public-debug', title: 'Public debug endpoint exposes service details', severity: 'high', cvss: 7.5,
      description: 'An unauthenticated request to the deliberately vulnerable /debug lab route reveals service version and host information.',
      remediation: 'Disable the lab debug route and return HTTP 403, then verify that unauthenticated access is denied.' },
    { key: 'login-rate-limit', title: 'Missing authentication rate limiting', severity: 'critical', cvss: 9.1,
      description: 'Six consecutive invalid login requests receive HTTP 401 without throttling, allowing repeated credential attempts against the lab workload.',
      remediation: 'Enable the lab authentication limiter: after five failures in 60 seconds, return HTTP 429 with Retry-After.' },
  ];
  async function probe(asset, key) {
    const headers = { 'x-lab-source-ip': probeSource(), 'x-lab-probe': 'true' };
    if (key === 'security-headers') {
      const response = await labFetch(`/lab/${asset.id}/home`, { headers });
      if (response.status !== 200) throw new ApiError(409, 'Restore the lab asset before scanning or verifying browser headers.');
      const csp = response.headers.get('content-security-policy');
      const frames = response.headers.get('x-frame-options');
      return { vulnerable: !csp || frames !== 'DENY', evidence: `GET /lab/${asset.id}/home → ${response.status}; Content-Security-Policy: ${csp || 'missing'}; X-Frame-Options: ${frames || 'missing'}` };
    }
    if (key === 'public-debug') {
      const response = await labFetch(`/lab/${asset.id}/debug`, { headers });
      if (![200, 403].includes(response.status)) throw new ApiError(409, 'Restore the lab asset before checking its debug endpoint.');
      return { vulnerable: response.status === 200, evidence: `GET /lab/${asset.id}/debug → ${response.status}; expected mitigation response: 403` };
    }
    const source = probeSource();
    failedLogins.delete(`${asset.id}:${source}`);
    const statuses = [];
    for (let i = 0; i < 6; i++) {
      const response = await labFetch(`/lab/${asset.id}/login`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-lab-source-ip': source, 'x-lab-probe': 'true' }, body: JSON.stringify({ username: 'lab-check', password: 'invalid-test-value' }) });
      if (![401, 429].includes(response.status)) throw new ApiError(409, 'Restore the lab asset before checking authentication controls.');
      statuses.push(response.status);
    }
    return { vulnerable: !statuses.includes(429), evidence: `Six invalid POST /lab/${asset.id}/login requests → [${statuses.join(', ')}]; expected mitigation response: 429 on attempt 6` };
  }
  async function scan(assetIds) {
    const targets = assetIds.map(assetFor);
    if (targets.some((asset) => asset.status !== 'online')) throw new ApiError(409, 'Restore contained lab assets before running a vulnerability scan.');
    const results = [];
    for (const asset of targets) {
      for (const check of CHECKS) {
        const result = await probe(asset, check.key);
        const id = `finding-${asset.id}-${check.key}`;
        const existing = data.findings.get(id);
        if (result.vulnerable || existing) {
          const finding = save('findings', {
            id, title: check.title, severity: check.severity, status: result.vulnerable ? 'open' : 'mitigated',
            assetId: asset.id, assetName: asset.name, cve: 'CWE-' + ({ 'security-headers': '693', 'public-debug': '200', 'login-rate-limit': '307' })[check.key],
            cvss: check.cvss, description: check.description, remediation: check.remediation,
            evidence: result.evidence, verifiedAt: iso(), check: check.key,
          });
          results.push(finding);
        }
      }
      updateAssetRisk(asset.id);
    }
    audit('Vulnerability scan completed', targets.map((asset) => asset.name).join(', '), `${results.filter((finding) => finding.status === 'open').length} verified open findings; real local HTTP checks`);
    schedulePublish();
    return results;
  }
  app.post('/api/scan', handler(async (req, res) => {
    if (req.body?.url || req.body?.target || req.body?.host) throw new ApiError(400, 'Only registered lab asset IDs can be scanned. Arbitrary targets are not accepted.');
    const ids = req.body?.assetId ? [string(req.body.assetId, 'assetId', 80)] : values('assets').map((asset) => asset.id);
    const findings = await scan(ids);
    res.json({ message: `Scan completed for ${ids.length} lab asset(s): ${findings.filter((finding) => finding.status === 'open').length} open findings verified.`, findings });
  }));
  app.post('/api/findings/:id/mitigate', handler(async (req, res) => {
    const finding = data.findings.get(req.params.id);
    if (!finding) throw new ApiError(404, 'Finding not found.');
    const asset = assetFor(finding.assetId);
    if (asset.status !== 'online') throw new ApiError(409, 'Restore the lab asset before applying and verifying mitigation.');
    const config = data.configs.get(asset.id);
    const field = ({ 'security-headers': 'securityHeaders', 'public-debug': 'debugEnabled', 'login-rate-limit': 'loginRateLimit' })[finding.check];
    if (!field) throw new ApiError(400, 'This finding has no supported lab mitigation.');
    const previous = config[field];
    config[field] = finding.check === 'public-debug' ? false : true;
    save('configs', config);
    let result;
    try {
      result = await probe(asset, finding.check);
      if (result.vulnerable) throw new ApiError(500, 'Mitigation did not pass the real HTTP verification check.');
    } catch (error) {
      config[field] = previous;
      save('configs', config);
      throw error;
    }
    finding.status = 'mitigated'; finding.evidence = result.evidence; finding.verifiedAt = iso();
    save('findings', finding); updateAssetRisk(asset.id);
    audit('Vulnerability mitigated and verified', `${asset.name}: ${finding.title}`, result.evidence);
    schedulePublish();
    res.json({ message: `${finding.title} mitigated on the lab workload and independently rechecked with HTTP requests.`, finding });
  }));
  async function runScenario(scenario) {
    if (!['brute-force', 'malware', 'recon'].includes(scenario)) throw new ApiError(400, 'scenario must be brute-force, malware, or recon.');
    const assetId = ({ 'brute-force': 'asset-finance', malware: 'asset-dev', recon: 'asset-gateway' })[scenario];
    const asset = assetFor(assetId);
    if (asset.status !== 'online') throw new ApiError(409, `Restore ${asset.name} before running this local scenario.`);
    const sourceIp = ({ 'brute-force': '203.0.113.42', malware: '198.51.100.66', recon: '192.0.2.88' })[scenario];
    const headers = { 'x-lab-source-ip': sourceIp, 'Content-Type': 'application/json' };
    const responses = [];
    if (scenario === 'brute-force') {
      for (let i = 0; i < 8; i++) responses.push(await awaitStatus(`/lab/${assetId}/login`, { method: 'POST', headers, body: JSON.stringify({ username: 'lab-user', password: 'invalid-lab-password' }) }));
    } else {
      responses.push(await awaitStatus(`/lab/${assetId}/${scenario === 'recon' ? 'debug' : 'home'}`, { headers }));
    }
    audit('Local lab scenario executed', scenario, `Actual localhost requests; HTTP responses ${responses.join(', ')}`);
    schedulePublish();
    return { message: `${scenario} local lab scenario executed. Requests generated live SIEM evidence.`, sourceIp, assetId, responses };
  }
  app.post('/api/demo/scenario', handler(async (req, res) => res.json(await runScenario(req.body?.scenario))));
  app.use('/api', (req, res) => res.status(404).json({ error: 'API endpoint not found.' }));
  const distPath = resolve(dirname(fileURLToPath(import.meta.url)), '../dist');
  app.use(express.static(distPath));
  app.get('/{*splat}', (req, res, next) => {
    if (req.path.startsWith('/lab/')) return next();
    const indexPath = resolve(distPath, 'index.html');
    if (!existsSync(indexPath)) return next();
    res.sendFile(indexPath);
  });
  app.use((error, req, res, next) => {
    if (res.headersSent) return next(error);
    const status = error.status || (error.type === 'entity.too.large' ? 413 : error instanceof SyntaxError ? 400 : 500);
    res.status(status).json({ error: status < 500 ? error.message : 'The local lab operation failed. Check server output for details.' });
    if (status >= 500) console.error(`[lab] ${error.message}`);
  });

  async function seedHistory() {
    if (setting('historySeeded')) return;
    // Clearly labelled historical lab fixtures complement the real live requests.
    for (let i = 0; i < 55; i++) {
      appendLog({ assetId: seedAssets()[i % 4].id, sourceIp: `10.10.0.${40 + (i % 15)}`, timestamp: new Date(Date.now() - (55 - i) * 6000).toISOString(), category: 'lab-history', origin: 'lab-history', severity: 'info', message: 'Seeded local lab history · successful workload connection' }, { bypassDetection: true });
    }
    setSetting('historySeeded', true);
  }
  return {
    app,
    get url() { return baseUrl; },
    state,
    async start(port = 3001, host = '127.0.0.1') {
      if (closed) throw new Error('This platform instance has been stopped. Create a new instance to restart.');
      if (server) return { url: baseUrl, port: server.address().port };
      server = await new Promise((resolveServer, reject) => {
        const listener = app.listen(port, host, () => resolveServer(listener));
        listener.once('error', reject);
      });
      const portNumber = server.address().port;
      baseUrl = `http://127.0.0.1:${portNumber}`;
      if (demo) {
        await seedHistory();
        if (!setting('initialScanDone')) {
          await scan(values('assets').filter((asset) => asset.status === 'online').map((asset) => asset.id));
          setSetting('initialScanDone', true);
          for (const scenario of ['brute-force', 'malware', 'recon']) await runScenario(scenario);
        }
        simulation = setInterval(async () => {
          if (closed) return;
          try {
            const candidates = values('assets').filter((asset) => asset.status === 'online');
            if (candidates.length) {
              const asset = candidates[(tick++) % candidates.length];
              await labFetch(`/lab/${asset.id}/home`, { headers: { 'x-lab-source-ip': `10.10.0.${40 + tick % 15}` } });
            } else {
              publish();
            }
          } catch (error) { if (!closed) console.error(`[lab live stream] ${error.message}`); }
        }, 2000);
        simulation.unref();
      }
      audit('Local security lab started', baseUrl, demo ? 'Live lab workload traffic enabled' : 'Automatic lab traffic disabled');
      return { url: baseUrl, port: portNumber };
    },
    async stop() {
      if (closed) return;
      closed = true;
      clearInterval(simulation);
      for (const stream of streams) stream.end();
      streams.clear();
      if (server) {
        await new Promise((resolveClose) => {
          server.close(resolveClose);
          server.closeIdleConnections();
          server.closeAllConnections();
        });
      }
      db.close();
    },
  };
}

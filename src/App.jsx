import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Activity, ArrowDownLeft, ArrowRight, ArrowUpRight, Bell, BookOpen, Check, CheckCheck, ChevronDown, ChevronRight, CircleHelp, Command, Download, ExternalLink, Fingerprint, Globe2, LayoutDashboard, Loader2, Menu, Monitor, MoreHorizontal, Pause, Play, Radar, Radio, Search, Settings2, Shield, ShieldAlert, ShieldCheck, Sparkles, Target, Terminal, Unplug, Workflow, X, Zap } from 'lucide-react';
import WorkspaceView from './Views.jsx';

const navigation = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'logs', label: 'Live logs', icon: Radio },
  { id: 'intelligence', label: 'Threat intelligence', icon: Globe2 },
  { id: 'vulnerabilities', label: 'Vulnerabilities', icon: Fingerprint },
  { id: 'assets', label: 'Assets & containment', icon: Monitor },
  { id: 'incidents', label: 'Incident response', icon: ShieldAlert },
  { id: 'playbooks', label: 'Response playbooks', icon: BookOpen },
];
const emptyState = { metrics: {}, series: [], logs: [], incidents: [], assets: [], findings: [], indicators: [], playbooks: [], audit: [], mode: 'local-lab' };
const severityColors = { critical: '#ef8287', high: '#edab75', medium: '#e2cb79', low: '#74c9c1', info: '#8292a4' };
const formatTime = value => new Date(value).toLocaleTimeString('en-GB', { hour12: false });
const formatNumber = value => Number(value || 0).toLocaleString('en-US');

function Brand({ compact = false }) {
  return <div className="brand"><div className="brand-mark"><Shield size={26} strokeWidth={1.8} /><span>A</span></div>{!compact && <div><strong>AEGIS<span className="brand-period">.</span></strong><small>SECURITY OPERATIONS</small></div>}</div>;
}

function Toast({ toast, onClose }) {
  if (!toast) return null;
  return <div className={`toast ${toast.type === 'error' ? 'toast-error' : ''}`} role="status"><span className="toast-icon">{toast.type === 'error' ? <ShieldAlert size={18} /> : <Check size={18} />}</span><div><strong>{toast.type === 'error' ? 'Action could not complete' : 'Action completed'}</strong><p>{toast.message}</p></div><button className="icon-button" aria-label="Dismiss notification" onClick={onClose}><X size={16} /></button></div>;
}

function MetricCard({ label, value, icon: Icon, subtitle, color, series, accent }) {
  const values = series.length ? series.slice(-12).map(s => Number(s.events || 0)) : [0];
  const max = Math.max(...values, 1);
  const points = values.map((v, i) => `${i / Math.max(values.length - 1, 1) * 108},${28 - v / max * 23}`).join(' ');
  return <div className={`metric-card ${accent ? 'metric-accent' : ''}`}><div className="metric-top"><span>{label}</span><span className="metric-icon" style={{ color }}><Icon size={17} /></span></div><div className="metric-number">{formatNumber(value)}<svg width="108" height="34" viewBox="0 0 108 34" aria-hidden="true"><polyline points={points} stroke={color} strokeWidth="1.8" fill="none" strokeLinejoin="round" /></svg></div><div className="metric-note"><span className="tiny-dot" style={{ background: color }} />{subtitle}</div></div>;
}

function makeSmoothPath(points) {
  if (!points.length) return '';
  let path = `M ${points[0][0]} ${points[0][1]}`;
  for (let i = 1; i < points.length; i++) {
    const [x0, y0] = points[i - 1];
    const [x1, y1] = points[i];
    const mid = (x0 + x1) / 2;
    path += ` C ${mid} ${y0}, ${mid} ${y1}, ${x1} ${y1}`;
  }
  return path;
}

function TelemetryChart({ logs, period, connected }) {
  const [metric, setMetric] = useState('events');
  const [hover, setHover] = useState(null);
  const data = useMemo(() => {
    const minutes = period === '1h' ? 60 : period === '24h' ? 1440 : 15;
    const end = Date.now();
    const span = minutes * 60000;
    const bins = Array.from({ length: 24 }, (_, i) => ({ time: end - span + i * span / 23, events: 0, threats: 0 }));
    logs.forEach(log => {
      const elapsed = new Date(log.timestamp).getTime() - (end - span);
      if (elapsed >= 0 && elapsed <= span) {
        const index = Math.min(23, Math.floor(elapsed / span * 24));
        bins[index].events++;
        if (log.action !== 'allowed' || ['critical', 'high'].includes(log.severity)) bins[index].threats++;
      }
    });
    return bins;
  }, [logs, period]);
  const width = 780, height = 176, max = Math.max(...data.map(d => d.events), 4);
  const coordinates = field => data.map((d, i) => [i / (data.length - 1) * width, height - 10 - (d[field] / max) * (height - 28)]);
  const eventPoints = coordinates('events'), threatPoints = coordinates('threats');
  const eventPath = makeSmoothPath(eventPoints), threatPath = makeSmoothPath(threatPoints);
  const total = data.reduce((sum, d) => sum + d[metric], 0);
  return <section className="panel telemetry-panel"><div className="panel-header"><div><h2><Activity size={17} />Threat activity</h2><p>Your perimeter, in real time</p></div><span className={`live-label ${connected ? '' : 'disconnected'}`}><span className="live-dot" />{connected ? 'LIVE' : 'OFFLINE'}</span></div><div className="chart-controls"><div className="segmented"><button className={metric === 'events' ? 'active' : ''} onClick={() => setMetric('events')}>All events</button><button className={metric === 'threats' ? 'active' : ''} onClick={() => setMetric('threats')}>Threats</button></div><span className="chart-summary"><strong>{formatNumber(total)}</strong> {metric === 'events' ? 'events' : 'detections'} in view</span></div><div className="chart-frame"><div className="chart-axis">{[max, Math.round(max * .75), Math.round(max * .5), Math.round(max * .25), 0].map((n, i) => <span key={i}>{n}</span>)}</div><div className="chart-plot" onMouseLeave={() => setHover(null)} onMouseMove={e => { const rect = e.currentTarget.getBoundingClientRect(); setHover(Math.max(0, Math.min(23, Math.round((e.clientX - rect.left) / rect.width * 23)))); }}><svg viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" role="img" aria-label={`Live event volume: ${total} ${metric} in the selected window`}><defs><linearGradient id="event-fill" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stopColor="#c4ef76" stopOpacity=".22" /><stop offset="100%" stopColor="#c4ef76" stopOpacity="0" /></linearGradient><linearGradient id="threat-fill" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stopColor="#7dcccf" stopOpacity=".18" /><stop offset="100%" stopColor="#7dcccf" stopOpacity="0" /></linearGradient></defs>{[0, .25, .5, .75, 1].map(n => <line key={n} x1="0" x2={width} y1={n * (height - 10)} y2={n * (height - 10)} stroke="#2a3239" strokeDasharray="4 6" strokeOpacity=".6" />)}{metric === 'events' && <><path d={`${eventPath} L ${width} ${height} L 0 ${height} Z`} fill="url(#event-fill)" /><path d={eventPath} fill="none" stroke="#c4ef76" strokeWidth="2.5" /></>}<path d={`${threatPath} L ${width} ${height} L 0 ${height} Z`} fill="url(#threat-fill)" /><path d={threatPath} fill="none" stroke="#70c6cc" strokeWidth="2" />{hover !== null && <><line x1={eventPoints[hover][0]} x2={eventPoints[hover][0]} y1="0" y2={height} stroke="#8292a4" strokeDasharray="4 4" /><circle cx={eventPoints[hover][0]} cy={metric === 'events' ? eventPoints[hover][1] : threatPoints[hover][1]} r="4" fill="#c4ef76" stroke="#10161b" strokeWidth="2" /></>}<circle className="chart-beacon" cx={width} cy={metric === 'events' ? eventPoints.at(-1)[1] : threatPoints.at(-1)[1]} r="4" fill="#c4ef76" /></svg>{hover !== null && <div className="chart-tooltip" style={{ left: `${Math.min(80, Math.max(8, hover / 23 * 100))}%` }}><strong>{data[hover][metric]} {metric}</strong><span>{new Date(data[hover].time).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })}</span></div>}<div className="chart-x-axis">{[0, 5, 11, 17, 23].map(i => <span key={i}>{new Date(data[i].time).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })}</span>)}</div></div></div><div className="chart-footer"><span><i style={{ background: '#c4ef76' }} />Ingested events</span><span><i style={{ background: '#70c6cc' }} />Threat detections</span><small>Rolling window · collected telemetry</small></div></section>;
}

function ThreatLandscape({ incidents, onNavigate }) {
  const open = incidents.filter(i => ['open', 'investigating'].includes(i.status));
  const counts = ['critical', 'high', 'medium', 'low'].map(severity => ({ severity, count: open.filter(i => i.severity === severity).length }));
  let start = 0;
  const segments = counts.map(c => { const from = start; start += c.count / Math.max(open.length, 1) * 100; return `${severityColors[c.severity]} ${from}% ${start}%`; });
  return <section className="panel landscape-panel"><div className="panel-header"><div><h2><Radar size={17} />Threat landscape</h2><p>Open incidents by severity</p></div><button className="icon-button" aria-label="View all incidents" onClick={() => onNavigate('incidents')}><ArrowUpRight size={18} /></button></div><div className="threat-donut" style={{ background: open.length ? `conic-gradient(${segments.join(',')})` : '#27323c' }}><div><strong>{open.length}</strong><span>active threats</span></div></div><div className="severity-list">{counts.map(c => <button key={c.severity} onClick={() => onNavigate('incidents')}><span><i style={{ background: severityColors[c.severity] }} />{c.severity[0].toUpperCase() + c.severity.slice(1)}</span><div className="severity-track"><i style={{ background: severityColors[c.severity], width: `${c.count / Math.max(...counts.map(c => c.count), 1) * 100}%` }} /></div><strong>{c.count.toString().padStart(2, '0')}</strong></button>)}</div></section>;
}

function LogTable({ logs, limit = 7, onLogClick }) {
  return <div className="table-scroll"><table className="log-table"><thead><tr><th>TIME</th><th>SEVERITY</th><th>EVENT / SOURCE</th><th>WORKSTATION</th><th>ACTION</th><th /></tr></thead><tbody>{logs.slice(0, limit).map(log => <tr key={log.id} className="log-enter" onClick={() => onLogClick(log)} tabIndex={0} role="button" aria-label={`Inspect event: ${log.message}`} onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onLogClick(log); } }}><td className="mono time-cell">{formatTime(log.timestamp)}</td><td><span className={`badge badge-${log.severity}`}><i />{log.severity}</span></td><td className="event-cell"><strong>{log.message}</strong><small><span className="mono">{log.sourceIp}</span><span className="event-separator">/</span>{log.category || 'Telemetry'}<span className="origin-tag">{log.origin === 'ingested' ? 'imported' : 'lab'}</span></small></td><td className="asset-cell"><Monitor size={13} /><span>{log.assetName || log.assetId}</span></td><td><span className={`action-label action-${log.action}`}><span />{log.action || 'allowed'}</span></td><td><ChevronRight size={14} /></td></tr>)}</tbody></table>{!logs.length && <div className="empty-state"><Radio size={27} /><h3>No events in this view</h3><p>Change your filters, or send telemetry using the ingestion API.</p></div>}</div>;
}

function Overview({ state, connected, onNavigate, onAction, onLogClick, busy }) {
  const [period, setPeriod] = useState('15m');
  const [paused, setPaused] = useState(false);
  const frozen = useRef([]);
  const [scenarioOpen, setScenarioOpen] = useState(false);
  const activeIncidents = state.incidents.filter(i => ['open', 'investigating'].includes(i.status));
  const topIncidents = [...activeIncidents].sort((a, b) => ['critical', 'high', 'medium', 'low'].indexOf(a.severity) - ['critical', 'high', 'medium', 'low'].indexOf(b.severity)).slice(0, 3);
  const logs = [...state.logs].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  if (!paused) frozen.current = logs;
  return <><div className="page-heading"><div><div className="eyebrow"><span className="tiny-dot" />YOUR SECURITY, AT A GLANCE</div><h1>Security overview<span className="heading-dot">.</span></h1><p>A clear view of your environment. A faster path to response.</p></div><div className="heading-actions"><label className="period-select"><Activity size={14} /><select value={period} aria-label="Chart time window" onChange={e => setPeriod(e.target.value)}><option value="15m">Last 15 minutes</option><option value="1h">Last hour</option><option value="24h">Last 24 hours</option></select><ChevronDown size={14} /></label><button className="btn btn-primary" disabled={busy} onClick={() => onAction('/api/scan', {}, 'Vulnerability scan completed')}><Fingerprint size={16} />Run scan<ArrowUpRight size={15} /></button></div></div><section className="command-banner"><div className="banner-wallpaper" /><div className="banner-grid" /><div className="banner-content"><span className="banner-tag"><Sparkles size={12} />ONE PLATFORM. COMPLETE VISIBILITY.</span><h2>Your perimeter.<br />Under control.</h2><p>Detect. Investigate. Contain. <span>Stay a step ahead.</span></p></div><div className="banner-status"><div className="orbital-ring ring-one" /><div className="orbital-ring ring-two" /><ShieldCheck size={50} strokeWidth={1} /><span className="banner-status-label"><i />SIEM + VAPT</span><small>Unified defense</small></div><span className="lab-label"><Terminal size={12} />LOCAL SECURITY LAB</span></section><div className="metrics-grid"><MetricCard label="Events ingested" value={state.metrics.events24h ?? state.logs.length} icon={Activity} subtitle="Rolling 24-hour telemetry" color="#c4ef76" series={state.series} accent /><MetricCard label="Active threats" value={state.metrics.activeThreats ?? activeIncidents.length} icon={ShieldAlert} subtitle="Open investigation queue" color="#ef8287" series={state.series} /><MetricCard label="Critical findings" value={state.metrics.criticalFindings ?? state.findings.filter(f => f.severity === 'critical' && f.status === 'open').length} icon={Fingerprint} subtitle="Prioritized for remediation" color="#edab75" series={state.series} /><MetricCard label="Managed workstations" value={state.assets.length} icon={Monitor} subtitle={`${state.assets.filter(a => a.status === 'online').length} online · ${state.assets.filter(a => a.status !== 'online').length} contained`} color="#70c6cc" series={state.series} /></div><div className="analytics-grid"><TelemetryChart logs={state.logs} period={period} connected={connected} /><ThreatLandscape incidents={state.incidents} onNavigate={onNavigate} /></div><div className="operations-grid"><section className="panel event-panel"><div className="panel-header"><div><h2><Radio size={17} />Live event stream <span className="count-pill">{state.logs.length}</span></h2><p>Signals that matter. Evidence you can act on.</p></div><div className="event-actions"><button className={`icon-button ${paused ? 'button-selected' : ''}`} onClick={() => setPaused(p => !p)} aria-label={paused ? 'Resume event stream' : 'Pause event stream'} title={paused ? 'Resume' : 'Pause'}>{paused ? <Play size={16} /> : <Pause size={16} />}</button><button className="text-button" onClick={() => onNavigate('logs')}>View all<ArrowRight size={14} /></button></div></div><LogTable logs={frozen.current} limit={6} onLogClick={onLogClick} /><div className="stream-footer"><span className={`live-label ${paused ? 'paused' : ''}`}><span className="live-dot" />{paused ? 'DISPLAY PAUSED' : 'CONTINUOUS MONITORING'}</span><span>{formatNumber(state.metrics.blockedSources)} sources blocked <ShieldCheck size={13} /></span></div></section><section className="panel attention-panel"><div className="panel-header"><div><h2><Target size={17} />Needs attention</h2><p>Your response priorities</p></div><span className="count-pill">{activeIncidents.length}</span></div><div className="attention-list">{topIncidents.map(incident => <button className="attention-item" key={incident.id} onClick={() => onNavigate('incidents')}><div className="attention-item-top"><span className={`severity-icon severity-icon-${incident.severity}`}><ShieldAlert size={16} /></span><span className={`badge badge-${incident.severity}`}>{incident.severity}</span><ArrowUpRight size={14} /></div><strong>{incident.title}</strong><span className="attention-asset"><Monitor size={12} />{incident.assetName}<span>·</span><span className="mono">{incident.technique || 'Triage'}</span></span></button>)}{!topIncidents.length && <div className="compact-empty"><ShieldCheck size={28} /><strong>No active incidents</strong><span>Your queue is clear.</span></div>}</div><div className="attention-bottom"><button className="text-button" onClick={() => onNavigate('incidents')}>Open incident queue<ArrowRight size={14} /></button></div></section></div><section className="lab-launcher"><div className="launcher-icon"><Zap size={20} /></div><div><strong>See your defenses in action.</strong><p>Run a lab scenario to follow detection, investigation, and containment.</p></div><div className="scenario-picker"><button className="btn btn-ghost" onClick={() => setScenarioOpen(p => !p)} aria-expanded={scenarioOpen}>Launch a scenario<ChevronDown size={14} /></button>{scenarioOpen && <div className="dropdown scenario-dropdown">{[['brute-force', 'Brute-force login', 'Credential attack detection'], ['malware', 'Malicious connection', 'Threat intelligence matching'], ['recon', 'Endpoint reconnaissance', 'Sensitive endpoint discovery']].map(([id, label, desc]) => <button key={id} onClick={() => { setScenarioOpen(false); onAction('/api/demo/scenario', { scenario: id }, `${label} scenario executed`); }} disabled={busy}><span><strong>{label}</strong><small>{desc}</small></span><ArrowUpRight size={15} /></button>)}</div>}</div></section></>;
}

function LiveLogs({ state, connected, onLogClick, onAction, busy }) {
  const [filter, setFilter] = useState('all');
  const [query, setQuery] = useState('');
  const [action, setAction] = useState('all');
  const [paused, setPaused] = useState(false);
  const frozen = useRef(state.logs);
  if (!paused) frozen.current = state.logs;
  const filtered = [...frozen.current].filter(l => (filter === 'all' || l.severity === filter) && (action === 'all' || l.action === action) && `${l.message} ${l.sourceIp} ${l.assetName} ${l.rule || ''}`.toLowerCase().includes(query.toLowerCase())).sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  return <><div className="page-heading"><div><div className="eyebrow"><span className="tiny-dot" />LIVE TELEMETRY</div><h1>Every signal. One view<span className="heading-dot">.</span></h1><p>Inspect raw evidence, correlate events, and block suspicious sources.</p></div><button className="btn btn-ghost" onClick={() => downloadJSON(filtered, 'aegis-events.json')}><Download size={15} />Export events</button></div><div className="log-status-bar"><span className={`live-label ${connected && !paused ? '' : 'paused'}`}><span className="live-dot" />{paused ? 'DISPLAY PAUSED' : connected ? 'LIVE INGESTION' : 'RECONNECTING'}</span><div className="signal-bars">{[12, 22, 15, 28, 19, 32, 23, 12, 20, 28, 15, 23, 30, 18, 25, 12, 19, 30, 22, 16].map((height, i) => <i key={i} style={{ height, animationDelay: `${i * -.15}s` }} />)}</div><span className="mono">{formatNumber(state.metrics.events24h ?? state.logs.length)} events / 24h</span><button className="btn btn-ghost" onClick={() => setPaused(p => !p)}>{paused ? <Play size={14} /> : <Pause size={14} />}{paused ? 'Resume display' : 'Pause display'}</button></div><section className="panel log-workspace"><div className="log-filters"><div className="input-with-icon"><Search size={16} /><input aria-label="Filter events" placeholder="Filter by message, source IP, or workstation…" value={query} onChange={e => setQuery(e.target.value)} /></div><label className="filter-select"><select value={action} aria-label="Filter action" onChange={e => setAction(e.target.value)}><option value="all">All actions</option><option value="detected">Detected</option><option value="blocked">Blocked</option><option value="allowed">Allowed</option></select><ChevronDown size={13} /></label></div><div className="filter-chips">{['all', 'critical', 'high', 'medium', 'low', 'info'].map(s => <button key={s} className={filter === s ? 'active' : ''} onClick={() => setFilter(s)}>{s !== 'all' && <i style={{ background: severityColors[s] }} />}{s === 'all' ? 'All events' : s[0].toUpperCase() + s.slice(1)}<span>{s === 'all' ? frozen.current.length : frozen.current.filter(l => l.severity === s).length}</span></button>)}<small>{filtered.length} matching events</small></div><LogTable logs={filtered} limit={100} onLogClick={onLogClick} /></section><div className="integration-note"><Terminal size={18} /><div><strong>Connect your own logs</strong><p>Forward JSON events through <code>POST /api/ingest</code> or use the included log collector.</p></div><button className="btn btn-ghost" disabled={busy} onClick={() => onAction('/api/demo/scenario', { scenario: 'brute-force' }, 'Brute-force scenario executed')}><Zap size={14} />Generate lab activity</button></div></>;
}

function downloadJSON(value, filename) {
  const blob = new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = filename; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function LogDetail({ log, onClose, onAction, busy, assets, blockedSources }) {
  const asset = assets.find(a => a.id === log.assetId);
  const dialogRef = useRef(null);
  useEffect(() => {
    const previous = document.activeElement;
    dialogRef.current?.querySelector('button')?.focus();
    return () => previous?.focus?.();
  }, []);
  const isBlocked = blockedSources.some(source => source.sourceIp === log.sourceIp);
  return <div className="modal-backdrop" onClick={onClose}><section ref={dialogRef} className="detail-modal" onKeyDown={e => { if (e.key !== 'Tab') return; const elements = [...e.currentTarget.querySelectorAll('button:not([disabled])')]; if (e.shiftKey && document.activeElement === elements[0]) { e.preventDefault(); elements.at(-1)?.focus(); } else if (!e.shiftKey && document.activeElement === elements.at(-1)) { e.preventDefault(); elements[0]?.focus(); } }} role="dialog" aria-modal="true" aria-labelledby="log-detail-title" onClick={e => e.stopPropagation()}><div className="modal-header"><div><div className="eyebrow">EVENT INVESTIGATION</div><h2 id="log-detail-title">Follow the signal<span className="heading-dot">.</span></h2></div><button className="icon-button" aria-label="Close event details" onClick={onClose}><X size={20} /></button></div><div className="modal-content"><div className="detail-badges"><span className={`badge badge-${log.severity}`}>{log.severity}</span><span className={`action-label action-${log.action}`}><span />{log.action}</span><span className="mono muted">#{log.id}</span></div><h3>{log.message}</h3><dl className="detail-grid">{[['Source address', log.sourceIp], ['Workstation', log.assetName || log.assetId], ['Category', log.category], ['Evidence source', log.origin === 'ingested' ? 'Imported telemetry' : log.origin === 'lab-history' ? 'Historical lab fixture' : 'Live lab request'], ['Detected at', new Date(log.timestamp).toLocaleString()], ['Detection rule', log.rule || 'Baseline telemetry'], ['MITRE ATT&CK', log.technique || 'No technique mapped']].map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value || '—'}</dd></div>)}</dl><div className="evidence-block"><div><Terminal size={14} />RAW EVENT</div><pre>{JSON.stringify(log, null, 2)}</pre></div><div className="detail-scope"><ShieldCheck size={16} /><span>Lab enforcement blocks workload access. Event evidence remains available for investigation.</span></div></div><div className="modal-footer"><button className="btn btn-ghost" onClick={() => downloadJSON(log, `aegis-event-${log.id}.json`)}><Download size={15} />Export evidence</button><button className="btn btn-danger" disabled={busy || isBlocked} onClick={() => onAction('/api/block', { sourceIp: log.sourceIp }, `Blocked source ${log.sourceIp}`)}><Shield size={15} />Block source</button>{asset && <button className="btn btn-primary" disabled={busy || asset.status !== 'online'} onClick={() => onAction(`/api/assets/${asset.id}/action`, { action: 'isolate' }, `${asset.name} isolated in the lab`)}><Unplug size={15} />Isolate asset</button>}</div></section></div>;
}

export default function App() {
  const initialView = window.location.hash.replace('#', '');
  const [view, setView] = useState(navigation.some(n => n.id === initialView) || initialView === 'settings' ? initialView : 'overview');
  const [state, setState] = useState(emptyState);
  const [connected, setConnected] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [toast, setToast] = useState(null);
  const [selectedLog, setSelectedLog] = useState(null);
  const [search, setSearch] = useState('');
  const [notifications, setNotifications] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const searchRef = useRef(null);
  const showToast = useCallback((message, type = 'success') => setToast({ message, type, id: Date.now() }), []);
  const refresh = useCallback(async () => {
    try { const res = await fetch('/api/state'); if (!res.ok) throw new Error('The API is unavailable. Start it with npm run dev.'); const next = await res.json(); setState({ ...emptyState, ...next }); setError(''); setLoading(false); } catch (e) { setError(e.message); setLoading(false); }
  }, []);
  useEffect(() => {
    refresh();
    const source = new EventSource('/api/events');
    source.onopen = () => setConnected(true);
    source.addEventListener('state', event => { try { setState({ ...emptyState, ...JSON.parse(event.data) }); setError(''); setLoading(false); setConnected(true); } catch { /* A malformed message is ignored; next state resynchronizes. */ } });
    source.onerror = () => setConnected(false);
    const fallback = setInterval(refresh, 20000);
    return () => { source.close(); clearInterval(fallback); };
  }, [refresh]);
  useEffect(() => { if (!toast) return; const timer = setTimeout(() => setToast(null), 5500); return () => clearTimeout(timer); }, [toast]);
  useEffect(() => { const listener = e => { if (e.key === 'Escape') { setSelectedLog(null); setSearch(''); setNotifications(false); setMenuOpen(false); } if (e.key === '/' && !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement?.tagName)) { e.preventDefault(); searchRef.current?.focus(); } }; document.addEventListener('keydown', listener); return () => document.removeEventListener('keydown', listener); }, []);
  useEffect(() => {
    const change = () => {
      const next = window.location.hash.slice(1);
      if (navigation.some(item => item.id === next) || next === 'settings') {
        setView(next); setMenuOpen(false); setSearch(''); setNotifications(false);
      }
    };
    window.addEventListener('hashchange', change);
    return () => window.removeEventListener('hashchange', change);
  }, []);
  const navigate = id => { setView(id); setSearch(''); setNotifications(false); setMenuOpen(false); window.history.replaceState(null, '', `#${id}`); window.scrollTo({ top: 0, behavior: 'smooth' }); };
  const onAction = async (path, body, successLabel) => {
    if (busy) return;
    setBusy(true);
    try { const res = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) }); const result = await res.json(); if (!res.ok) throw new Error(result.error || result.message || 'This action could not complete.'); await refresh(); showToast(result.message || successLabel || 'Changes saved'); return result; } catch (e) { showToast(e.message, 'error'); return null; } finally { setBusy(false); }
  };
  const selectedTitle = navigation.find(n => n.id === view)?.label || 'Data & integrations';
  const openCount = state.incidents.filter(i => ['open', 'investigating'].includes(i.status)).length;
  const searchResults = useMemo(() => {
    if (!search.trim()) return [];
    const q = search.toLowerCase();
    return [...state.logs.filter(l => `${l.message} ${l.sourceIp} ${l.assetName}`.toLowerCase().includes(q)).slice(0, 4).map(l => ({ label: l.message, detail: l.sourceIp, type: 'Event', log: l })), ...state.assets.filter(a => `${a.name} ${a.ip}`.toLowerCase().includes(q)).slice(0, 3).map(a => ({ label: a.name, detail: a.ip, type: 'Asset', view: 'assets' })), ...state.incidents.filter(i => i.title.toLowerCase().includes(q)).slice(0, 2).map(i => ({ label: i.title, detail: i.severity, type: 'Incident', view: 'incidents' })), ...state.findings.filter(f => f.title.toLowerCase().includes(q)).slice(0, 2).map(f => ({ label: f.title, detail: f.assetName, type: 'Finding', view: 'vulnerabilities' }))].slice(0, 8);
  }, [search, state]);
  return <div className="app-shell">{menuOpen && <div className="sidebar-overlay" onClick={() => setMenuOpen(false)} />}<aside className={`sidebar ${menuOpen ? 'sidebar-open' : ''}`}><button className="brand-button" onClick={() => navigate('overview')} aria-label="AEGIS overview"><Brand /></button><div className="workspace-badge"><span className="workspace-symbol"><Command size={15} /></span><div><strong>Security workspace</strong><small>Local lab environment</small></div><ChevronDown size={14} /></div><div className="nav-section-label">PLATFORM</div><nav aria-label="Primary navigation">{navigation.map(({ id, label, icon: Icon }) => <button key={id} className={`nav-item ${view === id ? 'active' : ''}`} onClick={() => navigate(id)}><Icon size={18} strokeWidth={1.7} /><span>{label}</span>{id === 'logs' && <i className="nav-live-dot" />}{id === 'incidents' && openCount > 0 && <span className="nav-count">{openCount}</span>}</button>)}</nav><div className="sidebar-bottom"><div className="system-status"><div className="status-title"><span className={`live-dot ${connected ? '' : 'offline'}`} /><span>{connected ? 'Telemetry connected' : 'Connecting telemetry'}</span><Activity size={13} /></div><p>{state.assets.length} managed assets <span>·</span> Local lab</p><div className="status-progress"><span style={{ width: connected ? '100%' : '25%' }} /></div></div><button className={`nav-item ${view === 'settings' ? 'active' : ''}`} onClick={() => navigate('settings')}><Settings2 size={18} /><span>Data & integrations</span></button><a className="nav-item" href="https://csrc.nist.gov/pubs/sp/800/61/r3/final" target="_blank" rel="noreferrer"><CircleHelp size={18} /><span>Response guidelines</span><ExternalLink size={12} /></a><div className="creator-card"><div className="avatar">VT</div><div><strong>Vaibhav Thakur</strong><small>Creator & security architect</small></div><span className="creator-dot" /></div></div></aside><div className="main-layout"><header className="topbar"><div className="breadcrumb"><button className="mobile-menu icon-button" aria-label="Open navigation" onClick={() => setMenuOpen(true)}><Menu size={20} /></button><span>Workspace</span><ChevronRight size={13} /><strong>{selectedTitle}</strong></div><div className="topbar-right"><div className="global-search"><Search size={15} /><input ref={searchRef} aria-label="Search workspace" placeholder="Search anything…" value={search} onChange={e => setSearch(e.target.value)} /><kbd>/</kbd>{search && <div className="dropdown search-dropdown"><div className="search-dropdown-heading">WORKSPACE RESULTS</div>{searchResults.length ? searchResults.map((r, i) => <button key={i} onClick={() => { if (r.log) { setSelectedLog(r.log); setSearch(''); } else navigate(r.view); }}><div className="search-result-icon">{r.type === 'Event' ? <Radio size={15} /> : r.type === 'Asset' ? <Monitor size={15} /> : <ShieldAlert size={15} />}</div><span><strong>{r.label}</strong><small>{r.type} · {r.detail}</small></span><ArrowUpRight size={14} /></button>) : <div className="search-no-results">No matching signals. Try an IP, asset, or event.</div>}</div>}</div><span className={`connection-pill ${connected ? '' : 'connection-offline'}`}><span className="live-dot" />{connected ? 'System live' : 'Reconnecting'}</span><div className="notification-holder"><button className={`icon-button notification-button ${notifications ? 'button-selected' : ''}`} aria-label="View action notifications" onClick={() => setNotifications(p => !p)}><Bell size={18} />{state.audit.length > 0 && <span />}</button>{notifications && <div className="dropdown notifications-dropdown"><div className="notification-heading"><strong>Action activity</strong><span className="count-pill">{state.audit.length}</span></div>{state.audit.slice(0, 6).map(a => <div className="notification-entry" key={a.id}><CheckCheck size={15} /><div><strong>{a.action}</strong><p>{a.target} · {a.result}</p><small>{formatTime(a.timestamp)}</small></div></div>)}{!state.audit.length && <div className="search-no-results">Response actions and scan results will appear here.</div>}</div>}</div><div className="topbar-divider" /><button className="avatar avatar-small" aria-label="Open creator and integration information" onClick={() => navigate('settings')}>VT</button></div></header><main className="main-content">{loading ? <div className="loading-state"><Brand /><Loader2 className="spin" size={25} /><p>Connecting to your security workspace…</p></div> : error && !state.logs.length ? <div className="connection-error"><Unplug size={32} /><h1>Let’s reconnect your workspace.</h1><p>{error}</p><code>npm run dev</code><button className="btn btn-primary" onClick={refresh}>Retry connection</button></div> : <><div className="view-transition" key={view}>{view === 'overview' ? <Overview state={state} connected={connected} onNavigate={navigate} onAction={onAction} onLogClick={setSelectedLog} busy={busy} /> : view === 'logs' ? <LiveLogs state={state} connected={connected} onLogClick={setSelectedLog} onAction={onAction} busy={busy} /> : <WorkspaceView view={view} state={state} onAction={onAction} busy={busy} />}</div><footer className="page-footer"><span><Shield size={12} />AEGIS <span className="footer-separator">/</span> Unified security operations</span><span>Created by <strong>Vaibhav Thakur</strong><i />v1.0.0</span></footer></>}</main></div>{busy && <div className="action-progress" role="status"><Loader2 size={14} className="spin" />Applying action and verifying evidence…</div>}<Toast toast={toast} onClose={() => setToast(null)} />{selectedLog && <LogDetail log={selectedLog} onClose={() => setSelectedLog(null)} onAction={onAction} busy={busy} assets={state.assets} blockedSources={state.blockedSources || []} />}</div>;
}

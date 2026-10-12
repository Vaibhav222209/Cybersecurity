import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity, ArrowRight, ArrowUpRight, Ban, Check, CheckCircle2, ChevronDown,
  ChevronRight, Clock3, Copy, Database, ExternalLink, FileText, Fingerprint,
  Globe2, Info, Laptop, LockKeyhole, Monitor, Network, Plus, Radar, RefreshCw,
  Search, Server, Shield, ShieldAlert, ShieldCheck, Terminal, TriangleAlert,
  Undo2, X,
} from 'lucide-react';
import './views.css';

const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const dateTime = value => {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Awaiting telemetry' : date.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
};
const normalize = value => String(value || 'info').toLowerCase();
const titleCase = value => String(value || '').replace(/[_-]/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
const evidenceText = evidence => typeof evidence === 'string' ? evidence : JSON.stringify(evidence || {}, null, 2);
const confidence = value => Math.min(100, Math.max(0, Number(value) || 0));

function Badge({ value, children }) {
  return <span className={`badge badge-${normalize(value)}`}>{children || titleCase(value)}</span>;
}

function ViewHeading({ eyebrow, title, description, children }) {
  return <div className="view-heading"><div><span className="view-eyebrow">{eyebrow}</span><h1>{title}</h1><p>{description}</p></div>{children && <div className="view-heading-actions">{children}</div>}</div>;
}

function Empty({ icon: Icon = ShieldCheck, title, description }) {
  return <div className="view-empty"><span><Icon size={26} /></span><h3>{title}</h3><p>{description}</p></div>;
}

function SearchField({ value, onChange, placeholder }) {
  return <label className="view-search"><Search size={16} /><input type="search" aria-label={placeholder} placeholder={placeholder} value={value} onChange={e => onChange(e.target.value)} />{value && <button type="button" aria-label="Clear search" onClick={() => onChange('')}><X size={14} /></button>}</label>;
}

function FilterSelect({ label, value, onChange, children }) {
  return <label className="view-filter"><span className="view-sr-only">{label}</span><select value={value} onChange={e => onChange(e.target.value)}>{children}</select><ChevronDown size={14} /></label>;
}

function LabNotice({ children }) {
  return <div className="view-lab-notice"><Shield size={16} /><span>{children || 'Enforcement applies to the managed local lab. External workstation protection requires an authenticated endpoint integration.'}</span><span className="view-lab-label">LOCAL LAB</span></div>;
}

function Confirmation({ action, busy, onClose, onConfirm }) {
  const cancelRef = useRef(null);
  useEffect(() => {
    if (!action) return;
    const previous = document.activeElement;
    cancelRef.current?.focus();
    const escape = e => { if (e.key === 'Escape' && !busy) onClose(); };
    document.addEventListener('keydown', escape);
    return () => { document.removeEventListener('keydown', escape); previous?.focus?.(); };
  }, [action, busy, onClose]);
  if (!action) return null;
  return <div className="view-dialog-backdrop" onClick={e => { if (e.target === e.currentTarget && !busy) onClose(); }}>
    <section className="view-confirm panel" role="dialog" aria-modal="true" aria-labelledby="view-confirm-title" onKeyDown={e => {
      if (e.key !== 'Tab') return;
      const focusable = Array.from(e.currentTarget.querySelectorAll('button:not([disabled])'));
      if (!focusable.length) return;
      if (e.shiftKey && document.activeElement === focusable[0]) { e.preventDefault(); focusable.at(-1)?.focus(); }
      else if (!e.shiftKey && document.activeElement === focusable.at(-1)) { e.preventDefault(); focusable[0]?.focus(); }
    }}>
      <span className={`view-confirm-icon ${action.danger ? 'is-danger' : ''}`}><ShieldAlert size={25} /></span>
      <h2 id="view-confirm-title">{action.title}</h2><p>{action.detail}</p>
      <div className="view-confirm-actions"><button ref={cancelRef} className="btn btn-ghost" disabled={busy} onClick={onClose}>Cancel</button><button className={`btn ${action.danger ? 'view-btn-danger' : 'btn-primary'}`} disabled={busy} onClick={onConfirm}>{busy ? <><RefreshCw size={15} className="view-spinning" /> Applying…</> : action.label}</button></div>
    </section>
  </div>;
}

function useConfirmation(onAction, busy) {
  const [action, setAction] = useState(null);
  const close = React.useCallback(() => setAction(null), []);
  const dialog = <Confirmation action={action} busy={busy} onClose={close} onConfirm={async () => {
    if (!action || busy) return;
    const result = await onAction(action.path, action.body, action.success || action.label);
    if (result) setAction(null);
  }} />;
  return [setAction, dialog];
}

function IncidentsView({ state, onAction, busy }) {
  const incidents = state.incidents || [];
  const assets = state.assets || [];
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('all');
  const [severity, setSeverity] = useState('all');
  const [expanded, setExpanded] = useState(null);
  const [confirm, dialog] = useConfirmation(onAction, busy);
  const filtered = incidents.filter(i => (status === 'all' || i.status === status) && (severity === 'all' || normalize(i.severity) === severity) && `${i.title} ${i.assetName} ${i.id} ${i.sourceIp} ${i.technique}`.toLowerCase().includes(search.toLowerCase()));
  const open = incidents.filter(i => i.status !== 'resolved');
  const counts = [
    { label: 'Active incidents', value: open.length, icon: ShieldAlert, color: 'coral' },
    { label: 'Under investigation', value: incidents.filter(i => i.status === 'investigating').length, icon: Search, color: 'cyan' },
    { label: 'Contained', value: incidents.filter(i => i.status === 'contained').length, icon: LockKeyhole, color: 'lime' },
    { label: 'Resolved', value: incidents.filter(i => i.status === 'resolved').length, icon: ShieldCheck, color: 'muted' },
  ];
  return <div className="view-page">
    <ViewHeading eyebrow="DETECT · INVESTIGATE · RESPOND" title="Incident workspace" description="Follow each signal from detection to a documented response." />
    <div className="view-stat-grid">{counts.map(item => <div className="view-mini-stat panel" key={item.label}><div className={`view-stat-icon ${item.color}`}><item.icon size={19} /></div><span>{item.label}</span><strong>{item.value}</strong></div>)}</div>
    <div className="panel view-table-panel">
      <div className="view-panel-heading"><div><h2>Incident queue <span className="view-count">{incidents.length}</span></h2><p>Correlated detections with actionable evidence</p></div><span className="view-updating"><span /> Live updates</span></div>
      <div className="view-toolbar"><SearchField value={search} onChange={setSearch} placeholder="Search incidents, assets or source IPs" /><div className="view-filters"><FilterSelect label="Filter incident status" value={status} onChange={setStatus}><option value="all">All statuses</option><option value="open">Open</option><option value="investigating">Investigating</option><option value="contained">Contained</option><option value="resolved">Resolved</option></FilterSelect><FilterSelect label="Filter incident severity" value={severity} onChange={setSeverity}><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></FilterSelect></div></div>
      {filtered.length ? <div className="view-table-scroll"><table className="view-table"><thead><tr><th>Incident</th><th>Severity</th><th>Asset</th><th>Status</th><th>Detected</th><th><span className="view-sr-only">Details</span></th></tr></thead><tbody>{filtered.map(incident => {
        const asset = assets.find(a => a.id === incident.assetId);
        const techniqueId = String(incident.technique || '').match(/T\d{4}(?:\.\d{3})?/)?.[0];
        const isExpanded = expanded === incident.id;
        return <React.Fragment key={incident.id}><tr className={isExpanded ? 'view-row-selected' : ''}><td><button className="view-title-button" onClick={() => setExpanded(isExpanded ? null : incident.id)} aria-expanded={isExpanded}><span className={`view-severity-dot ${normalize(incident.severity)}`} /><span><strong>{incident.title}</strong><small className="mono">{incident.id}</small></span></button></td><td><Badge value={incident.severity} /></td><td><span className="view-cell-asset"><Monitor size={14} />{incident.assetName || 'Local security lab'}</span></td><td><Badge value={incident.status} /></td><td className="view-cell-muted">{dateTime(incident.createdAt)}</td><td><button className="view-icon-button" aria-label={`${isExpanded ? 'Hide' : 'Show'} details for ${incident.title}`} onClick={() => setExpanded(isExpanded ? null : incident.id)}>{isExpanded ? <ChevronDown size={18} /> : <ChevronRight size={18} />}</button></td></tr>
          {isExpanded && <tr className="view-detail-row"><td colSpan="6"><div className="view-incident-detail"><div><span className="view-eyebrow">INVESTIGATION CONTEXT</span><p>{incident.description || 'Review the correlated logs and source indicator before deciding on a containment action.'}</p><div className="view-detail-facts"><div><span>Source address</span><code>{incident.sourceIp || 'Unavailable'}</code></div><div><span>MITRE ATT&CK</span>{techniqueId ? <a href={`https://attack.mitre.org/techniques/${techniqueId.replace('.', '/')}/`} target="_blank" rel="noreferrer">{incident.technique}<ExternalLink size={12} /></a> : <span>Unmapped</span>}</div><div><span>Endpoint state</span><Badge value={asset?.status || 'online'} /></div></div></div><div className="view-detail-action-column"><span className="view-eyebrow">RESPONSE ACTIONS</span>{incident.status === 'open' && <button className="btn btn-primary" disabled={busy} onClick={() => onAction(`/api/incidents/${incident.id}/status`, { status: 'investigating' }, 'Investigation started')}><Search size={15} /> Investigate</button>}{incident.sourceIp && <button className="btn btn-ghost" disabled={busy} onClick={() => confirm({ title: 'Block this source?', detail: `Block ${incident.sourceIp} in the local lab ingress policy. Subsequent matching requests to the lab workloads will be denied and recorded in the audit trail.`, path: '/api/block', body: { sourceIp: incident.sourceIp }, label: 'Block source', success: 'Source blocked', danger: true })}><Ban size={15} /> Block source</button>}{asset && asset.status === 'online' && <button className="btn btn-ghost" disabled={busy} onClick={() => confirm({ title: `Isolate ${asset.name}?`, detail: 'Restrict communication through the local lab policy while preserving its security telemetry. This action is reversible from Asset inventory.', path: `/api/assets/${asset.id}/action`, body: { action: 'isolate' }, label: 'Isolate workstation', success: 'Workstation isolated', danger: true })}><LockKeyhole size={15} /> Isolate endpoint</button>}{incident.status !== 'contained' && incident.status !== 'resolved' && <button className="btn btn-ghost" disabled={busy} onClick={() => onAction(`/api/incidents/${incident.id}/status`, { status: 'contained' }, 'Incident marked contained')}><Shield size={15} /> Mark contained</button>}{incident.status !== 'resolved' && <button className="btn btn-ghost" disabled={busy} onClick={() => confirm({ title: 'Resolve this incident?', detail: 'Confirm the threat is contained, relevant evidence has been reviewed, and recovery is complete. The incident remains available in your audit history.', path: `/api/incidents/${incident.id}/status`, body: { status: 'resolved' }, label: 'Resolve incident', success: 'Incident resolved' })}><CheckCircle2 size={15} /> Resolve incident</button>}{incident.status === 'resolved' && <button className="btn btn-ghost" disabled={busy} onClick={() => onAction(`/api/incidents/${incident.id}/status`, { status: 'open' }, 'Incident reopened')}><Undo2 size={15} /> Reopen incident</button>}</div></div></td></tr>}
        </React.Fragment>;
      })}</tbody></table></div> : <Empty title={incidents.length ? 'No matching incidents' : 'Your incident queue is clear'} description={incidents.length ? 'Try a different search or filter.' : 'Detections from live telemetry will appear here.'} />}
    </div><LabNotice />{dialog}
  </div>;
}

function VulnerabilitiesView({ state, onAction, busy }) {
  const findings = state.findings || [];
  const assets = state.assets || [];
  const [assetId, setAssetId] = useState('');
  const [status, setStatus] = useState('all');
  const [search, setSearch] = useState('');
  const [expanded, setExpanded] = useState(null);
  const [confirm, dialog] = useConfirmation(onAction, busy);
  const filtered = findings.filter(f => (status === 'all' || f.status === status) && `${f.title} ${f.assetName} ${f.cve || ''}`.toLowerCase().includes(search.toLowerCase())).sort((a, b) => (severityOrder[normalize(a.severity)] ?? 5) - (severityOrder[normalize(b.severity)] ?? 5));
  const containedTarget = assetId ? assets.find(a => a.id === assetId)?.status !== 'online' : assets.some(a => a.status !== 'online');
  const open = findings.filter(f => f.status === 'open');
  const verified = findings.filter(f => f.status === 'mitigated');
  const scanTime = state.lastScanAt || state.scan?.completedAt || findings.map(f => f.verifiedAt).filter(Boolean).sort().at(-1);
  return <div className="view-page">
    <ViewHeading eyebrow="DISCOVER · PRIORITIZE · REMEDIATE" title="Vulnerability management" description="Turn exposure into verified remediation in your managed lab."><div className="view-scan-control"><FilterSelect label="Choose scan target" value={assetId} onChange={setAssetId}><option value="">All lab assets</option>{assets.map(asset => <option key={asset.id} value={asset.id}>{asset.name}{asset.status !== 'online' ? ` · ${asset.status}` : ''}</option>)}</FilterSelect><button className="btn btn-primary" disabled={busy || containedTarget} title={containedTarget ? 'Restore contained targets or select an online asset before scanning' : undefined} onClick={() => onAction('/api/scan', assetId ? { assetId } : {}, 'Vulnerability scan completed')}><Radar size={17} className={busy ? 'view-spinning' : ''} />{busy ? 'Working…' : 'Run assessment'}</button></div></ViewHeading>
    <div className="view-vulnerability-summary"><div className="panel view-exposure-card"><div className="view-panel-heading"><h2>Exposure overview</h2><span className="view-soft-label">CURRENT STATE</span></div><div className="view-exposure-content"><div className="view-exposure-total"><strong>{open.length}</strong><span>open findings</span></div><div className="view-severity-breakdown">{['critical', 'high', 'medium', 'low'].map(level => <div key={level}><span className={`view-severity-dot ${level}`} /><span>{titleCase(level)}</span><strong>{open.filter(f => normalize(f.severity) === level).length}</strong></div>)}</div></div></div><div className="panel view-verification-card"><div className="view-stat-icon lime"><ShieldCheck size={24} /></div><div><span className="view-eyebrow">VERIFIED REMEDIATION</span><strong>{verified.length}<span> mitigated</span></strong><p>Apply supported local fixes, then reassess to verify the result.</p></div><div className="view-verification-footer"><Clock3 size={13} />{scanTime ? `Last verification ${dateTime(scanTime)}` : 'Run an assessment to establish a baseline'}</div></div></div>
    <LabNotice>Assessments inspect the deliberately vulnerable local lab. Fixes change its actual configuration and are verified by a follow-up check.</LabNotice>
    {containedTarget && <div className="view-containment-warning"><LockKeyhole size={14} /><span>Containment blocks assessment traffic. Select an online asset or restore the contained targets in Asset inventory before scanning.</span></div>}
    <div className="panel view-table-panel"><div className="view-panel-heading"><div><h2>Security findings <span className="view-count">{findings.length}</span></h2><p>Ordered by severity · inspect evidence before applying a fix</p></div><span className="view-soft-label">VAPT</span></div><div className="view-toolbar"><SearchField value={search} onChange={setSearch} placeholder="Search findings, assets or CWEs" /><FilterSelect label="Filter finding status" value={status} onChange={setStatus}><option value="all">All findings</option><option value="open">Open findings</option><option value="mitigated">Mitigated</option></FilterSelect></div>
      {filtered.length ? <div className="view-finding-list">{filtered.map(finding => {
        const isExpanded = expanded === finding.id;
        const isContained = assets.find(asset => asset.id === finding.assetId)?.status !== 'online';
        return <div className={`view-finding ${isExpanded ? 'is-expanded' : ''}`} key={finding.id}><div className="view-finding-top"><span className={`view-finding-symbol ${normalize(finding.severity)}`}><ShieldAlert size={20} /></span><button className="view-finding-title" onClick={() => setExpanded(isExpanded ? null : finding.id)} aria-expanded={isExpanded}><strong>{finding.title}</strong><span><Monitor size={12} /> {finding.assetName || 'Local lab'}<span className="view-middle-dot">·</span>{finding.cve || 'Configuration assessment'}</span></button><div className="view-finding-meta"><Badge value={finding.severity} />{finding.cvss != null && <span className="view-cvss" title="Illustrative CVSS estimate for this intentionally vulnerable lab; not a published advisory score">Lab score <b>{Number(finding.cvss).toFixed(1)}</b></span>}<Badge value={finding.status} /></div><button className="view-icon-button" aria-label={`${isExpanded ? 'Hide' : 'Show'} evidence for ${finding.title}`} onClick={() => setExpanded(isExpanded ? null : finding.id)}>{isExpanded ? <ChevronDown size={18} /> : <ChevronRight size={18} />}</button></div>
          {isExpanded && <div className="view-finding-detail"><div className="view-finding-description"><p>{finding.description}</p><div className="view-remediation-note"><ShieldCheck size={18} /><div><h4>Recommended mitigation</h4><p>{finding.remediation || 'Review the configuration evidence and apply the documented lab policy fix.'}</p></div></div></div><div className="view-evidence"><span className="view-eyebrow">ASSESSMENT EVIDENCE</span><pre>{evidenceText(finding.evidence)}</pre></div><div className="view-finding-footer"><span><Clock3 size={13} />{isContained && finding.status === 'open' ? 'Restore this asset before applying a verified fix' : finding.verifiedAt ? `Verified ${dateTime(finding.verifiedAt)}` : 'Awaiting mitigation verification'}</span>{finding.status === 'open' ? <button className="btn btn-primary" disabled={busy || isContained} title={isContained ? 'Restore the asset from Asset inventory first' : undefined} onClick={() => confirm({ title: 'Apply and verify this mitigation?', detail: `${finding.remediation || 'Apply the supported fix to the managed local lab.'} A follow-up assessment verifies the changed configuration.`, path: `/api/findings/${finding.id}/mitigate`, body: {}, label: 'Apply mitigation', success: 'Mitigation applied and verified' })}><ShieldCheck size={16} /> Apply mitigation</button> : <span className="view-verified-text"><CheckCircle2 size={16} /> Mitigation verified</span>}</div></div>}
        </div>;
      })}</div> : <Empty icon={Radar} title={findings.length ? 'No matching findings' : 'Start with a security assessment'} description={findings.length ? 'Change the filter or search to see your findings.' : 'Run an assessment to inspect local lab configuration and collect evidence.'} />}
    </div>{dialog}
  </div>;
}

function AssetsView({ state, onAction, busy }) {
  const assets = state.assets || [];
  const [search, setSearch] = useState('');
  const [expanded, setExpanded] = useState(null);
  const [confirm, dialog] = useConfirmation(onAction, busy);
  const filtered = assets.filter(a => `${a.name} ${a.ip} ${a.os} ${a.type}`.toLowerCase().includes(search.toLowerCase()));
  const action = (asset, type) => {
    const details = {
      isolate: { title: `Isolate ${asset.name}?`, detail: 'The local lab policy restricts this endpoint’s application communication and continues to collect security telemetry. Use Restore access after investigation and recovery.', label: 'Isolate endpoint', success: 'Workstation isolated', danger: true },
      quarantine: { title: `Quarantine ${asset.name}?`, detail: 'Mark this managed lab asset as quarantined for investigation and deny its application traffic through the lab gateway. Security telemetry and the audit record remain available.', label: 'Quarantine endpoint', success: 'Workstation quarantined', danger: true },
      restore: { title: `Restore ${asset.name}?`, detail: 'Restore this lab asset’s application access after you have reviewed the incident, removed the threat, and verified its security configuration.', label: 'Restore access', success: 'Workstation access restored' },
    };
    confirm({ ...details[type], path: `/api/assets/${asset.id}/action`, body: { action: type } });
  };
  return <div className="view-page"><ViewHeading eyebrow="KNOW · PROTECT · CONTAIN" title="Asset inventory" description="A clear view of every managed endpoint and its security posture."><span className="view-heading-pill"><Network size={16} />{assets.length} managed assets</span></ViewHeading>
    <div className="view-asset-overview panel"><div><span className="view-asset-count-dot online" /><strong>{assets.filter(a => a.status === 'online').length}</strong><span>Online</span></div><div><span className="view-asset-count-dot isolated" /><strong>{assets.filter(a => a.status === 'isolated').length}</strong><span>Isolated</span></div><div><span className="view-asset-count-dot quarantined" /><strong>{assets.filter(a => a.status === 'quarantined').length}</strong><span>Quarantined</span></div><SearchField value={search} onChange={setSearch} placeholder="Search asset name, IP or OS" /></div>
    <LabNotice />
    {filtered.length ? <div className="view-asset-grid">{filtered.map(asset => {
      const Icon = /server|linux/i.test(`${asset.type}`) ? Server : /laptop|workstation/i.test(`${asset.type}`) ? Laptop : Monitor;
      const risk = Math.min(100, Math.max(0, Number(asset.riskScore) || 0));
      const incidents = (state.incidents || []).filter(i => i.assetId === asset.id && i.status !== 'resolved');
      const findings = (state.findings || []).filter(f => f.assetId === asset.id && f.status === 'open');
      const isExpanded = expanded === asset.id;
      return <article className={`panel view-asset-card ${asset.status !== 'online' ? 'is-contained' : ''}`} key={asset.id}>
        <div className="view-asset-card-top"><span className="view-asset-symbol"><Icon size={25} /></span><Badge value={asset.status} /></div><h2>{asset.name}</h2><p className="view-asset-ip mono">{asset.ip || 'Local endpoint'}<span>{asset.managed ? 'Managed' : 'Unmanaged'}</span></p><div className="view-asset-platform"><span>{asset.os || 'Local lab runtime'}</span><span>{titleCase(asset.type || 'workstation')}</span></div>
        <div className="view-asset-risk"><div className={`view-risk-ring ${risk >= 70 ? 'risk-high' : risk >= 40 ? 'risk-medium' : 'risk-low'}`} style={{ '--risk-angle': `${risk * 3.6}deg` }}><span>{risk}</span></div><div><strong>Risk score</strong><p>{risk >= 70 ? 'Prioritize investigation' : risk >= 40 ? 'Needs your attention' : 'Within normal range'}</p></div><Shield size={18} /></div>
        <div className="view-asset-counters"><button onClick={() => setExpanded(isExpanded ? null : asset.id)} aria-expanded={isExpanded}><strong>{incidents.length}</strong><span>Active incidents</span></button><button onClick={() => setExpanded(isExpanded ? null : asset.id)} aria-expanded={isExpanded}><strong>{findings.length}</strong><span>Open findings</span></button></div>
        {isExpanded && <div className="view-asset-details"><span className="view-eyebrow">SECURITY CONTEXT</span>{incidents.length || findings.length ? <ul>{incidents.slice(0, 3).map(i => <li key={i.id}><span className={`view-severity-dot ${normalize(i.severity)}`} /><span>{i.title}</span></li>)}{findings.slice(0, 3).map(f => <li key={f.id}><ShieldAlert size={12} /><span>{f.title}</span></li>)}</ul> : <p>No active incidents or open findings.</p>}<span className="view-asset-last-seen"><Activity size={12} /> Last seen {dateTime(asset.lastSeen)}</span></div>}
        <div className="view-asset-card-actions">{asset.status === 'online' ? <><button className="btn btn-ghost" disabled={busy || !asset.managed} onClick={() => action(asset, 'isolate')}><LockKeyhole size={14} /> Isolate</button><button className="btn view-btn-danger-outline" disabled={busy || !asset.managed} onClick={() => action(asset, 'quarantine')}><ShieldAlert size={14} /> Quarantine</button></> : <><button className="btn btn-primary" disabled={busy || !asset.managed} onClick={() => action(asset, 'restore')}><Undo2 size={14} /> Restore access</button>{asset.status === 'isolated' && <button className="view-icon-button view-danger-icon" disabled={busy || !asset.managed} aria-label={`Quarantine ${asset.name}`} onClick={() => action(asset, 'quarantine')}><ShieldAlert size={18} /></button>}</>}</div>
      </article>;
    })}</div> : <div className="panel"><Empty icon={Monitor} title={assets.length ? 'No matching assets' : 'No managed assets yet'} description={assets.length ? 'Try an asset name or a different IP address.' : 'Managed local lab assets will appear after the runtime starts.'} /></div>}
    <div className="view-containment-guide panel"><div className="view-stat-icon cyan"><LockKeyhole size={21} /></div><div><h3>Containment with a recovery path</h3><p>Isolation denies application traffic through the local lab gateway. Quarantine also denies traffic and marks the asset for investigation. Both preserve security telemetry and can be reversed with Restore access.</p></div></div>{dialog}
  </div>;
}

function IntelMap({ indicators }) {
  const count = indicators.length;
  return <div className="view-intel-map" aria-label={`${count} threat indicators in the local intelligence feed`}>
    <svg viewBox="0 0 620 210" role="img"><defs><radialGradient id="intel-glow"><stop offset="0%" stopColor="#c4ef76" stopOpacity=".17" /><stop offset="100%" stopColor="#c4ef76" stopOpacity="0" /></radialGradient><linearGradient id="intel-line"><stop stopColor="#c4ef76" stopOpacity=".7" /><stop offset="100%" stopColor="#66c9cc" stopOpacity=".22" /></linearGradient></defs><circle cx="310" cy="106" r="130" fill="url(#intel-glow)" /><g fill="none" stroke="#27343b" strokeWidth="1"><ellipse cx="310" cy="106" rx="195" ry="68" /><ellipse cx="310" cy="106" rx="245" ry="91" /><ellipse cx="310" cy="106" rx="124" ry="40" /><path d="M80 106h460M310 10v192" /></g><g fill="none" stroke="url(#intel-line)" strokeWidth="1.3"><path d="M310 106L122 70M310 106L194 165M310 106L429 46M310 106L505 139" /></g><g className="view-intel-signal"><circle cx="310" cy="106" r="27" fill="none" stroke="#c4ef76" strokeOpacity=".3" /><circle cx="310" cy="106" r="41" fill="none" stroke="#c4ef76" strokeOpacity=".13" /></g><circle cx="310" cy="106" r="20" fill="#202c23" stroke="#c4ef76" /><path d="M310 94l9 4v7c0 6-9 12-9 12s-9-6-9-12v-7z" stroke="#c4ef76" strokeWidth="1.5" fill="none" />{[[122, 70, 'IP'], [194, 165, 'HASH'], [429, 46, 'DOMAIN'], [505, 139, 'FEED']].map(([x, y, label], i) => <g key={label}><circle cx={x} cy={y} r="5" fill={i % 2 ? '#66c9cc' : '#c4ef76'} /><circle className={`view-map-pulse pulse-${i}`} cx={x} cy={y} r="12" fill="none" stroke={i % 2 ? '#66c9cc' : '#c4ef76'} strokeOpacity=".35" /><text x={x + 14} y={y + 4} fill="#83909e" fontSize="10" fontFamily="monospace">{label}</text></g>)}</svg>
    <div className="view-intel-map-caption"><span className="view-updating"><span /> Indicator correlation</span><span>{count} intelligence records · topology illustration</span></div>
  </div>;
}

function IntelligenceView({ state, onAction, busy }) {
  const indicators = state.indicators || [];
  const blockedSources = state.blockedSources || [];
  const isBlocked = value => blockedSources.some(source => source.sourceIp === value);
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ type: 'ip', value: '', threat: '', confidence: 90 });
  const [error, setError] = useState('');
  const [confirm, dialog] = useConfirmation(onAction, busy);
  const filtered = indicators.filter(i => (typeFilter === 'all' || i.type === typeFilter) && `${i.value} ${i.threat} ${i.source}`.toLowerCase().includes(search.toLowerCase()));
  const sources = [...new Set(indicators.map(i => i.source).filter(Boolean))];
  const save = async e => {
    e.preventDefault();
    const value = form.value.trim();
    if (!value || !form.threat.trim()) { setError('Add an indicator value and a threat description.'); return; }
    if (form.type === 'hash' && !/^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$/.test(value)) { setError('Use a valid MD5, SHA-1, or SHA-256 hexadecimal hash.'); return; }
    if (form.type === 'domain' && (!value.includes('.') || /[\s/:]/.test(value))) { setError('Enter a domain such as suspicious.example without a protocol or path.'); return; }
    setError('');
    const result = await onAction('/api/indicators', { ...form, value, threat: form.threat.trim(), confidence: confidence(form.confidence) }, 'Threat indicator added');
    if (result) { setShowForm(false); setForm({ type: 'ip', value: '', threat: '', confidence: 90 }); }
  };
  return <div className="view-page"><ViewHeading eyebrow="ENRICH · CORRELATE · DEFEND" title="Threat intelligence" description="Connect live signals to known indicators and make informed decisions."><button className="btn btn-primary" onClick={() => { setShowForm(!showForm); setError(''); }}><Plus size={17} /> Add indicator</button></ViewHeading>
    <div className="view-intel-overview"><div className="panel view-intel-network"><div className="view-panel-heading"><div><h2>Intelligence network</h2><p>Your local indicator correlation layer</p></div><span className="view-soft-label">CONNECTED</span></div><IntelMap indicators={indicators} /></div><div className="view-intel-stats"><div className="panel view-intel-stat"><span className="view-stat-icon lime"><Fingerprint size={21} /></span><div><strong>{indicators.length}</strong><span>Active indicators</span></div></div><div className="panel view-intel-stat"><span className="view-stat-icon coral"><ShieldAlert size={21} /></span><div><strong>{indicators.filter(i => confidence(i.confidence) >= 80).length}</strong><span>High confidence signals</span></div></div><div className="panel view-intel-stat"><span className="view-stat-icon cyan"><Globe2 size={21} /></span><div><strong>{sources.length}</strong><span>Intelligence sources</span></div></div></div></div>
    {showForm && <form className="panel view-indicator-form" onSubmit={save}><div className="view-panel-heading"><div><h2>Add a threat indicator</h2><p>Correlate future events with a reviewed IP, domain or file hash.</p></div><button className="view-icon-button" type="button" aria-label="Close indicator form" onClick={() => setShowForm(false)}><X size={18} /></button></div><div className="view-form-grid"><label>Indicator type<select value={form.type} onChange={e => setForm({ ...form, type: e.target.value })}><option value="ip">IP address</option><option value="domain">Domain</option><option value="hash">File hash</option></select></label><label className="view-form-wide">Indicator value<input required autoComplete="off" placeholder={form.type === 'ip' ? 'e.g. 203.0.113.42' : form.type === 'domain' ? 'e.g. suspicious.example' : 'MD5, SHA-1 or SHA-256 hash'} value={form.value} onChange={e => setForm({ ...form, value: e.target.value })} /></label><label>Confidence %<input type="number" min="0" max="100" required value={form.confidence} onChange={e => setForm({ ...form, confidence: e.target.value })} /></label><label className="view-form-full">Threat description<input required maxLength="500" placeholder="Describe the observed threat or reason for tracking" value={form.threat} onChange={e => setForm({ ...form, threat: e.target.value })} /></label></div><div className="view-form-footer"><p className={error ? 'view-form-error' : ''} role={error ? 'alert' : undefined}>{error || 'Manually added indicators are labeled as user intelligence. Blocking is a separate explicit action.'}</p><button className="btn btn-primary" disabled={busy} type="submit"><Plus size={15} />{busy ? 'Saving…' : 'Save indicator'}</button></div></form>}
    <div className="panel view-table-panel"><div className="view-panel-heading"><div><h2>Indicator feed <span className="view-count">{indicators.length}</span></h2><p>Curated lab indicators and your own intelligence</p></div><span className="view-updating"><span /> Live correlation</span></div><div className="view-toolbar"><SearchField value={search} onChange={setSearch} placeholder="Search indicators, threats or sources" /><FilterSelect label="Filter indicator type" value={typeFilter} onChange={setTypeFilter}><option value="all">All indicator types</option><option value="ip">IP addresses</option><option value="domain">Domains</option><option value="hash">File hashes</option></FilterSelect></div>{filtered.length ? <div className="view-table-scroll"><table className="view-table view-intel-table"><thead><tr><th>Indicator</th><th>Threat context</th><th>Confidence</th><th>Source</th><th>Last seen</th><th>Action</th></tr></thead><tbody>{filtered.map(indicator => <tr key={indicator.id}><td><div className="view-indicator-value"><span className="view-indicator-type">{indicator.type === 'ip' ? <Network size={15} /> : indicator.type === 'domain' ? <Globe2 size={15} /> : <Fingerprint size={15} />}</span><div><code title={indicator.value}>{indicator.value}</code><small>{indicator.type === 'ip' ? 'IP ADDRESS' : indicator.type === 'domain' ? 'DOMAIN' : 'FILE HASH'}</small></div></div></td><td className="view-intel-threat">{indicator.threat}</td><td><div className="view-confidence"><span>{confidence(indicator.confidence)}<small>%</small></span><div><i style={{ width: `${confidence(indicator.confidence)}%` }} /></div></div></td><td><span className="view-source-label">{indicator.source || 'User intelligence'}</span></td><td className="view-cell-muted">{dateTime(indicator.lastSeen)}</td><td>{indicator.type === 'ip' && isBlocked(indicator.value) ? <span className="view-blocked-indicator"><ShieldCheck size={13} /> Blocked</span> : indicator.type === 'ip' ? <button className="btn btn-ghost view-small-button" disabled={busy} onClick={() => confirm({ title: 'Block this indicator?', detail: `Add ${indicator.value} to the local lab ingress block policy. Blocking applies only to traffic handled by the managed lab gateway.`, path: '/api/block', body: { sourceIp: indicator.value }, label: 'Block source', success: 'Threat indicator blocked', danger: true })}><Ban size={13} /> Block</button> : <span className="view-monitor-label"><Activity size={12} /> Correlate</span>}</td></tr>)}</tbody></table></div> : <Empty icon={Globe2} title={indicators.length ? 'No matching indicators' : 'Build your intelligence feed'} description={indicators.length ? 'Try searching by a different value or threat.' : 'Add a reviewed indicator to enrich matching log events.'} />}</div>
    <section className="panel view-deny-rules"><div className="view-panel-heading"><div><h2>Gateway deny rules <span className="view-count">{blockedSources.length}</span></h2><p>Reversible source blocks enforced on the managed lab workloads</p></div><LockKeyhole size={17} /></div>{blockedSources.length ? <div className="view-deny-rule-list">{blockedSources.map(source => <div className="view-deny-rule" key={source.sourceIp}><span className="view-deny-symbol"><Ban size={15} /></span><div><code>{source.sourceIp}</code><span>Blocked {dateTime(source.createdAt)}</span></div><span className="view-deny-status">Ingress denied</span><button className="btn btn-ghost view-small-button" disabled={busy} onClick={() => confirm({ title: 'Remove this source block?', detail: `Allow ${source.sourceIp} to access the local lab gateway again. Review the source and confirm that the threat has been addressed before removing this rule.`, path: '/api/unblock', body: { sourceIp: source.sourceIp }, label: 'Unblock source', success: 'Source block removed' })}><Undo2 size={13} /> Unblock</button></div>)}</div> : <div className="view-no-rules"><ShieldCheck size={16} /><span>No source blocks are active. Use Block on a reviewed IP indicator or suspicious event to add a rule.</span></div>}</section>
    <div className="view-intel-source-note"><Info size={14} /><p>Starter indicators use documentation addresses for the local exercise. Their confidence values are lab data. Review and add trusted intelligence before operational use.</p></div>{dialog}
  </div>;
}

function PlaybooksView({ state, onAction, busy }) {
  const playbooks = state.playbooks || [];
  const [selectedId, setSelectedId] = useState('');
  const [pendingSteps, setPendingSteps] = useState({});
  const effectiveStep = (playbookId, step) => ({ ...step, completed: pendingSteps[`${playbookId}:${step.id}`] ?? Boolean(step.completed) });
  const sourceSelected = playbooks.find(p => p.id === selectedId) || playbooks[0];
  const selected = sourceSelected ? { ...sourceSelected, steps: (sourceSelected.steps || []).map(step => effectiveStep(sourceSelected.id, step)) } : null;
  const toggleStep = async (playbookId, stepId, isCompleted) => {
    const key = `${playbookId}:${stepId}`;
    setPendingSteps(previous => ({ ...previous, [key]: isCompleted }));
    try {
      await onAction(`/api/playbooks/${playbookId}/steps/${stepId}`, { completed: isCompleted }, isCompleted ? 'Response step recorded' : 'Response step reopened');
    } finally {
      // A successful action already refreshed server state; failure restores its previous value.
      setPendingSteps(previous => { const next = { ...previous }; delete next[key]; return next; });
    }
  };
  const completed = selected?.steps?.filter(s => s.completed).length || 0;
  const total = selected?.steps?.length || 0;
  const percent = total ? Math.round(completed / total * 100) : 0;
  const phases = [...new Set((selected?.steps || []).map(s => s.phase))];
  return <div className="view-page"><ViewHeading eyebrow="PREPARE · RESPOND · RECOVER" title="Response playbooks" description="Repeatable incident response, grounded in recognized security guidance."><a className="btn btn-ghost" href="https://csrc.nist.gov/pubs/sp/800/61/r3/final" target="_blank" rel="noreferrer"><FileText size={16} /> NIST guidance <ArrowUpRight size={14} /></a></ViewHeading>
    <div className="view-standard-note"><ShieldCheck size={20} /><div><strong>Aligned with NIST SP 800-61 Rev. 3 and CSF 2.0</strong><p>Use Govern, Identify and Protect to prepare; Detect, Respond and Recover to handle incidents. Completion records your checklist progress; verify each action independently.</p></div><span className="view-soft-label">GUIDELINE ALIGNED</span></div>
    {playbooks.length ? <div className="view-playbooks-layout"><aside className="view-playbook-list panel"><div className="view-panel-heading"><h2>Response library</h2><span className="view-count">{playbooks.length}</span></div><nav aria-label="Select response playbook">{playbooks.map(playbook => {
      const count = playbook.steps?.filter(step => effectiveStep(playbook.id, step).completed).length || 0;
      return <button className={`view-playbook-nav ${selected?.id === playbook.id ? 'is-active' : ''}`} key={playbook.id} onClick={() => setSelectedId(playbook.id)}><span className="view-playbook-nav-icon"><FileText size={18} /></span><span><strong>{playbook.title}</strong><small>{count} / {playbook.steps?.length || 0} steps complete</small></span><ChevronRight size={15} /></button>;
    })}</nav><div className="view-playbook-library-footer"><span className="view-eyebrow">REFERENCE FRAMEWORKS</span><a href="https://www.nist.gov/cyberframework" target="_blank" rel="noreferrer">NIST Cybersecurity Framework 2.0 <ExternalLink size={12} /></a><a href="https://attack.mitre.org/" target="_blank" rel="noreferrer">MITRE ATT&CK <ExternalLink size={12} /></a></div></aside><section className="panel view-playbook-content"><div className="view-playbook-intro"><span className="view-eyebrow">INCIDENT RESPONSE PROCEDURE</span><h2>{selected.title}</h2><p>{selected.description}</p><span className="view-playbook-standard"><ShieldCheck size={13} />{selected.standard || 'NIST SP 800-61 Rev. 3 · CSF 2.0'}</span></div><div className="view-playbook-progress"><div><span>Response progress</span><strong>{completed}<span> / {total} steps</span></strong></div><div className="view-progress-track"><span style={{ width: `${percent}%` }} /></div><span>{percent}% complete</span></div><div className="view-playbook-phases">{phases.map((phase, phaseIndex) => <section className="view-playbook-phase" key={phase || phaseIndex}><div className="view-phase-heading"><span>{String(phaseIndex + 1).padStart(2, '0')}</span><h3>{titleCase(phase || 'Response')}</h3><i /></div>{selected.steps.filter(s => s.phase === phase).map(step => <label className={`view-playbook-step ${step.completed ? 'is-completed' : ''}`} key={step.id}><input type="checkbox" checked={Boolean(step.completed)} disabled={busy} onChange={e => toggleStep(selected.id, step.id, e.target.checked)} /><span className="view-step-check">{step.completed && <Check size={14} />}</span><span className="view-step-text"><strong>{step.title}</strong><span>{step.description}</span></span></label>)}</section>)}</div>{percent === 100 && <div className="view-playbook-complete"><ShieldCheck size={22} /><div><strong>Checklist complete</strong><p>Confirm recovery evidence, preserve the incident record, and capture lessons learned.</p></div></div>}<div className="view-playbook-bottom-note"><Info size={14} /><span>Checkboxes record operator progress. They do not execute containment or mitigation actions. Use the incident, asset and vulnerability workspaces to perform those actions.</span></div></section></div> : <div className="panel"><Empty icon={FileText} title="Loading response library" description="Your response procedures will appear when the local lab connects." /></div>}
  </div>;
}

function CopyCode({ text }) {
  const [copied, setCopied] = useState(false);
  const [failed, setFailed] = useState(false);
  const copy = async () => {
    try { await navigator.clipboard.writeText(text); setCopied(true); setFailed(false); window.setTimeout(() => setCopied(false), 1800); }
    catch { setFailed(true); }
  };
  return <div className="view-code-block"><button className="view-icon-button" type="button" aria-label={copied ? 'Copied' : 'Copy command'} onClick={copy}>{copied ? <Check size={15} /> : <Copy size={15} />}</button><pre>{text}</pre>{failed && <span className="view-copy-error" role="status">Select the command to copy it manually.</span>}</div>;
}

function SettingsView({ state }) {
  const audit = useMemo(() => [...(state.audit || [])].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)).slice(0, 20), [state.audit]);
  return <div className="view-page"><ViewHeading eyebrow="CONFIGURE · CONNECT · VERIFY" title="Lab & integrations" description="Understand your runtime, connect telemetry and review every response action." />
    <div className="view-settings-grid"><section className="panel view-runtime-card"><div className="view-panel-heading"><h2>Environment</h2><Badge value="online">Local lab</Badge></div><div className="view-runtime-emblem"><Shield size={30} /><span>AEGIS</span><small>SECURITY OPERATIONS LAB</small></div><dl className="view-runtime-facts"><div><dt>Operating mode</dt><dd>Managed local security lab</dd></div><div><dt>Telemetry</dt><dd>Live event stream</dd></div><div><dt>Response scope</dt><dd>Local gateway policy</dd></div><div><dt>Vulnerability checks</dt><dd>Configuration assessment</dd></div><div><dt>Incident guidance</dt><dd>NIST SP 800-61 Rev. 3</dd></div><div><dt>Project creator</dt><dd>Vaibhav Thakur</dd></div></dl></section><section className="panel view-integration-card"><div className="view-panel-heading"><div><h2>Connect your workflow</h2><p>A small, observable security lab you can develop further.</p></div><Terminal size={19} /></div><div className="view-integration-step"><span>01</span><div><h3>Keep the local runtime running</h3><p>The API generates lab telemetry, correlates indicators, tracks incidents, and persists response actions.</p><CopyCode text="npm run dev" /></div></div><div className="view-integration-step"><span>02</span><div><h3>Forward your JSONL security logs</h3><p>Replace the file path below with your event log. The collector watches appended lines and sends them to <code>POST /api/ingest</code>. Add <code>--once</code> for a one-time import. If ingestion authentication is configured, the collector reads <code>INGEST_TOKEN</code> from its environment.</p><CopyCode text="python3 scripts/collector.py --file /path/to/events.jsonl --url http://127.0.0.1:3001/api/ingest --from-start" /></div></div><div className="view-integration-step"><span>03</span><div><h3>Verify detection and practical remediation</h3><p>Run a scenario from Overview, inspect its incident, then use Vulnerability management to assess and mitigate a local configuration weakness. The README covers event fields, authentication, verification commands, and external endpoint integration boundaries.</p></div></div><div className="view-integration-status"><Database size={15} /><span>Lab policy and incident history are persisted by the local API.</span></div></section></div>
    <div className="view-scope-note"><Info size={18} /><div><strong>Know the response boundary</strong><p>Blocking, isolation, quarantine, and remediation affect this managed lab. Connecting production systems requires scoped authentication, a tested endpoint or firewall integration, and authorization for that environment.</p></div></div>
    <section className="panel view-table-panel"><div className="view-panel-heading"><div><h2>Operation audit <span className="view-count">{state.audit?.length || 0}</span></h2><p>Latest response actions and their recorded results</p></div><span className="view-soft-label">LAST 20 EVENTS</span></div>{audit.length ? <div className="view-table-scroll"><table className="view-table"><thead><tr><th>Timestamp</th><th>Operation</th><th>Target</th><th>Result</th></tr></thead><tbody>{audit.map(entry => <tr key={entry.id}><td className="view-cell-muted mono">{dateTime(entry.timestamp)}</td><td><span className="view-audit-operation"><Activity size={14} />{titleCase(entry.action)}</span></td><td className="mono">{entry.target || 'Local lab'}</td><td><span className={`view-audit-result ${/fail|error|denied/i.test(entry.result || '') ? 'is-error' : ''}`}><span />{typeof entry.result === 'string' ? entry.result : evidenceText(entry.result)}</span></td></tr>)}</tbody></table></div> : <Empty icon={Activity} title="Your audit trail starts here" description="Run an assessment or apply a response action to create a recorded event." />}</section>
  </div>;
}

export default function WorkspaceView({ view, state = {}, onAction, busy = false }) {
  const props = { state, onAction, busy };
  switch (view) {
    case 'incidents': return <IncidentsView {...props} />;
    case 'vulnerabilities': return <VulnerabilitiesView {...props} />;
    case 'assets': return <AssetsView {...props} />;
    case 'intelligence': return <IntelligenceView {...props} />;
    case 'playbooks': return <PlaybooksView {...props} />;
    case 'settings': return <SettingsView {...props} />;
    default: return null;
  }
}

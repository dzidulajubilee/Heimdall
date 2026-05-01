/* eslint-disable */
'use strict';
const { useState, useEffect, useRef, useMemo, useCallback } = React;

// ── Themes ────────────────────────────────────────────────────────────────────
const THEMES = [
  { id:'night',     label:'Night',          accent:'#6366f1', dot:'#07080f' },
  { id:'light',     label:'Light',          accent:'#4f46e5', dot:'#f0f2fa' },
  { id:'midnight',  label:'Midnight Blue',  accent:'#818cf8', dot:'#0d1117' },
  { id:'solarized', label:'Solarized Dark', accent:'#268bd2', dot:'#002b36' },
  { id:'dracula',   label:'Dracula',        accent:'#bd93f9', dot:'#191a21' },
  { id:'nord',      label:'Nord',           accent:'#88c0d0', dot:'#2e3440' },
];

function ThemePicker({ theme, onChange }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  const current = THEMES.find(t => t.id === theme) || THEMES[0];
  useEffect(() => {
    const h = e => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, []);
  return (
    <div style={{ position:'relative' }} ref={ref}>
      <button className="theme-btn" onClick={() => setOpen(o => !o)}>
        <div className="theme-swatch-dot" style={{ background:current.accent }} />
        <span>{current.label}</span>
        <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M2 4l3 3 3-3"/></svg>
      </button>
      {open && (
        <div className="theme-dropdown">
          {THEMES.map(t => (
            <div key={t.id} className={`theme-option${theme===t.id?' active':''}`}
                 onClick={() => { onChange(t.id); setOpen(false); }}>
              <div style={{ width:10,height:10,borderRadius:'50%',background:t.dot,border:`2px solid ${t.accent}`,flexShrink:0 }}/>
              <div style={{ width:10,height:10,borderRadius:'50%',background:t.accent,flexShrink:0 }}/>
              <span>{t.label}</span>
              {theme===t.id && <svg style={{ marginLeft:'auto' }} width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="2"><path d="M2 5l2.5 2.5L8 3"/></svg>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Constants ─────────────────────────────────────────────────────────────────
const SEV_ORDER = ['critical','high','medium','low','info'];
const SEV_META = {
  critical:{ color:'var(--sev-critical)', bg:'var(--sev-critical-bg)', label:'Critical' },
  high:    { color:'var(--sev-high)',     bg:'var(--sev-high-bg)',     label:'High'     },
  medium:  { color:'var(--sev-medium)',   bg:'var(--sev-medium-bg)',   label:'Medium'   },
  low:     { color:'var(--sev-low)',      bg:'var(--sev-low-bg)',      label:'Low'      },
  info:    { color:'var(--sev-info)',     bg:'var(--sev-info-bg)',     label:'Info'     },
};
const TRIAGE_META = {
  acknowledged:{ label:'Acknowledged', cls:'t-ack' },
  investigating:{ label:'Investigating', cls:'t-inv' },
  closed:       { label:'Closed',        cls:'t-clo' },
};
const ROLE_META     = { admin:{label:'Admin'}, analyst:{label:'Analyst'}, viewer:{label:'Viewer'} };
const ALL_SEVS      = ['critical','high','medium','low','info'];
const WEBHOOK_TYPES = ['slack','discord','generic'];
const CHART_WINDOWS = [{hrs:24,label:'24h'},{hrs:168,label:'7d'},{hrs:720,label:'30d'},{hrs:1440,label:'60d'},{hrs:2160,label:'90d'}];

function fmtAlertTime(ts) {
  if (!ts) return '';
  const d = new Date(ts); if (isNaN(d)) return ts;
  const now = new Date();
  const time = d.toLocaleTimeString([], { hour:'numeric', minute:'2-digit', hour12:true });
  const todayMid = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const yestMid  = new Date(todayMid - 864e5);
  if (d >= todayMid) return time;
  if (d >= yestMid)  return 'Yesterday at ' + time;
  return d.toLocaleDateString([], { month:'short', day:'numeric' }) + ' · ' + time;
}
function fmtDetailTime(ts) {
  if (!ts) return '';
  const d = new Date(ts); if (isNaN(d)) return ts;
  return d.toLocaleDateString([], { month:'short', day:'numeric', year:'numeric' })
    + ' · ' + d.toLocaleTimeString([], { hour:'numeric', minute:'2-digit', hour12:true });
}

function ConfirmDialog({ title, body, confirmLabel='Confirm', variant='danger', onConfirm, onClose }) {
  const ic = variant==='danger' ? 'var(--danger)' : 'var(--sev-medium)';
  const icon = variant==='danger'
    ? <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={ic} strokeWidth="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/></svg>
    : <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={ic} strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>;
  return (
    <div className="confirm-backdrop" onClick={e => e.target===e.currentTarget && onClose()}>
      <div className="confirm-box">
        <div className={`confirm-icon ${variant}`}>{icon}</div>
        <div className="confirm-title">{title}</div>
        <div className="confirm-body" dangerouslySetInnerHTML={{ __html:body }} />
        <div className="confirm-footer">
          <button className="btn-modal" onClick={onClose}>Cancel</button>
          <button className="btn-modal confirm"
            style={variant==='danger'?{background:'var(--danger-bg)',borderColor:'var(--danger)',color:'var(--danger)'}:{}}
            onClick={() => { onConfirm(); onClose(); }}>{confirmLabel}</button>
        </div>
      </div>
    </div>
  );
}

// ── Bento stat strip ──────────────────────────────────────────────────────────
function BentoStrip({ alerts, dbStats, sparkData }) {
  const counts = useMemo(() => {
    const c = { critical:0, high:0, medium:0, low:0, info:0, unreviewed:0 };
    alerts.forEach(a => {
      if (c[a.severity] !== undefined) c[a.severity]++;
      if (!a.status) c.unreviewed++;
    });
    return c;
  }, [alerts]);
  const topIp = useMemo(() => {
    const freq = {};
    alerts.forEach(a => { if (a.src_ip) freq[a.src_ip] = (freq[a.src_ip]||0) + 1; });
    const ips = Object.entries(freq).sort((a,b) => b[1]-a[1]);
    return ips[0] ? { ip:ips[0][0], count:ips[0][1] } : null;
  }, [alerts]);
  const sparkMax = Math.max(...sparkData, 1);
  return (
    <div className="bento-strip">
      <div className="bento-cell">
        <div className="bc-label">Total alerts</div>
        <div className="bc-value">{alerts.length}</div>
        <div className="bc-sub">
          {counts.critical > 0
            ? <span className="bc-badge warn">{counts.critical} critical</span>
            : <span className="bc-badge ok">no critical</span>}
        </div>
      </div>
      <div className="bento-cell">
        <div className="bc-label">Unreviewed</div>
        <div className="bc-value" style={{ color: counts.unreviewed > 0 ? 'var(--sev-high)' : 'var(--success)' }}>
          {counts.unreviewed}
        </div>
        <div className="bc-sub" style={{ color:'var(--tx3)' }}>
          {alerts.length ? Math.round(counts.unreviewed/alerts.length*100) : 0}% of total
        </div>
      </div>
      <div className="bento-cell">
        <div className="bc-label">Top source IP</div>
        <div className="bc-value" style={{ fontSize:13, paddingTop:3, fontFamily:'var(--mono)', color:'var(--accent)' }}>
          {topIp?.ip || '—'}
        </div>
        <div className="bc-sub" style={{ color:'var(--tx3)' }}>
          {topIp ? `${topIp.count} alerts` : 'no data'}
        </div>
      </div>
      <div className="bento-cell">
        <div className="bc-label">Severity split</div>
        <div className="bc-mini-bars">
          {SEV_ORDER.slice(0,4).map(s => {
            const m = SEV_META[s];
            const h = alerts.length ? Math.max(3, Math.round(counts[s]/alerts.length*36)) : 3;
            return (
              <div key={s} title={`${m.label}: ${counts[s]}`} className="bc-mini-bar"
                   style={{ height:h, background:m.color, opacity:counts[s]>0?1:0.15 }}/>
            );
          })}
        </div>
        <div className="bc-sub" style={{ color:'var(--tx3)', marginTop:2 }}>H:{counts.high} M:{counts.medium} L:{counts.low}</div>
      </div>
      <div className="bento-cell">
        <div className="bc-label">60s volume</div>
        <div className="bc-mini-bars" style={{ marginTop:4 }}>
          {sparkData.slice(-20).map((v,i) => {
            const h = Math.max(2, Math.round((v/sparkMax)*36));
            const bg = v>sparkMax*.75?'var(--sev-critical)':v>sparkMax*.45?'var(--sev-high)':'var(--s4)';
            return <div key={i} className="bc-mini-bar" style={{ height:h, background:bg }}/>;
          })}
        </div>
        <div className="bc-sub" style={{ color:'var(--tx3)', marginTop:2 }}>{dbStats.flows.toLocaleString()} flows · {dbStats.dns} dns</div>
      </div>
    </div>
  );
}

// ── Alert stream (left col) ───────────────────────────────────────────────────
function AlertStream({ alerts, svFilter, setSvFilter, search, setSearch, selectedId, setSelectedId }) {
  const counts = useMemo(() => {
    const c = { all:alerts.length, critical:0, high:0, medium:0, low:0, info:0 };
    alerts.forEach(a => { if (c[a.severity]!==undefined) c[a.severity]++; });
    return c;
  }, [alerts]);
  const filtered = useMemo(() => alerts.filter(a => {
    if (svFilter !== 'all' && a.severity !== svFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      if (!a.sig_msg?.toLowerCase().includes(q) && !a.src_ip?.includes(q) && !a.dst_ip?.includes(q)) return false;
    }
    return true;
  }), [alerts, svFilter, search]);
  const SEV_CHIPS = [
    { key:'all',      label:`All · ${counts.all}`,       cls:'' },
    { key:'critical', label:`Crit · ${counts.critical}`, cls:'sev-c' },
    { key:'high',     label:`High · ${counts.high}`,     cls:'sev-h' },
    { key:'medium',   label:`Med · ${counts.medium}`,    cls:'sev-m' },
    { key:'low',      label:`Low · ${counts.low}`,       cls:'sev-l' },
  ];
  return (
    <div className="stream-col">
      <div className="stream-head">
        <span className="stream-title">Alert stream</span>
        <span className="stream-count">{filtered.length}</span>
      </div>
      <div className="filter-bar">
        {SEV_CHIPS.map(c => (
          <div key={c.key} className={`f-chip ${c.cls}${svFilter===c.key?' active':''}`}
               onClick={() => setSvFilter(c.key)}>{c.label}</div>
        ))}
      </div>
      <div className="stream-search">
        <input className="search-input" placeholder="Search IPs, signatures…"
               value={search} onChange={e => setSearch(e.target.value)} />
      </div>
      <div className="stream-scroll">
        {!filtered.length && (
          <div className="empty-stream">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            No matching alerts
          </div>
        )}
        {filtered.map(a => {
          const m = SEV_META[a.severity] || SEV_META.info;
          const tCls = a.status==='acknowledged'?'ack':a.status==='investigating'?'inv':a.status==='closed'?'clo':'';
          return (
            <div key={a.id} className={`alert-card${selectedId===a.id?' selected':''}${a._new?' new-in':''}`}
                 onClick={() => setSelectedId(a.id)}>
              <div className="ac-row1">
                <div className="ac-sev-dot" style={{ background:m.color }}/>
                <div className="ac-sig">{a.sig_msg}</div>
                <div className="ac-time">{fmtAlertTime(a.ts)}</div>
              </div>
              <div className="ac-row2">
                <div className="ac-proto">{a.proto}</div>
                <div className="ac-net">{a.src_ip}:{a.src_port} → {a.dst_ip}:{a.dst_port}</div>
                {a.status && <div className={`ac-triage ${tCls}`}>{a.status}</div>}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Detail panel ──────────────────────────────────────────────────────────────
function DetailPanel({ alert:a, role, setAlerts }) {
  const [meta,    setMeta]    = useState(null);
  const [newNote, setNewNote] = useState('');
  const [saving,  setSaving]  = useState(false);
  const canTriage = role==='admin' || role==='analyst';

  useEffect(() => {
    if (!a?.id) { setMeta(null); return; }
    fetch(`/alerts/${encodeURIComponent(a.id)}/meta`)
      .then(r => r.json()).then(setMeta)
      .catch(() => setMeta({ status:null, notes:[], activity:[] }));
  }, [a?.id]);

  async function setStatus(status) {
    if (!canTriage) return;
    const next = meta?.status === status ? null : status;
    await fetch(`/alerts/${encodeURIComponent(a.id)}/status`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ status:next }),
    });
    a.status = next;
    setAlerts(prev => prev.map(x => x.id===a.id ? {...x, status:next} : x));
    const r = await fetch(`/alerts/${encodeURIComponent(a.id)}/meta`);
    setMeta(await r.json());
  }

  async function addNote() {
    if (!newNote.trim() || !canTriage) return;
    setSaving(true);
    const r = await fetch(`/alerts/${encodeURIComponent(a.id)}/notes`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ note:newNote.trim() }),
    });
    if (r.ok) {
      const n = await r.json();
      setMeta(prev => ({ ...prev, notes:[...(prev?.notes||[]),n] }));
      setNewNote('');
    }
    setSaving(false);
  }

  if (!a) return (
    <div className="detail-col">
      <div className="detail-empty">
        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1">
          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
          <polyline points="14 2 14 8 20 8"/>
        </svg>
        Select an alert to inspect
      </div>
    </div>
  );

  const m = SEV_META[a.severity] || SEV_META.info;
  const PORT_SERVICE = { 22:'SSH',80:'HTTP',443:'HTTPS',3306:'MySQL',5432:'PostgreSQL',
                         1433:'MSSQL',1521:'Oracle SQL',3389:'RDP',5900:'VNC',8080:'HTTP-Alt' };
  const dstService = PORT_SERVICE[a.dst_port] || '';

  return (
    <div className="detail-col">
      <div className="detail-hero">
        <div className="hero-sev-badge" style={{ background:m.bg, color:m.color, border:`1px solid ${m.color}40` }}>
          <div style={{ width:6,height:6,borderRadius:'50%',background:m.color }}/>
          {m.label} severity
        </div>
        <div className="hero-sig">{a.sig_msg}</div>
        <div className="hero-meta">SID {a.sig_id} · {a.category} · {fmtDetailTime(a.ts)}</div>
      </div>
      <div className="conn-viz">
        <div className="cv-label">Connection</div>
        <div className="cv-track">
          <div className="cv-node">
            <div className="cv-ip">{a.src_ip}</div>
            <div className="cv-port">:{a.src_port}</div>
            <div className="cv-role">Source</div>
          </div>
          <div className="cv-mid">
            <div className="cv-proto-tag">{a.proto}</div>
            <div className="cv-arrow-line"><div className="cv-dash"/><div className="cv-arrowhead"/></div>
          </div>
          <div className="cv-node" style={{ textAlign:'right' }}>
            <div className="cv-ip">{a.dst_ip}</div>
            <div className="cv-port">:{a.dst_port}</div>
            <div className="cv-role">{dstService || 'Destination'}</div>
          </div>
        </div>
      </div>
      <div className="detail-scroll">
        {canTriage && (
          <div className="d-section">
            <div className="d-sec-title">Triage</div>
            <div className="triage-grid">
              {['acknowledged','investigating','closed'].map(s => {
                const active = meta?.status === s;
                return (
                  <button key={s} className={`t-btn${active?' '+TRIAGE_META[s].cls:''}`}
                          onClick={() => setStatus(s)}>{TRIAGE_META[s].label}</button>
                );
              })}
            </div>
          </div>
        )}
        <div className="d-section">
          <div className="d-sec-title">Details</div>
          <div className="d-kv-grid">
            <div className="d-kv"><span className="d-k">Interface</span><span className="d-v" title={a.iface||'—'}>{a.iface||'—'}</span></div>
            <div className="d-kv"><span className="d-k">Flow ID</span><span className="d-v" title={String(a.flow_id||'—')}>{a.flow_id||'—'}</span></div>
            <div className="d-kv d-kv-wrap"><span className="d-k">Category</span><span className="d-v d-v-wrap" title={a.category}>{a.category}</span></div>
            <div className="d-kv"><span className="d-k">Severity</span>
              <span className="d-v sev" style={{ color:m.color }}>{m.label.toUpperCase()}</span></div>
          </div>
        </div>
        <div className="d-section">
          <div className="d-sec-title">Activity log</div>
          {!meta && <div className="id-empty">Loading…</div>}
          {meta && (!meta.activity?.length) && <div className="id-empty">No activity yet</div>}
          <div className="act-log">
            {meta?.activity?.length > 0 && [...meta.activity].reverse().map((ev,i) => (
              <div key={i} className="act-entry">
                <div className={`act-dot${i===0?' latest':''}`}/>
                <div>
                  <div className="act-action">{ev.action}</div>
                  <div className="act-meta">{ev.username} · {fmtDetailTime(new Date(ev.created_at*1000).toISOString())}</div>
                </div>
              </div>
            ))}
            <div className="act-entry">
              <div className="act-dot"/>
              <div>
                <div className="act-action">Alert received</div>
                <div className="act-meta">System · {fmtDetailTime(a.ts)}</div>
              </div>
            </div>
          </div>
        </div>
        {canTriage && (
          <div className="d-section">
            <div className="d-sec-title">Notes ({meta?.notes?.length||0})</div>
            {meta?.notes?.length > 0 && (
              <div className="note-list">
                {meta.notes.map((n,i) => (
                  <div key={i} className="note-item">
                    <div className="note-item-meta">{n.username} · {fmtDetailTime(new Date(n.created_at*1000).toISOString())}</div>
                    <div className="note-item-text">{n.note}</div>
                  </div>
                ))}
              </div>
            )}
            <div className="note-form">
              <textarea className="note-ta" rows={2} placeholder="Add analyst note… (Ctrl+Enter)"
                value={newNote} onChange={e => setNewNote(e.target.value)}
                onKeyDown={e => { if(e.key==='Enter'&&e.ctrlKey) addNote(); }}/>
              <button className="note-submit" onClick={addNote} disabled={saving||!newNote.trim()}>
                {saving ? 'Saving…' : 'Save note'}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ── IP context panel ──────────────────────────────────────────────────────────
function IpContextPanel({ alert:a, alerts }) {
  if (!a) return (
    <div className="context-col">
      <div className="ctx-head">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--tx3)" strokeWidth="1.5"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
        <span className="ctx-title">IP context</span>
      </div>
      <div className="ctx-empty">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
        Select an alert to see IP intelligence
      </div>
    </div>
  );
  const ip = a.src_ip;
  const ipAlerts = useMemo(() => alerts.filter(x => x.src_ip === ip), [alerts, ip]);
  const sevBreak = useMemo(() => {
    const c = { critical:0, high:0, medium:0, low:0, info:0 };
    ipAlerts.forEach(x => { if(c[x.severity]!==undefined) c[x.severity]++; });
    return c;
  }, [ipAlerts]);
  const topSigs = useMemo(() => {
    const freq = {};
    ipAlerts.forEach(x => { freq[x.sig_msg] = (freq[x.sig_msg]||0)+1; });
    return Object.entries(freq).sort((a,b)=>b[1]-a[1]).slice(0,5);
  }, [ipAlerts]);
  const maxSigCount = topSigs[0]?.[1] || 1;
  const histogram = useMemo(() => {
    const buckets = Array(24).fill(0);
    const now = Date.now();
    ipAlerts.forEach(x => {
      const d = new Date(x.ts); if (isNaN(d)) return;
      const hoursAgo = (now - d.getTime()) / 3600000;
      if (hoursAgo < 24) { buckets[23 - Math.floor(hoursAgo)]++; }
    });
    return buckets;
  }, [ipAlerts]);
  const histMax = Math.max(...histogram, 1);
  const recentFromIp = useMemo(() => ipAlerts.filter(x => x.id !== a.id).slice(0,6), [ipAlerts, a.id]);
  return (
    <div className="context-col">
      <div className="ctx-head">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--tx3)" strokeWidth="1.5"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
        <span className="ctx-title">IP intelligence</span>
      </div>
      <div className="ctx-scroll">
        <div className="ip-card">
          <div className="ip-addr">{ip}</div>
          <div className="ip-sub">Source IP · internal network</div>
          <div className="ip-stats-grid">
            <div className="ip-stat"><div className="ip-stat-val" style={{ color:'var(--sev-high)' }}>{ipAlerts.length}</div><div className="ip-stat-label">TOTAL ALERTS</div></div>
            <div className="ip-stat"><div className="ip-stat-val" style={{ color:'var(--sev-critical)' }}>{sevBreak.critical+sevBreak.high}</div><div className="ip-stat-label">HIGH+ SEVERITY</div></div>
            <div className="ip-stat"><div className="ip-stat-val" style={{ color:'var(--accent)' }}>{topSigs.length}</div><div className="ip-stat-label">UNIQUE SIGS</div></div>
            <div className="ip-stat"><div className="ip-stat-val" style={{ color:'var(--tx2)' }}>{Object.values(sevBreak).reduce((a,b)=>a+b,0)>0?Math.round(((sevBreak.critical+sevBreak.high)/ipAlerts.length)*100)+'%':'—'}</div><div className="ip-stat-label">HIGH RATE</div></div>
          </div>
        </div>
        <div className="ip-histogram">
          <div className="ctx-sec-label">Activity — last 24 hours</div>
          <div className="hist-bars">
            {histogram.map((v,i) => {
              const h = Math.max(2, Math.round((v/histMax)*34));
              const bg = v>histMax*.75?'var(--sev-critical)':v>histMax*.4?'var(--sev-high)':v>0?'var(--accent)':'var(--s3)';
              return <div key={i} className="hist-bar" style={{ height:h, background:bg }}/>;
            })}
          </div>
          <div className="hist-axis">
            <span className="hist-tick">24h ago</span>
            <span className="hist-tick">12h ago</span>
            <span className="hist-tick">now</span>
          </div>
        </div>
        {topSigs.length > 0 && (
          <div className="top-sigs">
            <div className="ctx-sec-label">Top signatures</div>
            {topSigs.map(([sig, count], i) => (
              <div key={i} className="sig-row">
                <div className="sig-name" title={sig}>{sig}</div>
                <div className="sig-track"><div className="sig-fill" style={{ width:`${Math.round(count/maxSigCount*100)}%` }}/></div>
                <div className="sig-count">{count}</div>
              </div>
            ))}
          </div>
        )}
        {recentFromIp.length > 0 && (
          <div className="ctx-recent">
            <div className="ctx-sec-label">Other alerts from this IP</div>
            {recentFromIp.map(x => {
              const m = SEV_META[x.severity]||SEV_META.info;
              return (
                <div key={x.id} className="ctx-recent-item">
                  <div className="ctx-recent-sev" style={{ background:m.color }}/>
                  <div className="ctx-recent-sig">{x.sig_msg}</div>
                  <div className="ctx-recent-time">{fmtAlertTime(x.ts)}</div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Chronicle helpers ─────────────────────────────────────────────────────────
function localDateKey(d) {
  return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
}
function heatColor(count) {
  if (count === 0) return 'rgba(255,255,255,0.05)';
  const alpha = Math.min(0.85, 0.15 + count / 20);
  const a = alpha.toFixed(2);
  if (count > 15) return `rgba(248,113,113,${a})`;
  if (count > 8)  return `rgba(251,146,60,${a})`;
  if (count > 3)  return `rgba(251,191,36,${a})`;
  return `rgba(74,222,128,${a})`;
}
function fmtGroupTime(d) {
  return d.toLocaleTimeString([], { hour:'numeric', minute:'2-digit', hour12:true })
    + ' · ' + d.toLocaleDateString([], { month:'short', day:'numeric' });
}

// ── HeatmapStrip ──────────────────────────────────────────────────────────────
function HeatmapStrip({ alerts, onDayClick }) {
  const buckets = useMemo(() => {
    const map = {};
    alerts.forEach(a => {
      const d = new Date(a.ts); if (isNaN(d)) return;
      const key = localDateKey(d);
      map[key] = (map[key] || 0) + 1;
    });
    const days = [];
    const today = new Date();
    for (let i = 89; i >= 0; i--) {
      const d = new Date(today); d.setDate(d.getDate() - i);
      const key = localDateKey(d);
      days.push({ date:d, key, count:map[key]||0, daysAgo:i });
    }
    return days;
  }, [alerts]);
  return (
    <div className="cal-strip">
      <div className="cal-label">90-day alert heatmap — click any day to jump</div>
      <div className="cal-grid">
        {buckets.map(({ date, key, count, daysAgo }) => {
          const h = Math.max(8, Math.min(28, 8 + count));
          const showLabel = daysAgo % 14 === 0 || daysAgo === 89;
          return (
            <div key={key} className="cal-col" onClick={() => onDayClick(date)}
                 title={`${date.toDateString()}: ${count} alert${count!==1?'s':''}`}>
              <div className="cal-cell" style={{ height:h, background:heatColor(count) }} />
              {showLabel && <div className="cal-day-label">{date.toLocaleDateString([],{month:'short',day:'numeric'})}</div>}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── AlertRow ──────────────────────────────────────────────────────────────────
function AlertRow({ alert:a, selected, onClick }) {
  const m = SEV_META[a.severity] || SEV_META.info;
  const triageLabel = a.status==='acknowledged'?"Ack'd":a.status==='investigating'?'Invest.':a.status==='closed'?'Closed':null;
  const tCls = a.status==='acknowledged'?'ack':a.status==='investigating'?'inv':a.status==='closed'?'clo':'';
  return (
    <div className={`alert-row${selected?' selected':''}`} onClick={onClick}>
      <div className="ar-sev-track" style={{ background:m.color }} />
      <div className="ar-body">
        <div className="ar-proto">{a.proto}</div>
        <div className="ar-sig">{a.sig_msg}</div>
        <div className="ar-net">{a.src_ip}:{a.src_port} → {a.dst_ip}:{a.dst_port}</div>
        {triageLabel && <div className={`ar-triage ${tCls}`}>{triageLabel}</div>}
      </div>
    </div>
  );
}

// ── TimelineCol ───────────────────────────────────────────────────────────────
function TimelineCol({ alerts, selectedId, setSelectedId, scrollToDate }) {
  const lanesRef = useRef(null);
  const groups = useMemo(() => {
    const sorted = [...alerts].sort((a,b) => new Date(b.ts) - new Date(a.ts));
    const buckets = new Map();
    sorted.forEach(alert => {
      const d = new Date(alert.ts); if (isNaN(d)) return;
      const key = `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}-${d.getHours()}`;
      if (!buckets.has(key)) buckets.set(key, { time:d, dateKey:localDateKey(d), alerts:[] });
      buckets.get(key).alerts.push(alert);
    });
    return [...buckets.values()];
  }, [alerts]);
  useEffect(() => {
    if (!scrollToDate || !lanesRef.current) return;
    const el = lanesRef.current.querySelector(`[data-date="${localDateKey(scrollToDate)}"]`);
    if (el) el.scrollIntoView({ behavior:'smooth', block:'start' });
  }, [scrollToDate]);
  return (
    <div className="timeline-col">
      <div className="tl-head">
        <span className="tl-title">Event timeline</span>
        <span className="tl-count">{alerts.length} events</span>
        <div className="sev-legend">
          {['critical','high','medium','low'].map(s => (
            <div key={s} className="sev-leg-item">
              <div className="sev-leg-dot" style={{ background:SEV_META[s].color }} />{SEV_META[s].label}
            </div>
          ))}
        </div>
      </div>
      <div className="tl-lanes" ref={lanesRef}>
        {!groups.length && <div className="empty-state">No alerts yet</div>}
        {groups.map((group,gi) => (
          <div key={gi} className="lane-group" data-date={group.dateKey}>
            <div className="lane-time-header">
              <div className="lth-time">{fmtGroupTime(group.time)}</div>
              <div className="lth-line" />
            </div>
            {group.alerts.map(alert => (
              <AlertRow key={alert.id} alert={alert}
                selected={selectedId===alert.id} onClick={() => setSelectedId(alert.id)} />
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}

// ── ChronicleView ─────────────────────────────────────────────────────────────
function ChronicleView({ alerts, role, setAlerts }) {
  const [selectedId,   setSelectedId]   = useState(null);
  const [scrollToDate, setScrollToDate] = useState(null);
  useEffect(() => { if (alerts.length && !selectedId) setSelectedId(alerts[0].id); }, [alerts.length]);
  const selectedAlert = alerts.find(a => a.id === selectedId) || null;
  return (
    <div className="chronicle-shell">
      <HeatmapStrip alerts={alerts} onDayClick={date => setScrollToDate(date)} />
      <div className="chronicle-main">
        <TimelineCol alerts={alerts} selectedId={selectedId}
          setSelectedId={setSelectedId} scrollToDate={scrollToDate} />
        <DetailPanel alert={selectedAlert} role={role} setAlerts={setAlerts} />
      </div>
    </div>
  );
}

// ── Flows view ────────────────────────────────────────────────────────────────
function FlowsView() {
  const [flows, setFlows] = useState([]);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    fetch('/flows?limit=200').then(r=>r.json()).then(d=>{setFlows(d.flows||[]);setLoading(false);}).catch(()=>setLoading(false));
    const es = new EventSource('/events');
    es.addEventListener('flow', e => { try { setFlows(prev => [JSON.parse(e.data), ...prev].slice(0,500)); } catch {} });
    return () => es.close();
  }, []);
  if (loading) return <div className="empty-state">Loading flows…</div>;
  if (!flows.length) return <div className="empty-state">No flow events</div>;
  return (
    <div className="table-wrap">
      <table className="data-table">
        <thead><tr><th>Time</th><th>Source</th><th>Destination</th><th>Proto</th><th>App</th><th>↑ Bytes</th><th>↓ Bytes</th><th>State</th></tr></thead>
        <tbody>{flows.map((f,i) => (
          <tr key={i}>
            <td>{fmtAlertTime(f.ts)}</td><td className="td-hi">{f.src_ip}:{f.src_port}</td>
            <td>{f.dst_ip}:{f.dst_port}</td><td>{f.proto?.toUpperCase()}</td>
            <td>{f.app_proto||'—'}</td><td>{(f.bytes_toserver||0).toLocaleString()}</td>
            <td>{(f.bytes_toclient||0).toLocaleString()}</td>
            <td className={f.state==='closed'?'':'td-ok'}>{f.state||'—'}</td>
          </tr>
        ))}</tbody>
      </table>
    </div>
  );
}


// ── DNS detail modal ──────────────────────────────────────────────────────────
function DNSDetailModal({ record, onClose }) {
  return (
    <div className="confirm-backdrop" onClick={e => e.target===e.currentTarget&&onClose()}>
      <div className="confirm-box" style={{ maxWidth:520, width:'92vw' }}>
        <div className="confirm-icon" style={{ background:'var(--sev-info-bg)' }}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
               stroke="var(--sev-info)" strokeWidth="2" strokeLinecap="round">
            <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/>
            <line x1="12" y1="16" x2="12.01" y2="16"/>
          </svg>
        </div>
        <div className="confirm-title" style={{ marginBottom:4 }}>DNS Record Detail</div>
        <div className="confirm-body" style={{ marginBottom:14 }}>
          <span style={{ fontSize:13 }}>{record.rrname||'—'}</span>
        </div>
        <pre style={{
          background:'var(--s2)', border:'1px solid var(--ln)',
          borderRadius:'var(--r-md)', padding:'12px 14px',
          fontSize:11, fontFamily:'var(--mono)', color:'var(--tx1)',
          textAlign:'left', overflowX:'auto', maxHeight:320,
          overflowY:'auto', whiteSpace:'pre-wrap', wordBreak:'break-all', margin:0,
        }}>
          {JSON.stringify(record, null, 2)}
        </pre>
        <div className="confirm-footer" style={{ marginTop:16 }}>
          <button className="btn-modal confirm" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}

// ── DNS view ──────────────────────────────────────────────────────────────────
function DNSView() {
  const [records,  setRecords]  = useState([]);
  const [loading,  setLoading]  = useState(true);
  const [selected, setSelected] = useState(null);
  useEffect(() => {
    fetch('/dns?limit=200').then(r=>r.json()).then(d=>{setRecords(d.dns||[]);setLoading(false);}).catch(()=>setLoading(false));
    const es = new EventSource('/events');
    es.addEventListener('dns', e => { try { setRecords(prev => [JSON.parse(e.data), ...prev].slice(0,500)); } catch {} });
    return () => es.close();
  }, []);
  if (loading) return <div className="empty-state">Loading DNS records…</div>;
  if (!records.length) return <div className="empty-state">No DNS events</div>;
  return (
    <>
      <div className="table-wrap">
        <table className="data-table">
          <thead><tr><th>Time</th><th>Client</th><th>Query</th><th>Type</th><th>Dir</th><th>RCode</th><th>TTL</th></tr></thead>
          <tbody>{records.map((d,i) => (
            <tr key={i} onClick={() => setSelected(d)} style={{ cursor:'pointer' }} className="row-hover">
              <td>{fmtAlertTime(d.ts)}</td><td className="td-hi">{d.src_ip}</td>
              <td className="td-accent">{d.rrname||'—'}</td><td>{d.rrtype||'—'}</td>
              <td>{d.dns_type||'—'}</td>
              <td className={d.rcode==='NOERROR'?'td-ok':d.rcode?'td-warn':''}>{d.rcode||'—'}</td>
              <td>{d.ttl??'—'}</td>
            </tr>
          ))}</tbody>
        </table>
      </div>
      {selected && <DNSDetailModal record={selected} onClose={() => setSelected(null)} />}
    </>
  );
}

// ── Donut chart ───────────────────────────────────────────────────────────────
function DonutChart({ data }) {
  const COLORS = ['var(--accent)','var(--sev-high)','var(--sev-medium)','var(--sev-low)','var(--sev-critical)','var(--sev-info)','#a78bfa','#f472b6'];
  const total = data.reduce((s,d)=>s+d.count,0)||1;
  const R=70,cx=90,cy=90,sw=22,circ=2*Math.PI*R;
  let offset=0;
  const slices=data.map((d,i)=>{const dash=(d.count/total)*circ;const sl={offset,dash,gap:circ-dash,color:COLORS[i%COLORS.length],label:d.category,count:d.count};offset+=dash;return sl;});
  const [hov,setHov]=useState(null);
  return (
    <div style={{display:'flex',gap:20,alignItems:'center',flexWrap:'wrap'}}>
      <svg width="180" height="180" viewBox="0 0 180 180" style={{flexShrink:0}}>
        <circle cx={cx} cy={cy} r={R} fill="none" stroke="var(--s3)" strokeWidth={sw}/>
        {slices.map((sl,i)=>(
          <circle key={i} cx={cx} cy={cy} r={R} fill="none" stroke={sl.color} strokeWidth={hov===i?sw+4:sw}
                  strokeDasharray={`${sl.dash} ${sl.gap}`} strokeDashoffset={circ/4-sl.offset}
                  style={{cursor:'pointer',transition:'stroke-width .15s',transform:'rotate(-90deg)',transformOrigin:`${cx}px ${cy}px`}}
                  onMouseEnter={()=>setHov(i)} onMouseLeave={()=>setHov(null)}/>
        ))}
        <text x={cx} y={cy-6} textAnchor="middle" fill="var(--tx1)" fontSize="20" fontWeight="700" fontFamily="var(--mono)">{total}</text>
        <text x={cx} y={cy+11} textAnchor="middle" fill="var(--tx3)" fontSize="9" letterSpacing=".08em">TOTAL</text>
      </svg>
      <div style={{display:'flex',flexDirection:'column',gap:7,flex:1,minWidth:140}}>
        {slices.map((sl,i)=>(
          <div key={i} style={{display:'flex',alignItems:'center',gap:7,opacity:hov!==null&&hov!==i?0.35:1,transition:'opacity .15s'}}
               onMouseEnter={()=>setHov(i)} onMouseLeave={()=>setHov(null)}>
            <div style={{width:8,height:8,borderRadius:2,background:sl.color,flexShrink:0}}/>
            <span style={{fontSize:10,color:'var(--tx2)',flex:1,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{sl.label||'—'}</span>
            <span style={{fontSize:10,color:'var(--tx1)',fontFamily:'var(--mono)',flexShrink:0}}>{sl.count}</span>
            <span style={{fontSize:9,color:'var(--tx3)',width:32,textAlign:'right',fontFamily:'var(--mono)',flexShrink:0}}>{Math.round(sl.count/total*100)}%</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Charts view ───────────────────────────────────────────────────────────────
function ChartsView() {
  const [data,setData]=useState(null);
  const [loading,setLoading]=useState(true);
  const [hrs,setHrs]=useState(24);
  function load(h){setLoading(true);fetch(`/charts?trend=${h}`).then(r=>r.json()).then(d=>{setData(d);setLoading(false);}).catch(()=>setLoading(false));}
  useEffect(()=>{load(hrs);},[hrs]);
  if(loading)return <div className="empty-state">Loading charts…</div>;
  if(!data)return <div className="empty-state">No chart data</div>;
  const trend=data.trend||[],sevs=data.by_severity||[],talkers=data.top_talkers||[],cats=data.by_category||[];
  const mxT=Math.max(...trend.map(t=>t.count),1),mxS=Math.max(...sevs.map(x=>x.count),1),mxTk=Math.max(...talkers.map(x=>x.count),1);
  const labelEvery=Math.max(1,Math.ceil(trend.length/8));
  const IP_COLORS=['var(--sev-info)','var(--sev-medium)','var(--accent)','var(--sev-high)','var(--sev-critical)','var(--sev-low)'];
  return (
    <div className="charts-layout">
      <div className="charts-controls">
        <div style={{display:'flex',gap:2,marginLeft:'auto'}}>
          {CHART_WINDOWS.map(w=><button key={w.hrs} className={`tab-btn${hrs===w.hrs?' active':''}`} onClick={()=>setHrs(w.hrs)}>{w.label}</button>)}
        </div>
      </div>
      <div className="charts-grid">
        <div className="chart-card wide">
          <div className="chart-card-title">Alert trend</div>
          <div style={{display:'flex',alignItems:'flex-end',gap:2,height:130,paddingBottom:22,position:'relative'}}>
            {[.25,.5,.75,1].map(p=><div key={p} style={{position:'absolute',left:0,right:0,bottom:22+p*108,borderTop:'1px dashed var(--ln)',pointerEvents:'none'}}/>)}
            {trend.map((t,i)=>{const h=Math.max(2,Math.round(t.count/mxT*108));const col=t.count>mxT*.75?'var(--sev-critical)':t.count>mxT*.45?'var(--sev-high)':'var(--accent)';return(
              <div key={i} title={`${t.ts}: ${t.count}`} style={{flex:1,display:'flex',flexDirection:'column',alignItems:'center',justifyContent:'flex-end',position:'relative'}}>
                <div style={{width:'100%',height:h,background:col,opacity:.85,borderRadius:'2px 2px 0 0',transition:'height .2s'}}/>
                {i%labelEvery===0&&<div style={{position:'absolute',bottom:-18,fontSize:9,color:'var(--tx3)',whiteSpace:'nowrap',transform:'translateX(-50%)',left:'50%'}}>{t.ts}</div>}
              </div>
            );})}
          </div>
          <div style={{display:'flex',justifyContent:'space-between',marginTop:4}}>
            <span style={{fontSize:9,color:'var(--tx3)'}}>0</span>
            <span style={{fontSize:9,color:'var(--tx3)'}}>peak: {mxT}</span>
          </div>
        </div>
        <div className="chart-card">
          <div className="chart-card-title">By severity</div>
          <div className="bar-list">{sevs.map(r=>{const m=SEV_META[r.severity]||SEV_META.info;return(<div key={r.severity} className="bar-row"><span className="bar-label" style={{color:m.color}}>{m.label}</span><div className="bar-track" style={{background:m.bg}}><div className="bar-fill" style={{width:`${Math.round(r.count/mxS*100)}%`,background:m.color}}/></div><span className="bar-val" style={{color:m.color}}>{r.count}</span></div>);})}</div>
        </div>
        <div className="chart-card">
          <div className="chart-card-title">Top source IPs</div>
          <div className="bar-list">{talkers.map((r,i)=>{const c=IP_COLORS[i%IP_COLORS.length];return(<div key={r.ip} className="bar-row"><span className="bar-label" style={{color:c}}>{r.ip}</span><div className="bar-track"><div className="bar-fill" style={{width:`${Math.round(r.count/mxTk*100)}%`,background:c}}/></div><span className="bar-val" style={{color:c}}>{r.count}</span></div>);})}</div>
        </div>
        <div className="chart-card wide">
          <div className="chart-card-title">By category</div>
          {cats.length?<DonutChart data={cats}/>:<div className="empty-state" style={{padding:'20px 0'}}>No category data</div>}
        </div>
      </div>
    </div>
  );
}

// ── Webhook modal ─────────────────────────────────────────────────────────────
function WebhookModal({ initial, onSave, onClose }) {
  const editing=Boolean(initial?.id);
  const [name,setName]=useState(initial?.name||'');
  const [type,setType]=useState(initial?.type||'generic');
  const [url,setUrl]=useState(initial?.url||'');
  const [sevs,setSevs]=useState(initial?.severities||ALL_SEVS);
  function toggleSev(s){setSevs(p=>p.includes(s)?p.filter(x=>x!==s):[...p,s]);}
  async function submit(){
    if(!name.trim()||!url.trim())return;
    const body={name:name.trim(),type,url:url.trim(),severities:sevs,enabled:true};
    const res=await fetch(editing?`/webhooks/${initial.id}`:'/webhooks',{method:editing?'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    if(res.ok){onSave();onClose();}
  }
  return (
    <div className="modal-backdrop" onClick={e=>e.target===e.currentTarget&&onClose()}>
      <div className="modal">
        <div className="modal-title">{editing?'Edit webhook':'Add webhook'}</div>
        <div className="modal-sub">Push alert notifications to Slack, Discord, or any HTTP endpoint.</div>
        <div className="form-row">
          <div className="form-group" style={{flex:1}}><label className="form-label">Name</label><input className="form-input" value={name} onChange={e=>setName(e.target.value)} placeholder="My Webhook"/></div>
          <div className="form-group" style={{maxWidth:110}}><label className="form-label">Type</label><select className="form-select" value={type} onChange={e=>setType(e.target.value)}>{WEBHOOK_TYPES.map(t=><option key={t} value={t}>{t.charAt(0).toUpperCase()+t.slice(1)}</option>)}</select></div>
        </div>
        <div className="form-group"><label className="form-label">Endpoint URL</label><input className="form-input" value={url} onChange={e=>setUrl(e.target.value)} placeholder="https://hooks.slack.com/…"/></div>
        <div className="form-group">
          <label className="form-label">Trigger on severity</label>
          <div className="sev-checkboxes">{ALL_SEVS.map(s=>{const m=SEV_META[s];const on=sevs.includes(s);return(<label key={s} className={`sev-check${on?' checked':''}`} style={{color:m.color,borderColor:on?m.color:'var(--ln)'}}><input type="checkbox" checked={on} onChange={()=>toggleSev(s)}/>{m.label}</label>);})}</div>
        </div>
        <div className="modal-footer">
          <button className="btn-modal" onClick={onClose}>Cancel</button>
          <button className="btn-modal confirm" onClick={submit}>{editing?'Save changes':'Add webhook'}</button>
        </div>
      </div>
    </div>
  );
}

// ── User modal ────────────────────────────────────────────────────────────────
function UserModal({ initial, onSave, onClose }) {
  const editing=Boolean(initial?.id);
  const [username,setUsername]=useState(initial?.username||'');
  const [password,setPassword]=useState('');
  const [role,setRole]=useState(initial?.role||'analyst');
  async function submit(){
    if(!editing&&(!username.trim()||!password))return;
    const body=editing?{role}:{username:username.trim(),password,role};
    const res=await fetch(editing?`/users/${initial.id}`:'/users',{method:editing?'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    if(res.ok){onSave();onClose();}
  }
  return (
    <div className="modal-backdrop" onClick={e=>e.target===e.currentTarget&&onClose()}>
      <div className="modal">
        <div className="modal-title">{editing?'Edit user':'Add user'}</div>
        <div className="modal-sub">Role controls what the user can see and do.</div>
        {!editing&&(<><div className="form-group"><label className="form-label">Username</label><input className="form-input" value={username} onChange={e=>setUsername(e.target.value)} placeholder="jsmith"/></div><div className="form-group"><label className="form-label">Password</label><input className="form-input" type="password" value={password} onChange={e=>setPassword(e.target.value)} placeholder="••••••••"/></div></>)}
        <div className="form-group"><label className="form-label">Role</label><select className="form-select" value={role} onChange={e=>setRole(e.target.value)}><option value="admin">Admin — full access</option><option value="analyst">Analyst — read + triage, no delete</option><option value="viewer">Viewer — alert stream only</option></select></div>
        <div className="modal-footer">
          <button className="btn-modal" onClick={onClose}>Cancel</button>
          <button className="btn-modal confirm" onClick={submit}>{editing?'Save':'Create user'}</button>
        </div>
      </div>
    </div>
  );
}

// ── Settings view ─────────────────────────────────────────────────────────────
function SettingsView({ theme, setTheme, role, username, onLogout }) {
  const [users,setUsers]=useState([]);
  const [health,setHealth]=useState(null);
  const [modal,setModal]=useState(null);
  const [whModal,setWhModal]=useState(null);
  const [webhooks,setWebhooks]=useState([]);
  const [testMsg,setTestMsg]=useState({});
  const [confirm,setConfirm]=useState(null);
  const isAdmin=role==='admin';
  async function loadUsers(){const r=await fetch('/users');const d=await r.json();setUsers(d.users||[]);}
  async function loadHealth(){const r=await fetch('/health');const d=await r.json();setHealth(d);}
  async function loadWebhooks(){const r=await fetch('/webhooks');const d=await r.json();setWebhooks(d.webhooks||[]);}
  useEffect(()=>{loadUsers();loadHealth();if(isAdmin)loadWebhooks();},[]);
  useEffect(()=>{const id=setInterval(loadHealth,10000);return()=>clearInterval(id);},[]);
  const [clearMsg,setClearMsg]=useState({});
  const DB_KEY={'/alerts':'alerts','/flows':'flows','/dns':'dns','/http':'http'};
  function confirmDeleteUser(u){setConfirm({title:'Delete user',body:`Delete <strong>${u.username}</strong>? Cannot be undone.`,confirmLabel:'Delete',variant:'danger',onConfirm:async()=>{await fetch(`/users/${u.id}`,{method:'DELETE'});loadUsers();}});}
  function confirmClearData(ep,label,count){setConfirm({title:`Clear all ${label}`,body:`Permanently delete <strong>${count} ${label} records</strong>. Cannot be undone.`,confirmLabel:`Clear ${label}`,variant:'warning',onConfirm:async()=>{
    const res=await fetch(ep,{method:'DELETE'});
    const key=DB_KEY[ep];
    if(res.ok){
      const data=await res.json();
      if(key){
        setHealth(prev=>prev?{...prev,db:{...prev.db,[key]:{total:0,recent:0}}}:prev);
        setClearMsg(prev=>({...prev,[key]:`Cleared ${(data.deleted||0).toLocaleString()} records`}));
        setTimeout(()=>setClearMsg(prev=>{const n={...prev};delete n[key];return n;}),8000);
      }
    }
  }});}
  async function toggleWebhook(wh){await fetch(`/webhooks/${wh.id}`,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:!wh.enabled})});loadWebhooks();}
  function confirmDeleteWh(wh){setConfirm({title:'Delete webhook',body:`Delete <strong>${wh.name}</strong>?`,confirmLabel:'Delete',variant:'danger',onConfirm:async()=>{await fetch(`/webhooks/${wh.id}`,{method:'DELETE'});loadWebhooks();}});}
  async function testWebhook(id){
    setTestMsg(p=>({...p,[id]:'Sending…'}));
    const r=await fetch(`/webhooks/${id}/test`,{method:'POST'});
    const d=await r.json();
    setTestMsg(p=>({...p,[id]:d.ok?'✓ Delivered':'✗ '+(d.error||'Failed')}));
    setTimeout(()=>setTestMsg(p=>{const n={...p};delete n[id];return n;}),3000);
  }
  const initials=n=>n.slice(0,2).toUpperCase();
  return (
    <div className="settings-layout">
      {isAdmin&&(<div className="settings-card">
        <div className="settings-card-header"><span className="settings-card-title">Users</span><button className="btn primary sm" onClick={()=>setModal({})}>Add user</button></div>
        <div className="settings-card-body">
          {users.map(u=>(
            <div key={u.id} className={`user-row${!u.enabled?' disabled':''}`}>
              <div className="user-avatar">{initials(u.username)}</div>
              <div className="user-info">
                <div className="user-name">{u.username}{u.username===username&&<span style={{fontSize:9,color:'var(--tx3)',marginLeft:6}}>(you)</span>}</div>
                <div className="user-meta">{u.last_login?`Last login ${new Date(u.last_login*1000).toLocaleDateString()}`:'Never logged in'}</div>
              </div>
              <span className={`role-badge ${u.role}`}>{ROLE_META[u.role]?.label||u.role}</span>
              <button className="btn sm" onClick={()=>setModal(u)}>Edit</button>
              <button className="btn danger sm" onClick={()=>confirmDeleteUser(u)}>Delete</button>
            </div>
          ))}
        </div>
      </div>)}
      {isAdmin&&(<div className="settings-card">
        <div className="settings-card-header"><span className="settings-card-title">Webhooks</span><button className="btn primary sm" onClick={()=>setWhModal({})}>Add webhook</button></div>
        <div className="settings-card-body">
          {!webhooks.length&&<div style={{fontSize:11,color:'var(--tx3)'}}>No webhooks configured.</div>}
          {webhooks.map(wh=>(
            <div key={wh.id} className="wh-row">
              <div className="wh-top"><span className="wh-name">{wh.name}</span><span className="wh-type">{wh.type.toUpperCase()}</span><button className={`wh-toggle${wh.enabled?' on':''}`} onClick={()=>toggleWebhook(wh)}/></div>
              <div className="wh-url">{wh.url}</div>
              <div className="wh-sevs">{ALL_SEVS.map(s=>{const m=SEV_META[s];const on=(wh.severities||[]).includes(s);return(<span key={s} className={`wh-sev-pip${on?' on':''}`} style={{color:m.color,background:m.bg,border:`1px solid ${m.color}40`}}>{m.label}</span>);})}</div>
              <div className="wh-meta"><span>Fired {wh.fire_count||0}×</span>{wh.last_fired&&<span>Last: {new Date(wh.last_fired*1000).toLocaleTimeString()}</span>}</div>
              <div className="wh-actions"><button className="btn sm" onClick={()=>setWhModal(wh)}>Edit</button><button className="btn sm" onClick={()=>testWebhook(wh.id)}>{testMsg[wh.id]||'Test'}</button><button className="btn danger sm" onClick={()=>confirmDeleteWh(wh)}>Delete</button></div>
              {wh.last_error&&<div className="wh-error">Last error: {wh.last_error}</div>}
            </div>
          ))}
        </div>
      </div>)}
      <div className="settings-card">
        <div className="settings-card-header"><span className="settings-card-title">Theme</span></div>
        <div className="settings-card-body">
          <div className="theme-grid">
            {THEMES.map(t=>(
              <div key={t.id} className={`theme-tile${theme===t.id?' active':''}`}
                   onClick={()=>{setTheme(t.id);document.documentElement.setAttribute('data-theme',t.id);localStorage.setItem('heimdall-theme',t.id);}}>
                <div style={{display:'flex',gap:3,flexShrink:0}}>
                  <div style={{width:10,height:10,borderRadius:3,background:t.dot,border:'1px solid rgba(0,0,0,.15)'}}/>
                  <div style={{width:10,height:10,borderRadius:3,background:t.accent}}/>
                </div>
                <span style={{fontSize:11}}>{t.label}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
      {isAdmin&&health&&(<div className="settings-card">
        <div className="settings-card-header"><span className="settings-card-title">Data management</span></div>
        <div className="settings-card-body">
          {[
            { label:'Alerts',      ep:'/alerts', count:health?.db?.alerts?.total??0 },
            { label:'Flows',       ep:'/flows',  count:health?.db?.flows?.total??0  },
            { label:'DNS events',  ep:'/dns',    count:health?.db?.dns?.total??0    },
          ].map(row=>(
            <div key={row.label} className="data-mgmt-row">
              <div><div className="data-mgmt-label">{row.label}</div><div className="data-mgmt-sub">{row.count.toLocaleString()} records</div></div>
              <div style={{display:'flex',flexDirection:'column',alignItems:'flex-end',gap:3}}>
                <button className="btn danger sm" onClick={()=>confirmClearData(row.ep,row.label.toLowerCase(),row.count)}>Clear all</button>
                {clearMsg[DB_KEY[row.ep]]&&<span style={{fontSize:9,color:'var(--success)',fontFamily:'var(--mono)'}}>{clearMsg[DB_KEY[row.ep]]}</span>}
              </div>
            </div>
          ))}
        </div>
      </div>)}
      {health&&(<div className="settings-card">
        <div className="settings-card-header"><span className="settings-card-title">Server health</span></div>
        <div className="settings-card-body">
          <div className="health-grid">
            {[
              {l:'Alerts',  v:health.db?.alerts?.total, s:`${health.db?.alerts?.recent} recent`},
              {l:'Flows',   v:health.db?.flows?.total,  s:`${health.db?.flows?.recent} recent`},
              {l:'DNS',     v:health.db?.dns?.total,    s:`${health.db?.dns?.recent} recent`},
              {l:'HTTP',    v:health.db?.http?.total,   s:`${health.db?.http?.recent} recent`},
              {l:'Clients', v:health.clients,           s:'connected'},
            ].map(r=>(
              <div key={r.l} className="health-stat">
                <div className="health-stat-label">{r.l}</div>
                <div className="health-stat-value">{(r.v||0).toLocaleString()}</div>
                <div className="health-stat-sub">{r.s}</div>
              </div>
            ))}
            <div className="health-stat">
              <div className="health-stat-label">Oldest record</div>
              <div className="health-stat-value" style={{fontSize:12}}>{health.db?.oldest?new Date(health.db.oldest).toLocaleDateString():'—'}</div>
            </div>
          </div>
        </div>
      </div>)}
      <div className="settings-card">
        <div className="settings-card-header"><span className="settings-card-title">Account</span></div>
        <div className="settings-card-body">
          <div style={{display:'flex',alignItems:'center',justifyContent:'space-between'}}>
            <div>
              <div style={{fontSize:13,fontWeight:600,color:'var(--tx1)'}}>{username}</div>
              <div style={{fontSize:10,color:'var(--tx3)',marginTop:3}}>{ROLE_META[role]?.label||role} · Currently signed in</div>
            </div>
            <button className="btn danger sm" onClick={()=>setConfirm({title:'Sign out',body:'Sign out of Heimdall?',confirmLabel:'Sign out',variant:'warning',onConfirm:onLogout})}>Sign out</button>
          </div>
        </div>
      </div>
      {modal!==null&&<UserModal initial={modal.id?modal:null} onSave={loadUsers} onClose={()=>setModal(null)}/>}
      {whModal!==null&&<WebhookModal initial={whModal.id?whModal:null} onSave={loadWebhooks} onClose={()=>setWhModal(null)}/>}
      {confirm!==null&&<ConfirmDialog title={confirm.title} body={confirm.body} confirmLabel={confirm.confirmLabel} variant={confirm.variant} onConfirm={confirm.onConfirm} onClose={()=>setConfirm(null)}/>}
    </div>
  );
}

// ── Root App ──────────────────────────────────────────────────────────────────
function App() {
  const [alerts,     setAlerts]     = useState([]);
  const [view,       setView]       = useState('alerts');
  const [selectedId, setSelectedId] = useState(null);
  const [svFilter,   setSvFilter]   = useState('all');
  const [search,     setSearch]     = useState('');
  const [sparkData,  setSparkData]  = useState(() => Array.from({length:60},()=>Math.floor(Math.random()*3)));
  const [theme,      setTheme]      = useState(() => {
    const s = localStorage.getItem('heimdall-theme');
    if (s) document.documentElement.setAttribute('data-theme', s);
    return s || 'night';
  });
  const [dbStats,   setDbStats]   = useState({ alerts:0, flows:0, dns:0 });
  const [role,      setRole]      = useState('viewer');
  const [username,  setUsername]  = useState('');
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    fetch('/me').then(r=>r.json()).then(d=>{setRole(d.role||'viewer');setUsername(d.username||'');}).catch(()=>{});
    fetch('/alerts?limit=500').then(r=>r.json()).then(d=>{
      const rows=d.alerts||[];
      setAlerts(rows);
      if(rows.length) setSelectedId(rows[0].id);
    }).catch(()=>{});
    fetch('/health').then(r=>r.json()).then(d=>setDbStats({alerts:d.db?.alerts?.total||0,flows:d.db?.flows?.total||0,dns:d.db?.dns?.total||0})).catch(()=>{});
  }, []);

  useEffect(() => {
    let es;
    function connect() {
      es = new EventSource('/events');
      es.addEventListener('alert', e => {
        try {
          const a = JSON.parse(e.data); a._new = true;
          setAlerts(prev => { if(prev.find(x=>x.id===a.id)) return prev; return [a,...prev].slice(0,500); });
          setSparkData(prev => { const n=[...prev.slice(1)]; n.push(prev[prev.length-1]+1); return n; });
          setTimeout(()=>setAlerts(prev=>prev.map(x=>x.id===a.id?{...x,_new:false}:x)),600);
        } catch {}
      });
      es.addEventListener('ping', ()=>{});
      es.onopen  = () => setConnected(true);
      es.onerror = () => { setConnected(false); es.close(); setTimeout(connect,3000); };
    }
    connect();
    return () => es?.close();
  }, []);

  useEffect(() => {
    const id = setInterval(() => {
      setSparkData(prev=>[...prev.slice(1),Math.max(0,prev[prev.length-1]-1+Math.floor(Math.random()*2))]);
    }, 4000);
    return () => clearInterval(id);
  }, []);

  function applyTheme(t) { setTheme(t); document.documentElement.setAttribute('data-theme',t); localStorage.setItem('heimdall-theme',t); }
  async function handleLogout() { try { await fetch('/logout',{method:'POST'}); } catch {} window.location.href='/login'; }

  const selectedAlert = alerts.find(a => a.id === selectedId) || null;
  const NAV_VIEWS  = ['alerts','chronicle','flows','dns','charts','settings'];
  const NAV_LABELS = { alerts:'Alerts', chronicle:'Chronicle', flows:'Flows', dns:'DNS', charts:'Charts', settings:'Settings' };

  return (
    <div className="shell">
      <header className="topbar">
        <div className="logo">
          <div className="logo-orb">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
              <ellipse cx="12" cy="12" rx="9.5" ry="6.5" stroke="white" strokeWidth="1.8"/>
              <circle cx="12" cy="12" r="2.8" fill="white"/>
              <circle cx="12" cy="12" r="1.1" fill="var(--logo-a)"/>
            </svg>
          </div>
          <div>
            <div className="logo-name">Heimdall</div>
            <div className="logo-sub">IDS DASHBOARD</div>
          </div>
        </div>
        <nav className="center-nav">
          {NAV_VIEWS.map(v => (
            <button key={v} className={`nav-pill${view===v?' active':''}`} onClick={()=>setView(v)}>
              {NAV_LABELS[v]}
            </button>
          ))}
        </nav>
        <div className="tb-right">
          <ThemePicker theme={theme} onChange={applyTheme}/>
          <div className={`live-ring${connected?'':' off'}`}>
            <div className="live-dot"/>
            {connected ? 'Live' : 'Reconnecting'}
          </div>
          {username && (
            <div className="user-chip" onClick={handleLogout} title="Click to sign out">
              <div className="user-av">{username.slice(0,2).toUpperCase()}</div>
              {username}
              <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>
                <polyline points="16 17 21 12 16 7"/>
                <line x1="21" y1="12" x2="9" y2="12"/>
              </svg>
            </div>
          )}
        </div>
      </header>

      {view === 'alerts' && <BentoStrip alerts={alerts} dbStats={dbStats} sparkData={sparkData}/>}

      <div className={`workspace${view==='alerts'?' alerts-view':' full-view'}`}>
        {view === 'alerts' && (
          <>
            <AlertStream alerts={alerts} svFilter={svFilter} setSvFilter={setSvFilter}
              search={search} setSearch={setSearch}
              selectedId={selectedId} setSelectedId={setSelectedId}/>
            <DetailPanel alert={selectedAlert} role={role} setAlerts={setAlerts}/>
            <IpContextPanel alert={selectedAlert} alerts={alerts}/>
          </>
        )}
        {view !== 'alerts' && (
          <div className="main-view">
            {view === 'chronicle' && <ChronicleView alerts={alerts} role={role} setAlerts={setAlerts}/>}
            {view === 'flows'     && <><div className="main-head"><span className="main-title">Flow events</span></div><FlowsView/></>}
            {view === 'dns'       && <><div className="main-head"><span className="main-title">DNS queries</span></div><DNSView/></>}
            {view === 'charts'    && <ChartsView/>}
            {view === 'settings'  && <SettingsView theme={theme} setTheme={applyTheme} role={role} username={username} onLogout={handleLogout}/>}
          </div>
        )}
      </div>

      <footer className="statusbar">
        <div className="sb-item"><div className="sb-dot" style={{background:'var(--success)'}}/>Database</div>
        <div className="sb-item">
          <div className="sb-dot" style={{background:connected?'var(--success)':'var(--sev-medium)'}}/>
          {connected ? 'Tail active' : 'Reconnecting…'}
        </div>
        <span className="sb-sep">|</span>
        <div className="sb-item">Retain 90 days</div>
        {username && <div className="sb-item" style={{color:'var(--tx3)'}}>{username} · {role}</div>}
      </footer>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<App/>);

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

function SevBadge({ sev }) {
  const m = SEV_META[sev] || SEV_META.info;
  return <span className="sev-badge" style={{ color:m.color, background:m.bg }}>{m.label}</span>;
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
        <div className="bc-value">{alerts.length.toLocaleString()}<span style={{fontSize:10,color:"var(--tx3)",marginLeft:4}}>/ {(dbStats?.alerts || 0).toLocaleString()}</span></div>
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
              <div key={s} title={`${m.label}: ${counts[s]}`}
                   className="bc-mini-bar"
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
    { key:'all',      label:`All · ${counts.all}`,      cls:'' },
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
          <div key={c.key}
               className={`f-chip ${c.cls}${svFilter===c.key?' active':''}`}
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
            <div key={a.id}
                 className={`alert-card${selectedId===a.id?' selected':''}${a._new?' new-in':''}`}
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

// ── Detail panel (center col) ─────────────────────────────────────────────────
function DetailPanel({ alert:a, role, setAlerts, onExplain }) {
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
  const PORT_SERVICE = { 22:'SSH', 80:'HTTP', 443:'HTTPS', 3306:'MySQL', 5432:'PostgreSQL',
                         1433:'MSSQL', 1521:'Oracle SQL', 3389:'RDP', 5900:'VNC', 8080:'HTTP-Alt' };
  const dstService = PORT_SERVICE[a.dst_port] || '';

  return (
    <div className="detail-col">
      {/* Hero */}
      <div className="detail-hero">
        <div className="hero-sev-badge"
             style={{ background:m.bg, color:m.color, border:`1px solid ${m.color}40` }}>
          <div style={{ width:6,height:6,borderRadius:'50%',background:m.color }}/>
          {m.label} severity
        </div>
        <div className="hero-sig">{a.sig_msg}</div>
        <div className="hero-meta">SID {a.sig_id} · {a.category} · {fmtDetailTime(a.ts)}</div>
      </div>

      {/* Connection visualizer */}
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
            <div className="cv-arrow-line">
              <div className="cv-dash"/>
              <div className="cv-arrowhead"/>
            </div>
          </div>
          <div className="cv-node" style={{ textAlign:'right' }}>
            <div className="cv-ip">{a.dst_ip}</div>
            <div className="cv-port">:{a.dst_port}</div>
            <div className="cv-role">{dstService || 'Destination'}</div>
          </div>
        </div>
      </div>

      <div className="detail-scroll">
        {/* Explain */}
        {onExplain && (
          <button onClick={() => onExplain(a)}
            style={{ display:'flex', alignItems:'center', gap:5, marginTop:8,
                     padding:'5px 13px', border:'1px solid var(--accent)',
                     borderRadius:'var(--radius-sm,4px)', background:'transparent',
                     color:'var(--accent)', fontSize:11, cursor:'pointer',
                     fontFamily:'var(--mono)', letterSpacing:'.04em' }}>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none"
                 stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10"/>
              <line x1="12" y1="8" x2="12" y2="12"/>
              <line x1="12" y1="16" x2="12.01" y2="16"/>
            </svg>
            Explain
          </button>
        )}
        {/* Triage */}
        {canTriage && (
          <div className="d-section">
            <div className="d-sec-title">Triage</div>
            <div className="triage-grid">
              {['acknowledged','investigating','closed'].map(s => {
                const active = meta?.status === s;
                return (
                  <button key={s} className={`t-btn${active?' '+TRIAGE_META[s].cls:''}`}
                          onClick={() => setStatus(s)}>
                    {TRIAGE_META[s].label}
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {/* Signature details */}
        <div className="d-section">
          <div className="d-sec-title">Details</div>
          <div className="d-kv-grid">
            <div className="d-kv"><span className="d-k">Interface</span><span className="d-v">{a.iface||'—'}</span></div>
            <div className="d-kv"><span className="d-k">Flow ID</span><span className="d-v">{a.flow_id||'—'}</span></div>
            <div className="d-kv"><span className="d-k">Category</span><span className="d-v">{a.category}</span></div>
            <div className="d-kv"><span className="d-k">Severity</span>
              <span className="d-v sev" style={{ color:m.color }}>{m.label.toUpperCase()}</span></div>
          </div>
        </div>

        {/* Activity log */}
        <div className="d-section">
          <div className="d-sec-title">Activity log</div>
          {!meta && <div className="id-empty">Loading…</div>}
          {meta && (!meta.activity || meta.activity.length===0) && <div className="id-empty">No activity yet</div>}
          {meta?.activity?.length > 0 && (
            <div className="act-log">
              {[...meta.activity].reverse().map((ev,i) => (
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
          )}
          {meta && (!meta.activity || meta.activity.length===0) && (
            <div className="act-log">
              <div className="act-entry">
                <div className="act-dot"/>
                <div>
                  <div className="act-action">Alert received</div>
                  <div className="act-meta">System · {fmtDetailTime(a.ts)}</div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Notes */}
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

// ── IP context panel (right col) ──────────────────────────────────────────────
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

  // 24h activity histogram — bucket by hour
  const histogram = useMemo(() => {
    const buckets = Array(24).fill(0);
    const now = Date.now();
    ipAlerts.forEach(x => {
      const d = new Date(x.ts);
      if (isNaN(d)) return;
      const hoursAgo = (now - d.getTime()) / 3600000;
      if (hoursAgo < 24) {
        const bucket = Math.floor(hoursAgo);
        buckets[23 - bucket]++;
      }
    });
    return buckets;
  }, [ipAlerts]);
  const histMax = Math.max(...histogram, 1);

  const recentFromIp = useMemo(() =>
    ipAlerts.filter(x => x.id !== a.id).slice(0,6),
    [ipAlerts, a.id]);

  return (
    <div className="context-col">
      <div className="ctx-head">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--tx3)" strokeWidth="1.5"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
        <span className="ctx-title">IP intelligence</span>
      </div>
      <div className="ctx-scroll">
        {/* IP card */}
        <div className="ip-card">
          <div className="ip-addr">{ip}</div>
          <div className="ip-sub">Source IP · internal network</div>
          <div className="ip-stats-grid">
            <div className="ip-stat">
              <div className="ip-stat-val" style={{ color:'var(--sev-high)' }}>{ipAlerts.length}</div>
              <div className="ip-stat-label">TOTAL ALERTS</div>
            </div>
            <div className="ip-stat">
              <div className="ip-stat-val" style={{ color:'var(--sev-critical)' }}>{sevBreak.critical+sevBreak.high}</div>
              <div className="ip-stat-label">HIGH+ SEVERITY</div>
            </div>
            <div className="ip-stat">
              <div className="ip-stat-val" style={{ color:'var(--accent)' }}>{topSigs.length}</div>
              <div className="ip-stat-label">UNIQUE SIGS</div>
            </div>
            <div className="ip-stat">
              <div className="ip-stat-val" style={{ color:'var(--tx2)' }}>
                {Object.values(sevBreak).reduce((a,b)=>a+b,0) > 0
                  ? Math.round(((sevBreak.critical+sevBreak.high) / ipAlerts.length)*100) + '%'
                  : '—'}
              </div>
              <div className="ip-stat-label">HIGH RATE</div>
            </div>
          </div>
        </div>

        {/* 24h histogram */}
        <div className="ip-histogram">
          <div className="ctx-sec-label">Activity — last 24 hours</div>
          <div className="hist-bars">
            {histogram.map((v,i) => {
              const h = Math.max(2, Math.round((v/histMax)*34));
              const bg = v>histMax*.75 ? 'var(--sev-critical)' : v>histMax*.4 ? 'var(--sev-high)' : v>0 ? 'var(--accent)' : 'var(--s3)';
              return <div key={i} className="hist-bar" style={{ height:h, background:bg }}/>;
            })}
          </div>
          <div className="hist-axis">
            <span className="hist-tick">24h ago</span>
            <span className="hist-tick">12h ago</span>
            <span className="hist-tick">now</span>
          </div>
        </div>

        {/* Top signatures */}
        {topSigs.length > 0 && (
          <div className="top-sigs">
            <div className="ctx-sec-label">Top signatures</div>
            {topSigs.map(([sig, count], i) => (
              <div key={i} className="sig-row">
                <div className="sig-name" title={sig}>{sig}</div>
                <div className="sig-track">
                  <div className="sig-fill" style={{ width:`${Math.round(count/maxSigCount*100)}%` }}/>
                </div>
                <div className="sig-count">{count}</div>
              </div>
            ))}
          </div>
        )}

        {/* Recent alerts from this IP */}
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

// ── Bulk panel ────────────────────────────────────────────────────────────────
function BulkPanel({ selectedAlerts, alerts, role, onBulkStatus, onClearSelection }) {
  const canTriage = role==='admin'||role==='analyst';
  const count = selectedAlerts.size;
  return (
    <div className="bulk-panel">
      <div className="bulk-title">{count} selected</div>
      <div className="bulk-count">{canTriage ? 'Apply triage status to all selected:' : 'Read-only access'}</div>
      {canTriage && (
        <div className="bulk-actions">
          {['acknowledged','investigating','closed'].map(s => (
            <button key={s} className="btn primary" onClick={() => onBulkStatus(s)}>
              Mark as {s}
            </button>
          ))}
          <button className="btn danger" style={{ marginTop:6 }} onClick={onClearSelection}>
            Clear selection
          </button>
        </div>
      )}
    </div>
  );
}

// ── Flows view ────────────────────────────────────────────────────────────────
function FlowsView() {
  const [flows, setFlows] = useState([]);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    fetch('/flows?limit=200').then(r=>r.json())
      .then(d => { setFlows(d.flows||[]); setLoading(false); })
      .catch(() => setLoading(false));
    const es = new EventSource('/events');
    es.addEventListener('flow', e => { try { setFlows(prev => [JSON.parse(e.data), ...prev].slice(0,500)); } catch {} });
    return () => es.close();
  }, []);
  if (loading) return <div className="empty-state">Loading flows…</div>;
  if (!flows.length) return <div className="empty-state">No flow events</div>;
  return (
    <div className="table-wrap">
      <table className="data-table">
        <thead><tr>
          <th>Time</th><th>Source</th><th>Destination</th>
          <th>Proto</th><th>App</th><th>↑ Bytes</th><th>↓ Bytes</th><th>State</th>
        </tr></thead>
        <tbody>{flows.map((f,i) => (
          <tr key={i}>
            <td>{fmtAlertTime(f.ts)}</td>
            <td className="td-hi">{f.src_ip}:{f.src_port}</td>
            <td>{f.dst_ip}:{f.dst_port}</td>
            <td>{f.proto?.toUpperCase()}</td>
            <td>{f.app_proto||'—'}</td>
            <td>{(f.bytes_toserver||0).toLocaleString()}</td>
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
    fetch('/dns?limit=200').then(r=>r.json())
      .then(d => { setRecords(d.dns||[]); setLoading(false); })
      .catch(() => setLoading(false));
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
          <thead><tr>
            <th>Time</th><th>Client</th><th>Query</th>
            <th>Type</th><th>Dir</th><th>RCode</th><th>TTL</th>
          </tr></thead>
          <tbody>{records.map((d,i) => (
            <tr key={i} onClick={() => setSelected(d)} style={{ cursor:'pointer' }} className="row-hover">
              <td>{fmtAlertTime(d.ts)}</td>
              <td className="td-hi">{d.src_ip}</td>
              <td className="td-accent">{d.rrname||'—'}</td>
              <td>{d.rrtype||'—'}</td>
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
  const total = data.reduce((s,d) => s+d.count, 0) || 1;
  const R=70, cx=90, cy=90, sw=22, circ=2*Math.PI*R;
  let offset=0;
  const slices = data.map((d,i) => {
    const dash = (d.count/total)*circ;
    const sl = { offset, dash, gap:circ-dash, color:COLORS[i%COLORS.length], label:d.category, count:d.count };
    offset += dash; return sl;
  });
  const [hov, setHov] = useState(null);
  return (
    <div style={{ display:'flex', gap:20, alignItems:'center', flexWrap:'wrap' }}>
      <svg width="180" height="180" viewBox="0 0 180 180" style={{ flexShrink:0 }}>
        <circle cx={cx} cy={cy} r={R} fill="none" stroke="var(--s3)" strokeWidth={sw}/>
        {slices.map((sl,i) => (
          <circle key={i} cx={cx} cy={cy} r={R} fill="none" stroke={sl.color}
                  strokeWidth={hov===i?sw+4:sw}
                  strokeDasharray={`${sl.dash} ${sl.gap}`}
                  strokeDashoffset={circ/4-sl.offset}
                  style={{ cursor:'pointer', transition:'stroke-width .15s', transform:'rotate(-90deg)', transformOrigin:`${cx}px ${cy}px` }}
                  onMouseEnter={()=>setHov(i)} onMouseLeave={()=>setHov(null)}/>
        ))}
        <text x={cx} y={cy-6} textAnchor="middle" fill="var(--tx1)" fontSize="20" fontWeight="700" fontFamily="var(--mono)">{total}</text>
        <text x={cx} y={cy+11} textAnchor="middle" fill="var(--tx3)" fontSize="9" letterSpacing=".08em">TOTAL</text>
      </svg>
      <div style={{ display:'flex', flexDirection:'column', gap:7, flex:1, minWidth:140 }}>
        {slices.map((sl,i) => (
          <div key={i} style={{ display:'flex', alignItems:'center', gap:7, opacity:hov!==null&&hov!==i?0.35:1, transition:'opacity .15s' }}
               onMouseEnter={()=>setHov(i)} onMouseLeave={()=>setHov(null)}>
            <div style={{ width:8, height:8, borderRadius:2, background:sl.color, flexShrink:0 }}/>
            <span style={{ fontSize:10, color:'var(--tx2)', flex:1, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{sl.label||'—'}</span>
            <span style={{ fontSize:10, color:'var(--tx1)', fontFamily:'var(--mono)', flexShrink:0 }}>{sl.count}</span>
            <span style={{ fontSize:9, color:'var(--tx3)', width:32, textAlign:'right', fontFamily:'var(--mono)', flexShrink:0 }}>{Math.round(sl.count/total*100)}%</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Charts view ───────────────────────────────────────────────────────────────
function ChartsView() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [hrs, setHrs] = useState(24);
  function load(h) {
    setLoading(true);
    fetch(`/charts?trend=${h}`).then(r=>r.json()).then(d=>{setData(d);setLoading(false);}).catch(()=>setLoading(false));
  }
  useEffect(() => { load(hrs); }, [hrs]);
  if (loading) return <div className="empty-state">Loading charts…</div>;
  if (!data)   return <div className="empty-state">No chart data</div>;
  const trend  = data.trend||[], sevs=data.by_severity||[], talkers=data.top_talkers||[], cats=data.by_category||[];
  const mxT=Math.max(...trend.map(t=>t.count),1), mxS=Math.max(...sevs.map(x=>x.count),1), mxTk=Math.max(...talkers.map(x=>x.count),1);
  const labelEvery = Math.max(1, Math.ceil(trend.length/8));
  const IP_COLORS = ['var(--sev-info)','var(--sev-medium)','var(--accent)','var(--sev-high)','var(--sev-critical)','var(--sev-low)'];
  return (
    <div className="charts-layout">
      <div className="charts-controls">
        <div style={{ display:'flex', gap:2, marginLeft:'auto' }}>
          {CHART_WINDOWS.map(w => (
            <button key={w.hrs} className={`tab-btn${hrs===w.hrs?' active':''}`} onClick={()=>setHrs(w.hrs)}>{w.label}</button>
          ))}
        </div>
      </div>
      <div className="charts-grid">
        <div className="chart-card wide">
          <div className="chart-card-title">Alert trend</div>
          <div style={{ display:'flex', alignItems:'flex-end', gap:2, height:130, paddingBottom:22, position:'relative' }}>
            {[.25,.5,.75,1].map(p=><div key={p} style={{ position:'absolute',left:0,right:0,bottom:22+p*108,borderTop:'1px dashed var(--ln)',pointerEvents:'none' }}/>)}
            {trend.map((t,i) => {
              const h = Math.max(2, Math.round(t.count/mxT*108));
              const col = t.count>mxT*.75?'var(--sev-critical)':t.count>mxT*.45?'var(--sev-high)':'var(--accent)';
              return (
                <div key={i} title={`${t.ts}: ${t.count}`}
                     style={{ flex:1, display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'flex-end', position:'relative' }}>
                  <div style={{ width:'100%', height:h, background:col, opacity:.85, borderRadius:'2px 2px 0 0', transition:'height .2s' }}/>
                  {i%labelEvery===0 && <div style={{ position:'absolute', bottom:-18, fontSize:9, color:'var(--tx3)', whiteSpace:'nowrap', transform:'translateX(-50%)', left:'50%' }}>{t.ts}</div>}
                </div>
              );
            })}
          </div>
          <div style={{ display:'flex', justifyContent:'space-between', marginTop:4 }}>
            <span style={{ fontSize:9, color:'var(--tx3)' }}>0</span>
            <span style={{ fontSize:9, color:'var(--tx3)' }}>peak: {mxT}</span>
          </div>
        </div>
        <div className="chart-card">
          <div className="chart-card-title">By severity</div>
          <div className="bar-list">
            {sevs.map(r => { const m=SEV_META[r.severity]||SEV_META.info; return (
              <div key={r.severity} className="bar-row">
                <span className="bar-label" style={{ color:m.color }}>{m.label}</span>
                <div className="bar-track" style={{ background:m.bg }}><div className="bar-fill" style={{ width:`${Math.round(r.count/mxS*100)}%`, background:m.color }}/></div>
                <span className="bar-val" style={{ color:m.color }}>{r.count}</span>
              </div>
            ); })}
          </div>
        </div>
        <div className="chart-card">
          <div className="chart-card-title">Top source IPs</div>
          <div className="bar-list">
            {talkers.map((r,i) => { const c=IP_COLORS[i%IP_COLORS.length]; return (
              <div key={r.ip} className="bar-row">
                <span className="bar-label" style={{ color:c }}>{r.ip}</span>
                <div className="bar-track"><div className="bar-fill" style={{ width:`${Math.round(r.count/mxTk*100)}%`, background:c }}/></div>
                <span className="bar-val" style={{ color:c }}>{r.count}</span>
              </div>
            ); })}
          </div>
        </div>
        <div className="chart-card wide">
          <div className="chart-card-title">By category</div>
          {cats.length ? <DonutChart data={cats}/> : <div className="empty-state" style={{ padding:'20px 0' }}>No category data</div>}
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
  const [url, setUrl] =useState(initial?.url||'');
  const [sevs,setSevs]=useState(initial?.severities||ALL_SEVS);
  const [allowLocal,setAllowLocal]=useState(initial?.allow_local||false);
  function toggleSev(s){setSevs(p=>p.includes(s)?p.filter(x=>x!==s):[...p,s]);}
  async function submit(){
    if(!name.trim()||!url.trim())return;
    const body={name:name.trim(),type,url:url.trim(),severities:sevs,enabled:true,allow_local:allowLocal};
    const res=await fetch(editing?`/webhooks/${initial.id}`:'/webhooks',{
      method:editing?'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),
    });
    if(res.ok){onSave();onClose();}
  }
  return (
    <div className="modal-backdrop" onClick={e=>e.target===e.currentTarget&&onClose()}>
      <div className="modal">
        <div className="modal-title">{editing?'Edit webhook':'Add webhook'}</div>
        <div className="modal-sub">Push alert notifications to Slack, Discord, or any HTTP endpoint.</div>
        <div className="form-row">
          <div className="form-group" style={{flex:1}}><label className="form-label">Name</label><input className="form-input" value={name} onChange={e=>setName(e.target.value)} placeholder="My Webhook"/></div>
          <div className="form-group" style={{maxWidth:110}}><label className="form-label">Type</label>
            <select className="form-select" value={type} onChange={e=>setType(e.target.value)}>
              {WEBHOOK_TYPES.map(t=><option key={t} value={t}>{t.charAt(0).toUpperCase()+t.slice(1)}</option>)}
            </select>
          </div>
        </div>
        <div className="form-group"><label className="form-label">Endpoint URL</label><input className="form-input" value={url} onChange={e=>setUrl(e.target.value)} placeholder="https://hooks.slack.com/…"/></div>
        <div className="form-group">
          <label className="form-label" style={{ display:'flex', alignItems:'center', gap:10, cursor:'pointer', userSelect:'none' }}>
            <span style={{ position:'relative', display:'inline-block', width:36, height:20, flexShrink:0 }}>
              <input type="checkbox" checked={allowLocal} onChange={e=>setAllowLocal(e.target.checked)}
                     style={{ opacity:0, width:0, height:0, position:'absolute' }}/>
              <span style={{ position:'absolute', inset:0, borderRadius:20, transition:'.2s',
                background: allowLocal ? 'var(--accent)' : 'var(--s3)',
                border:'1px solid var(--ln)' }}/>
              <span style={{ position:'absolute', top:2, left: allowLocal ? 18 : 2,
                width:16, height:16, borderRadius:'50%', background:'white',
                boxShadow:'0 1px 3px rgba(0,0,0,.3)', transition:'.2s' }}/>
            </span>
            <span style={{ fontSize:12, color:'var(--tx1)' }}>Allow local / private URLs</span>
            <span style={{ fontSize:11, color:'var(--tx3)', fontWeight:400 }}>
              {allowLocal
                ? '⚠ Enabled — private IPs (e.g. n8n at 192.168.x.x) are permitted'
                : 'Off — only public HTTPS endpoints allowed'}
            </span>
          </label>
        </div>
        <div className="form-group">
          <label className="form-label">Trigger on severity</label>
          <div className="sev-checkboxes">
            {ALL_SEVS.map(s=>{const m=SEV_META[s];const on=sevs.includes(s);return(
              <label key={s} className={`sev-check${on?' checked':''}`} style={{color:m.color,borderColor:on?m.color:'var(--ln)'}}>
                <input type="checkbox" checked={on} onChange={()=>toggleSev(s)}/>{m.label}
              </label>
            );})}
          </div>
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
    const res=await fetch(editing?`/users/${initial.id}`:'/users',{
      method:editing?'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),
    });
    if(res.ok){onSave();onClose();}
  }
  return (
    <div className="modal-backdrop" onClick={e=>e.target===e.currentTarget&&onClose()}>
      <div className="modal">
        <div className="modal-title">{editing?'Edit user':'Add user'}</div>
        <div className="modal-sub">Role controls what the user can see and do.</div>
        {!editing&&(<>
          <div className="form-group"><label className="form-label">Username</label><input className="form-input" value={username} onChange={e=>setUsername(e.target.value)} placeholder="jsmith"/></div>
          <div className="form-group"><label className="form-label">Password</label><input className="form-input" type="password" value={password} onChange={e=>setPassword(e.target.value)} placeholder="••••••••"/></div>
        </>)}
        <div className="form-group"><label className="form-label">Role</label>
          <select className="form-select" value={role} onChange={e=>setRole(e.target.value)}>
            <option value="admin">Admin — full access</option>
            <option value="analyst">Analyst — read + triage, no delete</option>
            <option value="viewer">Viewer — alert stream only</option>
          </select>
        </div>
        <div className="modal-footer">
          <button className="btn-modal" onClick={onClose}>Cancel</button>
          <button className="btn-modal confirm" onClick={submit}>{editing?'Save':'Create user'}</button>
        </div>
      </div>
    </div>
  );
}

// ── Settings view ─────────────────────────────────────────────────────────────
function SettingsView({ theme, setTheme, role, username, onLogout, onDataFlushed }) {
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
  function confirmDeleteUser(u){setConfirm({title:'Delete user',body:`Delete <strong>${u.username}</strong>? Cannot be undone.`,confirmLabel:'Delete',variant:'danger',onConfirm:async()=>{await fetch(`/users/${u.id}`,{method:'DELETE'});loadUsers();}});}
  function confirmClearData(ep,label,count){setConfirm({title:`Clear all ${label}`,body:`Permanently delete <strong>${count} ${label} records</strong>. Cannot be undone.`,confirmLabel:`Clear ${label}`,variant:'warning',onConfirm:async()=>{await fetch(ep,{method:'DELETE'});loadHealth();}});}
  async function toggleWebhook(wh){await fetch(`/webhooks/${wh.id}`,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:!wh.enabled})});loadWebhooks();}
  function confirmDeleteWh(wh){setConfirm({title:'Delete webhook',body:`Delete <strong>${wh.name}</strong>?`,confirmLabel:'Delete',variant:'danger',onConfirm:async()=>{await fetch(`/webhooks/${wh.id}`,{method:'DELETE'});loadWebhooks();}});}
  async function testWebhook(id){
    setTestMsg(p=>({...p,[id]:'Sending…'}));
    const r=await fetch(`/webhooks/${id}/test`,{method:'POST'});
    const d=await r.json();
    setTestMsg(p=>({...p,[id]:d.ok?'✓ Delivered':'✗ '+(d.error||'Failed')}));
    setTimeout(()=>setTestMsg(p=>{const n={...p};delete n[id];return n;}),3000);
  }
  const initials=name=>name.slice(0,2).toUpperCase();
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
              <div className="wh-url" style={{display:'flex',alignItems:'center',gap:6,flexWrap:'wrap'}}>
                <span>{wh.url}</span>
                {wh.allow_local && (
                  <span style={{fontSize:9,padding:'1px 6px',borderRadius:10,
                    background:'rgba(251,191,36,.12)',color:'#fbbf24',
                    border:'1px solid rgba(251,191,36,.3)',fontFamily:'var(--mono)',
                    letterSpacing:'.05em',textTransform:'uppercase',flexShrink:0}}>local</span>
                )}
              </div>
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
                <div style={{display:'flex',gap:3,flexShrink:0}}><div style={{width:10,height:10,borderRadius:3,background:t.dot,border:'1px solid rgba(0,0,0,.15)'}}/><div style={{width:10,height:10,borderRadius:3,background:t.accent}}/></div>
                <span style={{fontSize:11}}>{t.label}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
      {isAdmin&&health&&(<div className="settings-card">
        <div className="settings-card-header"><span className="settings-card-title">Data management</span></div>
        <div className="settings-card-body">
          {[{label:'Alerts',ep:'/alerts',count:health?.db?.alerts?.total??0},{label:'Flows',ep:'/flows',count:health?.db?.flows?.total??0},{label:'DNS events',ep:'/dns',count:health?.db?.dns?.total??0}].map(row=>(
            <div key={row.label} className="data-mgmt-row">
              <div><div className="data-mgmt-label">{row.label}</div><div className="data-mgmt-sub">{row.count.toLocaleString()} records</div></div>
              <button className="btn danger sm" onClick={()=>confirmClearData(row.ep,row.label.toLowerCase(),row.count)}>Clear all</button>
            </div>
          ))}
        </div>
      </div>)}
      {health&&(<div className="settings-card">
        <div className="settings-card-header"><span className="settings-card-title">Server health</span></div>
        <div className="settings-card-body">
          <div className="health-grid">
            {[{l:'Alerts',v:health.db?.alerts?.total,s:`${health.db?.alerts?.recent} recent`},{l:'Flows',v:health.db?.flows?.total,s:`${health.db?.flows?.recent} recent`},{l:'DNS',v:health.db?.dns?.total,s:`${health.db?.dns?.recent} recent`},{l:'HTTP',v:health.db?.http?.total,s:`${health.db?.http?.recent} recent`},{l:'Clients',v:health.clients,s:'connected'}].map(r=>(
              <div key={r.l} className="health-stat">
                <div className="health-stat-label">{r.l}</div>
                <div className="health-stat-value">{(r.v||0).toLocaleString()}</div>
                <div className="health-stat-sub">{r.s}</div>
              </div>
            ))}
            <div className="health-stat"><div className="health-stat-label">Oldest record</div><div className="health-stat-value" style={{fontSize:12}}>{health.db?.oldest?new Date(health.db.oldest).toLocaleDateString():'—'}</div></div>
          </div>
        </div>
      </div>)}
      {/* Replay / Flush */}
      {isAdmin && <ReplayFlushPanel onFlushed={onDataFlushed}/>}

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

// ══════════════════════════════════════════════════════════════════════════════
// THREAT INTEL — shared across all skins
function ExplainDialog({ alert: a, role, onClose, aiEnabled, aiExplanation, onRequestAiExplain }) {
  const [intel,    setIntel]   = useState(null);
  const [loading,  setLoading] = useState(true);
  const [editing,  setEditing] = useState(false);
  const [tab,      setTab]     = useState(aiEnabled ? 'ai' : 'intel');
  const canWrite = role === 'admin' || role === 'analyst';

  useEffect(() => {
    if (!a) return;
    setLoading(true); setIntel(null); setEditing(false);
    fetch(`/threat-intel/lookup?sig_id=${encodeURIComponent(a.sig_id||'')}` +
          `&category=${encodeURIComponent(a.category||'')}`)
      .then(r => r.json())
      .then(d => { setIntel(d && d.id ? d : null); setLoading(false); })
      .catch(() => { setIntel(null); setLoading(false); });
    // Trigger AI fetch on open if AI enabled and not yet fetched
    if (aiEnabled && onRequestAiExplain && !aiExplanation) {
      onRequestAiExplain(a);
    }
  }, [a?.sig_id, a?.category]);

  if (!a) return null;
  const m = SEV_META[a.severity] || SEV_META.info;

  const overlayStyle = {
    position:'fixed', inset:0, background:'rgba(0,0,0,.65)',
    display:'flex', alignItems:'center', justifyContent:'center',
    zIndex:1000, padding:16,
  };
  const boxStyle = {
    background:'var(--s1)', border:'1px solid var(--ln)',
    borderRadius:'var(--radius-lg,10px)', width:560, maxWidth:'95vw',
    maxHeight:'88vh', display:'flex', flexDirection:'column',
    boxShadow:'0 24px 48px rgba(0,0,0,.4)',
  };
  const tabBtn = active => ({
    padding:'4px 14px', border:'none', cursor:'pointer', fontSize:11,
    fontFamily:'var(--mono)', borderRadius:'var(--radius-sm,4px)',
    background: active ? 'var(--accent)' : 'transparent',
    color: active ? 'white' : 'var(--tx3)',
  });

  return (
    <div style={overlayStyle} onClick={e => e.target===e.currentTarget && onClose()}>
      <div style={boxStyle}>
        {/* Header */}
        <div style={{ padding:'16px 20px', borderBottom:'1px solid var(--ln)',
                      display:'flex', alignItems:'flex-start', gap:12, flexShrink:0 }}>
          <div style={{ flex:1, minWidth:0 }}>
            <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:6, flexWrap:'wrap' }}>
              <span className="sev-badge" style={{ color:m.color, background:m.bg }}>{a.severity?.toUpperCase()}</span>
              <span style={{ fontFamily:'var(--mono)', fontSize:11, color:'var(--tx3)' }}>SID {a.sig_id}</span>
              {a.category && <span style={{ fontFamily:'var(--mono)', fontSize:11, color:'var(--tx3)' }}>{a.category}</span>}
            </div>
            <div style={{ fontSize:13, fontWeight:600, color:'var(--tx1)', lineHeight:1.4 }}>{a.sig_msg}</div>
          </div>
          <button onClick={onClose} style={{ background:'none', border:'none',
            color:'var(--tx3)', cursor:'pointer', padding:4, flexShrink:0, fontSize:18, lineHeight:1 }}>×</button>
        </div>

        {/* Tab bar */}
        <div style={{ display:'flex', gap:2, padding:'8px 20px',
                      borderBottom:'1px solid var(--ln)', background:'var(--s2)', flexShrink:0 }}>
          <div style={{ display:'flex', gap:2, background:'var(--s3)',
                        border:'1px solid var(--ln)', borderRadius:'var(--radius-sm,4px)', padding:2 }}>
            <button style={tabBtn(tab==='intel')} onClick={()=>setTab('intel')}>Threat Intel</button>
            {aiEnabled && (
              <button style={tabBtn(tab==='ai')} onClick={()=>{ setTab('ai'); if(onRequestAiExplain && !aiExplanation) onRequestAiExplain(a); }}>
                AI Summary
              </button>
            )}
          </div>
        </div>

        {/* Body */}
        <div style={{ flex:1, overflowY:'auto', padding:'18px 20px' }}>
          {tab === 'intel' && (
            <>
              {loading && (
                <div style={{ textAlign:'center', padding:'32px 0', color:'var(--tx3)',
                              fontFamily:'var(--mono)', fontSize:12 }}>Looking up intel…</div>
              )}
              {!loading && intel && !editing && (
                <TIReadView intel={intel} alert={a} role={role} onEdit={() => setEditing(true)} />
              )}
              {!loading && !intel && !editing && (
                <TIEmptyView alert={a} canWrite={canWrite} onAdd={() => setEditing(true)} />
              )}
              {!loading && editing && (
                <TIEditForm
                  alert={a} existing={intel} role={role}
                  onSaved={d => { setIntel(d); setEditing(false); }}
                  onCancel={() => setEditing(false)}
                />
              )}
            </>
          )}

          {tab === 'ai' && aiEnabled && (
            <AIExplanationPanel
              alert={a}
              aiExplanation={aiExplanation}
              onRequest={() => onRequestAiExplain && onRequestAiExplain(a)}
            />
          )}
        </div>
      </div>
    </div>
  );
}


function AIExplanationPanel({ alert: a, aiExplanation, onRequest }) {
  const hasResult  = aiExplanation && aiExplanation.text;
  const isLoading  = aiExplanation && aiExplanation.loading;
  const hasError   = aiExplanation && aiExplanation.error;

  return (
    <div>
      <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:14 }}>
        <span style={{ fontSize:9, fontFamily:'var(--mono)', letterSpacing:'.07em',
                       textTransform:'uppercase', padding:'2px 8px', borderRadius:20,
                       background:'rgba(99,102,241,.1)', color:'var(--accent)',
                       border:'1px solid rgba(99,102,241,.25)' }}>AI Executive Summary</span>
        {!isLoading && (
          <button onClick={onRequest} style={{ marginLeft:'auto', padding:'2px 10px',
            border:'1px solid var(--ln)', borderRadius:'var(--radius-sm,4px)',
            background:'transparent', color:'var(--tx2)', fontSize:11, cursor:'pointer' }}>
            {hasResult ? '↻ Refresh' : 'Generate'}
          </button>
        )}
      </div>

      {isLoading && (
        <div style={{ display:'flex', alignItems:'center', gap:10, padding:'24px 0',
                      color:'var(--tx3)', fontFamily:'var(--mono)', fontSize:12 }}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"
               strokeWidth="2" style={{ animation:'spin 1s linear infinite' }}>
            <path d="M21 12a9 9 0 1 1-6.219-8.56"/>
          </svg>
          Generating executive summary…
        </div>
      )}

      {!isLoading && hasError && (
        <div style={{ padding:'12px 14px', fontSize:12, lineHeight:1.65,
                      background:'rgba(240,84,84,.08)', border:'1px solid rgba(240,84,84,.25)',
                      borderRadius:'var(--radius-md,6px)', color:'var(--danger,#f05454)' }}>
          {aiExplanation.error}
        </div>
      )}

      {!isLoading && hasResult && (
        <div style={{ fontSize:13, color:'var(--tx1)', lineHeight:1.8, whiteSpace:'pre-wrap',
                      background:'var(--s2)', border:'1px solid var(--ln)',
                      borderRadius:'var(--radius-md,6px)', padding:'14px 16px' }}>
          {aiExplanation.text}
        </div>
      )}

      {!isLoading && !hasResult && !hasError && (
        <div style={{ textAlign:'center', padding:'32px 0', color:'var(--tx3)' }}>
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor"
               strokeWidth="1" style={{ marginBottom:10, opacity:.3 }}>
            <circle cx="12" cy="12" r="10"/>
            <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/>
          </svg>
          <div style={{ fontSize:13, marginBottom:6 }}>No AI summary yet</div>
          <div style={{ fontSize:11, color:'var(--tx3)' }}>Click Generate to create an executive summary</div>
        </div>
      )}
    </div>
  );
}

function TIReadView({ intel, alert: a, role, onEdit }) {
  const matchLabel = intel.sig_id === a.sig_id ? 'Exact SID match' : 'Category match';
  const fmtDate = ts => new Date(ts*1000).toLocaleDateString(undefined,{month:'short',day:'numeric',year:'numeric'});
  return (
    <div>
      <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:14 }}>
        <span style={{ fontSize:9, fontFamily:'var(--mono)', letterSpacing:'.07em',
                       textTransform:'uppercase', padding:'2px 8px', borderRadius:20,
                       background:'var(--success-bg,rgba(76,175,130,.12))',
                       color:'var(--success,#4caf82)', border:'1px solid var(--success,#4caf82)' }}>
          {matchLabel}
        </span>
        <span style={{ fontSize:10, color:'var(--tx3)', fontFamily:'var(--mono)' }}>
          {intel.created_by||'system'} · {fmtDate(intel.updated_at)}
        </span>
        {(role==='admin'||role==='analyst') && (
          <button onClick={onEdit} style={{ marginLeft:'auto', padding:'2px 10px',
            border:'1px solid var(--ln)', borderRadius:'var(--radius-sm,4px)',
            background:'transparent', color:'var(--tx2)', fontSize:11, cursor:'pointer' }}>Edit</button>
        )}
      </div>
      <div style={{ fontSize:13, color:'var(--tx1)', lineHeight:1.75, whiteSpace:'pre-wrap',
                    background:'var(--s2)', border:'1px solid var(--ln)',
                    borderRadius:'var(--radius-md,6px)', padding:'12px 14px', marginBottom:14 }}>
        {intel.explanation}
      </div>
      {intel.tags?.length > 0 && (
        <div style={{ marginBottom:12 }}>
          <div style={{ fontSize:9, fontFamily:'var(--mono)', textTransform:'uppercase',
                        letterSpacing:'.09em', color:'var(--tx3)', marginBottom:6 }}>Tags</div>
          <div style={{ display:'flex', flexWrap:'wrap', gap:5 }}>
            {intel.tags.map(t => (
              <span key={t} style={{ padding:'2px 9px', borderRadius:20, fontSize:11,
                background:'var(--s3)', border:'1px solid var(--ln)',
                color:'var(--tx2)', fontFamily:'var(--mono)' }}>{t}</span>
            ))}
          </div>
        </div>
      )}
      {intel.refs?.length > 0 && (
        <div>
          <div style={{ fontSize:9, fontFamily:'var(--mono)', textTransform:'uppercase',
                        letterSpacing:'.09em', color:'var(--tx3)', marginBottom:6 }}>References</div>
          {intel.refs.map((r,i) => (
            <div key={i} style={{ marginBottom:3 }}>
              <a href={r.startsWith('http')?r:`https://${r}`} target="_blank" rel="noopener noreferrer"
                 style={{ fontSize:11, color:'var(--accent)', fontFamily:'var(--mono)', wordBreak:'break-all' }}>{r}</a>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function TIEmptyView({ alert: a, canWrite, onAdd }) {
  return (
    <div style={{ textAlign:'center', padding:'24px 0' }}>
      <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="var(--tx3)"
           strokeWidth="1" style={{ marginBottom:12, opacity:.4 }}>
        <circle cx="12" cy="12" r="10"/>
        <line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
      </svg>
      <div style={{ fontSize:13, fontWeight:500, color:'var(--tx2)', marginBottom:6 }}>No explanation yet</div>
      <div style={{ fontSize:12, color:'var(--tx3)', marginBottom:20, lineHeight:1.6 }}>
        SID {a.sig_id} · {a.category||'Uncategorized'}<br/>
        Add an explanation to help analysts understand this alert.
      </div>
      {canWrite && (
        <button onClick={onAdd} style={{ padding:'7px 20px',
          border:'1px solid var(--accent)', borderRadius:'var(--radius-sm,4px)',
          background:'transparent', color:'var(--accent)', fontSize:12, cursor:'pointer' }}>
          + Add Explanation
        </button>
      )}
    </div>
  );
}

function TIEditForm({ alert: a, existing, role, onSaved, onCancel }) {
  const [scope,       setScope]       = useState(existing?.sig_id ? 'sid' : 'category');
  const [explanation, setExplanation] = useState(existing?.explanation || '');
  const [tagInput,    setTagInput]    = useState('');
  const [tags,        setTags]        = useState(existing?.tags || []);
  const [refInput,    setRefInput]    = useState('');
  const [refs,        setRefs]        = useState(existing?.refs || []);
  const [saving,      setSaving]      = useState(false);
  const [err,         setErr]         = useState('');

  function addTag() { const t=tagInput.trim(); if(t&&!tags.includes(t)) setTags(p=>[...p,t]); setTagInput(''); }
  function addRef() { const r=refInput.trim(); if(r&&!refs.includes(r)) setRefs(p=>[...p,r]); setRefInput(''); }

  async function save() {
    if (!explanation.trim()) { setErr('Explanation is required'); return; }
    setSaving(true); setErr('');
    const body = {
      explanation: explanation.trim(), tags, refs,
      sig_id:   scope==='sid'      ? a.sig_id   : null,
      sig_msg:  scope==='sid'      ? a.sig_msg   : null,
      category: scope==='category' ? a.category  : null,
    };
    const method   = existing?.id ? 'PUT'  : 'POST';
    const endpoint = existing?.id ? `/threat-intel/${existing.id}` : '/threat-intel';
    try {
      const r = await fetch(endpoint, { method,
        headers:{'Content-Type':'application/json'}, body:JSON.stringify(body) });
      const d = await r.json();
      if (!r.ok) { setErr(d.error||'Save failed'); return; }
      onSaved(d);
    } catch { setErr('Network error'); }
    finally { setSaving(false); }
  }

  const inp = { width:'100%', padding:'7px 10px', background:'var(--s2)',
    border:'1px solid var(--ln)', borderRadius:'var(--radius-sm,4px)',
    color:'var(--tx1)', fontSize:12, fontFamily:'var(--sans,inherit)',
    outline:'none', boxSizing:'border-box' };
  const lbl = { fontSize:9, fontWeight:600, letterSpacing:'.09em', textTransform:'uppercase',
    color:'var(--tx3)', display:'block', marginBottom:5 };

  return (
    <div>
      {!existing && (
        <div style={{ marginBottom:14 }}>
          <label style={lbl}>Apply explanation to</label>
          <div style={{ display:'flex', gap:8 }}>
            {[{val:'sid',label:`SID ${a.sig_id} only`},{val:'category',label:`All "${a.category||'Uncategorized'}" alerts`}].map(opt => (
              <button key={opt.val} onClick={() => setScope(opt.val)} style={{ flex:1, padding:'6px 10px',
                border:`1px solid ${scope===opt.val?'var(--accent)':'var(--ln)'}`,
                borderRadius:'var(--radius-sm,4px)', cursor:'pointer',
                background: scope===opt.val?'rgba(var(--accent-rgb,79,156,249),.1)':'transparent',
                color: scope===opt.val?'var(--accent)':'var(--tx2)', fontSize:11 }}>
                {opt.label}
              </button>
            ))}
          </div>
        </div>
      )}

      <div style={{ marginBottom:12 }}>
        <label style={lbl}>Explanation</label>
        <textarea style={{ ...inp, minHeight:110, resize:'vertical', lineHeight:1.65 }}
          placeholder="What does this alert mean? What triggered it? Typically malicious or benign?"
          value={explanation} onChange={e => setExplanation(e.target.value)}/>
      </div>

      <div style={{ marginBottom:12 }}>
        <label style={lbl}>Tags</label>
        <div style={{ display:'flex', flexWrap:'wrap', gap:5, marginBottom:6 }}>
          {tags.map(t => (
            <span key={t} style={{ display:'inline-flex', alignItems:'center', gap:4,
              padding:'2px 8px', borderRadius:20, fontSize:11,
              background:'var(--s3)', border:'1px solid var(--ln)', color:'var(--tx2)', fontFamily:'var(--mono)' }}>
              {t}
              <span onClick={() => setTags(p=>p.filter(x=>x!==t))}
                    style={{ cursor:'pointer', color:'var(--tx3)', marginLeft:2 }}>×</span>
            </span>
          ))}
        </div>
        <div style={{ display:'flex', gap:6 }}>
          <input style={{ ...inp, flex:1 }} placeholder="e.g. lateral-movement, c2…"
                 value={tagInput} onChange={e=>setTagInput(e.target.value)}
                 onKeyDown={e=>{ if(e.key==='Enter'){e.preventDefault();addTag();} }}/>
          <button onClick={addTag} style={{ padding:'6px 12px', border:'1px solid var(--ln)',
            borderRadius:'var(--radius-sm,4px)', background:'transparent',
            color:'var(--tx2)', fontSize:11, cursor:'pointer' }}>Add</button>
        </div>
      </div>

      <div style={{ marginBottom:14 }}>
        <label style={lbl}>References</label>
        <div style={{ display:'flex', flexDirection:'column', gap:3, marginBottom:6 }}>
          {refs.map(r => (
            <div key={r} style={{ display:'flex', alignItems:'center', gap:8 }}>
              <span style={{ flex:1, fontFamily:'var(--mono)', fontSize:11, color:'var(--accent)',
                overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{r}</span>
              <span onClick={() => setRefs(p=>p.filter(x=>x!==r))}
                    style={{ cursor:'pointer', color:'var(--tx3)', fontSize:13 }}>×</span>
            </div>
          ))}
        </div>
        <div style={{ display:'flex', gap:6 }}>
          <input style={{ ...inp, flex:1, fontFamily:'var(--mono)', fontSize:11 }}
                 placeholder="https://…"
                 value={refInput} onChange={e=>setRefInput(e.target.value)}
                 onKeyDown={e=>{ if(e.key==='Enter'){e.preventDefault();addRef();} }}/>
          <button onClick={addRef} style={{ padding:'6px 12px', border:'1px solid var(--ln)',
            borderRadius:'var(--radius-sm,4px)', background:'transparent',
            color:'var(--tx2)', fontSize:11, cursor:'pointer' }}>Add</button>
        </div>
      </div>

      {err && (
        <div style={{ marginBottom:10, padding:'7px 10px', fontSize:12,
          background:'rgba(240,84,84,.1)', border:'1px solid var(--danger,#f05454)',
          borderRadius:'var(--radius-sm,4px)', color:'var(--danger,#f05454)' }}>{err}</div>
      )}

      <div style={{ display:'flex', gap:8, justifyContent:'flex-end' }}>
        <button onClick={onCancel} disabled={saving} style={{ padding:'5px 14px',
          border:'1px solid var(--ln)', borderRadius:'var(--radius-sm,4px)',
          background:'transparent', color:'var(--tx2)', fontSize:12, cursor:'pointer' }}>Cancel</button>
        <button onClick={save} disabled={saving} style={{ padding:'5px 18px',
          border:'1px solid var(--accent)', borderRadius:'var(--radius-sm,4px)',
          background:'transparent', color:'var(--accent)', fontSize:12,
          cursor:saving?'wait':'pointer' }}>
          {saving ? 'Saving…' : existing ? 'Save Changes' : 'Save Explanation'}
        </button>
      </div>
    </div>
  );
}

// ── ThreatIntelView — full settings-style page ─────────────────────────────────
// ── TIEntryForm — standalone create/edit (no alert context needed) ─────────────
function TIEntryForm({ initial, onSaved, onCancel }) {
  const isEdit = Boolean(initial?.id);

  const [sigId,       setSigId]       = useState(initial?.sig_id   || '');
  const [sigMsg,      setSigMsg]      = useState(initial?.sig_msg   || '');
  const [category,    setCategory]    = useState(initial?.category  || '');
  const [explanation, setExplanation] = useState(initial?.explanation || '');
  const [tagInput,    setTagInput]    = useState('');
  const [tags,        setTags]        = useState(initial?.tags || []);
  const [refInput,    setRefInput]    = useState('');
  const [refs,        setRefs]        = useState(initial?.refs || []);
  const [saving,      setSaving]      = useState(false);
  const [err,         setErr]         = useState('');

  function addTag() {
    const t = tagInput.trim();
    if (t && !tags.includes(t)) setTags(p => [...p, t]);
    setTagInput('');
  }
  function addRef() {
    const r = refInput.trim();
    if (r && !refs.includes(r)) setRefs(p => [...p, r]);
    setRefInput('');
  }

  async function save() {
    if (!sigId && !category.trim()) { setErr('Enter a SID or a category'); return; }
    if (!explanation.trim())         { setErr('Explanation is required');   return; }
    setSaving(true); setErr('');
    const body = {
      sig_id:      sigId ? parseInt(sigId, 10) : null,
      sig_msg:     sigMsg.trim() || null,
      category:    category.trim() || null,
      explanation: explanation.trim(),
      tags, refs,
    };
    const method   = isEdit ? 'PUT'  : 'POST';
    const endpoint = isEdit ? `/threat-intel/${initial.id}` : '/threat-intel';
    try {
      const r = await fetch(endpoint, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const d = await r.json();
      if (!r.ok) { setErr(d.error || 'Save failed'); return; }
      onSaved(d);
    } catch { setErr('Network error'); }
    finally { setSaving(false); }
  }

  const inp = {
    width:'100%', padding:'7px 10px', background:'var(--s2)',
    border:'1px solid var(--ln)', borderRadius:'var(--radius-sm,4px)',
    color:'var(--tx1)', fontSize:12, outline:'none', boxSizing:'border-box',
  };
  const lbl = {
    fontSize:9, fontWeight:600, letterSpacing:'.09em', textTransform:'uppercase',
    color:'var(--tx3)', display:'block', marginBottom:5,
  };

  return (
    <div style={{ background:'var(--s1)', border:'1px solid var(--ln)',
                  borderRadius:'var(--radius-lg,10px)', padding:'16px 18px', marginBottom:14 }}>
      <div style={{ fontSize:12, fontWeight:600, color:'var(--tx1)', marginBottom:14 }}>
        {isEdit ? 'Edit Entry' : 'New Entry'}
      </div>

      <div style={{ display:'grid', gridTemplateColumns:'1fr 2fr', gap:12, marginBottom:12 }}>
        <div>
          <label style={lbl}>SID (sig_id)</label>
          <input style={inp} type="number" placeholder="e.g. 2024897"
                 value={sigId} onChange={e => setSigId(e.target.value)}/>
        </div>
        <div>
          <label style={lbl}>Signature Name (optional)</label>
          <input style={inp} placeholder="e.g. ET SCAN Nmap"
                 value={sigMsg} onChange={e => setSigMsg(e.target.value)}/>
        </div>
      </div>

      <div style={{ marginBottom:12 }}>
        <label style={lbl}>Category (fallback if no SID)</label>
        <input style={inp} placeholder="e.g. Web Application Attack"
               value={category} onChange={e => setCategory(e.target.value)}/>
      </div>

      <div style={{ marginBottom:12 }}>
        <label style={lbl}>Explanation *</label>
        <textarea style={{ ...inp, minHeight:100, resize:'vertical', lineHeight:1.65 }}
          placeholder="What does this alert mean? What likely triggered it? Recommended action?"
          value={explanation} onChange={e => setExplanation(e.target.value)}/>
      </div>

      <div style={{ marginBottom:12 }}>
        <label style={lbl}>Tags</label>
        <div style={{ display:'flex', flexWrap:'wrap', gap:5, marginBottom:6 }}>
          {tags.map(t => (
            <span key={t} style={{ display:'inline-flex', alignItems:'center', gap:4,
              padding:'2px 8px', borderRadius:20, fontSize:11,
              background:'var(--s2)', border:'1px solid var(--ln)',
              color:'var(--tx2)', fontFamily:'var(--mono)' }}>
              {t}
              <span onClick={() => setTags(p => p.filter(x => x !== t))}
                    style={{ cursor:'pointer', color:'var(--tx3)', marginLeft:2 }}>×</span>
            </span>
          ))}
        </div>
        <div style={{ display:'flex', gap:6 }}>
          <input style={{ ...inp, flex:1 }} placeholder="scanning, recon, c2…"
                 value={tagInput} onChange={e => setTagInput(e.target.value)}
                 onKeyDown={e => { if (e.key==='Enter') { e.preventDefault(); addTag(); } }}/>
          <button onClick={addTag} style={{ padding:'6px 12px', border:'1px solid var(--ln)',
            borderRadius:'var(--radius-sm,4px)', background:'transparent',
            color:'var(--tx2)', fontSize:11, cursor:'pointer' }}>Add</button>
        </div>
      </div>

      <div style={{ marginBottom:14 }}>
        <label style={lbl}>References</label>
        <div style={{ display:'flex', flexDirection:'column', gap:4, marginBottom:6 }}>
          {refs.map(r => (
            <div key={r} style={{ display:'flex', alignItems:'center', gap:8 }}>
              <span style={{ flex:1, fontFamily:'var(--mono)', fontSize:11, color:'var(--accent)',
                overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{r}</span>
              <span onClick={() => setRefs(p => p.filter(x => x !== r))}
                    style={{ cursor:'pointer', color:'var(--tx3)', fontSize:13 }}>×</span>
            </div>
          ))}
        </div>
        <div style={{ display:'flex', gap:6 }}>
          <input style={{ ...inp, flex:1, fontFamily:'var(--mono)', fontSize:11 }}
                 placeholder="https://…"
                 value={refInput} onChange={e => setRefInput(e.target.value)}
                 onKeyDown={e => { if (e.key==='Enter') { e.preventDefault(); addRef(); } }}/>
          <button onClick={addRef} style={{ padding:'6px 12px', border:'1px solid var(--ln)',
            borderRadius:'var(--radius-sm,4px)', background:'transparent',
            color:'var(--tx2)', fontSize:11, cursor:'pointer' }}>Add</button>
        </div>
      </div>

      {err && (
        <div style={{ marginBottom:10, padding:'7px 10px', fontSize:12,
          background:'rgba(240,84,84,.1)', border:'1px solid var(--danger,#f05454)',
          borderRadius:'var(--radius-sm,4px)', color:'var(--danger,#f05454)' }}>{err}</div>
      )}

      <div style={{ display:'flex', gap:8, justifyContent:'flex-end' }}>
        <button onClick={onCancel} disabled={saving} style={{ padding:'5px 14px',
          border:'1px solid var(--ln)', borderRadius:'var(--radius-sm,4px)',
          background:'transparent', color:'var(--tx2)', fontSize:12, cursor:'pointer' }}>
          Cancel
        </button>
        <button onClick={save} disabled={saving} style={{ padding:'5px 18px',
          border:'1px solid var(--accent)', borderRadius:'var(--radius-sm,4px)',
          background:'transparent', color:'var(--accent)', fontSize:12,
          cursor: saving ? 'wait' : 'pointer' }}>
          {saving ? 'Saving…' : isEdit ? 'Save Changes' : 'Create Entry'}
        </button>
      </div>
    </div>
  );
}

function ThreatIntelView({ role }) {
  const [entries,     setEntries]     = useState([]);
  const [gaps,        setGaps]        = useState([]);
  const [loading,     setLoading]     = useState(true);
  const [tab,         setTab]         = useState('entries');
  const [showForm,    setShowForm]    = useState(false);
  const [editing,     setEditing]     = useState(null);
  const [delId,       setDelId]       = useState(null);
  const [importing,   setImporting]   = useState(false);
  const [importResult,setImportResult]= useState(null);
  const [overwrite,   setOverwrite]   = useState(false);
  const [clearConfirm,setClearConfirm]= useState(false);
  const fileInputRef  = React.useRef(null);
  const canWrite = role==='admin'||role==='analyst';

  function load() {
    setLoading(true);
    Promise.all([
      fetch('/threat-intel').then(r=>r.json()),
      fetch('/threat-intel/gaps').then(r=>r.json()),
    ]).then(([e,g]) => {
      setEntries(Array.isArray(e)?e:[]);
      setGaps(Array.isArray(g)?g:[]);
      setLoading(false);
    }).catch(()=>setLoading(false));
  }
  useEffect(()=>{ load(); },[]);

  async function doDelete(id) {
    await fetch(`/threat-intel/${id}`,{method:'DELETE'});
    setDelId(null); load();
  }

  function handleExport() {
    window.location.href = '/threat-intel/export';
  }

  async function handleImportFile(e) {
    const file = e.target.files[0];
    if (!file) return;
    e.target.value = '';
    setImporting(true); setImportResult(null);
    try {
      const text = await file.text();
      const r    = await fetch('/threat-intel/import', {
        method:  'POST',
        headers: {'Content-Type':'application/json'},
        body:    JSON.stringify({ content: text, overwrite }),
      });
      const d = await r.json();
      setImportResult(d);
      if (d.imported > 0 || d.overwritten > 0) load();
    } catch(err) {
      setImportResult({ imported:0, skipped:0, errors:[String(err)], warnings:[] });
    }
    setImporting(false);
  }

  const fmtDate = ts => new Date(ts*1000).toLocaleDateString(undefined,{month:'short',day:'numeric',year:'numeric'});

  // ── Styles ────────────────────────────────────────────────────────────────
  const sectionStyle  = { padding:'20px 24px', width:'100%', boxSizing:'border-box' };
  const innerStyle    = { maxWidth:1100, margin:'0 auto' };
  const cardStyle     = {
    background:'var(--s1)', border:'1px solid var(--ln)',
    borderRadius:'var(--radius-lg,10px)', padding:'14px 16px', marginBottom:10
  };
  const tabBtnStyle   = active => ({
    padding:'4px 14px', border:'none', cursor:'pointer', fontSize:11,
    fontFamily:'var(--mono)', borderRadius:'var(--radius-sm,4px)',
    background: active ? 'var(--accent)' : 'transparent',
    color: active ? 'white' : 'var(--tx3)',
  });
  const actnBtn = (color) => ({
    display:'flex', alignItems:'center', gap:5, padding:'4px 12px',
    border:`1px solid ${color || 'var(--ln)'}`, borderRadius:'var(--radius-sm,4px)',
    background:'transparent', color: color || 'var(--tx2)',
    fontSize:11, fontFamily:'var(--mono)', cursor:'pointer', flexShrink:0,
  });

  return (
    <div style={{ overflowY:'auto', flex:1 }}>
      {/* Tab + action bar */}
      <div style={{ display:'flex', alignItems:'center', gap:8, padding:'10px 24px',
                    borderBottom:'1px solid var(--ln)', background:'var(--s1)',
                    flexShrink:0, flexWrap:'wrap', rowGap:8 }}>
        <div style={{ display:'flex', gap:2, background:'var(--s2)',
                      border:'1px solid var(--ln)', borderRadius:'var(--radius-sm,4px)', padding:2 }}>
          <button style={tabBtnStyle(tab==='entries')} onClick={()=>setTab('entries')}>
            Entries ({entries.length})
          </button>
          <button style={tabBtnStyle(tab==='gaps')} onClick={()=>setTab('gaps')}>
            Gaps ({gaps.length})
          </button>
        </div>

        <div style={{ marginLeft:'auto', display:'flex', gap:6, alignItems:'center', flexWrap:'wrap' }}>
          {/* Export */}
          {entries.length > 0 && (
            <button style={actnBtn('var(--accent)')} onClick={handleExport} title="Download all entries as .htf">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                <polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
              </svg>
              Export .htf
            </button>
          )}

          {/* Import + overwrite toggle */}
          {canWrite && (
            <>
              <input
                ref={fileInputRef} type="file" accept=".htf,.txt"
                style={{ display:'none' }} onChange={handleImportFile}
              />
              <button
                onClick={() => setOverwrite(v => !v)}
                title={overwrite ? 'Overwrite ON — matching entries will be replaced' : 'Overwrite OFF — duplicates will be skipped'}
                style={{
                  display:'flex', alignItems:'center', gap:6,
                  padding:'2px 10px 2px 5px',
                  background: overwrite ? 'var(--teal,#0D9488)' : 'var(--s3)',
                  border: overwrite ? '1px solid var(--teal,#0D9488)' : '1px solid var(--ln)',
                  borderRadius:20, cursor:'pointer',
                  fontSize:10, fontFamily:'var(--mono)',
                  color: overwrite ? '#fff' : 'var(--tx3)',
                  transition:'background .18s, border-color .18s, color .18s',
                  flexShrink:0,
                }}>
                <span style={{
                  width:24, height:13, borderRadius:7,
                  background: overwrite ? 'rgba(255,255,255,.28)' : 'var(--s4)',
                  position:'relative', display:'inline-block',
                  flexShrink:0, transition:'background .18s',
                }}>
                  <span style={{
                    position:'absolute', top:1, left: overwrite ? 11 : 1,
                    width:11, height:11, borderRadius:'50%',
                    background: overwrite ? '#fff' : 'var(--tx3)',
                    transition:'left .18s, background .18s',
                  }}/>
                </span>
                Overwrite
              </button>
              <button style={actnBtn(importing ? 'var(--tx3)' : 'var(--teal,#0D9488)')}
                      disabled={importing}
                      onClick={() => fileInputRef.current?.click()}
                      title={overwrite ? 'Import — existing matching entries will be replaced' : 'Import — duplicates will be skipped'}>
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                  <polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>
                </svg>
                {importing ? 'Importing…' : 'Import .htf'}
              </button>
            </>
          )}

          {/* Clear All */}
          {role==='admin' && entries.length > 0 && (
            clearConfirm ? (
              <span style={{ display:'flex', alignItems:'center', gap:6 }}>
                <span style={{ fontSize:11, color:'var(--danger,#f05454)',
                               fontFamily:'var(--mono)' }}>Clear all?</span>
                <button style={actnBtn('var(--danger,#f05454)')}
                        onClick={async ()=>{
                          await fetch('/threat-intel',{method:'DELETE'});
                          setClearConfirm(false); load();
                        }}>Yes, clear</button>
                <button style={actnBtn()} onClick={()=>setClearConfirm(false)}>Cancel</button>
              </span>
            ) : (
              <button style={actnBtn('var(--danger,#f05454)')}
                      onClick={()=>setClearConfirm(true)}
                      title="Delete all threat intel entries">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <polyline points="3 6 5 6 21 6"/>
                  <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>
                  <path d="M10 11v6M14 11v6"/>
                  <path d="M9 6V4h6v2"/>
                </svg>
                Clear All
              </button>
            )
          )}

          {/* Add entry */}
          {canWrite && !showForm && tab==='entries' && (
            <button style={actnBtn()} onClick={()=>{setShowForm(true);setEditing(null);}}>
              + Add Entry
            </button>
          )}
        </div>
      </div>

      {/* Import result banner */}
      {importResult && (
        <div style={{ margin:'12px 24px 0', padding:'10px 14px',
                      background: importResult.errors?.length ? 'rgba(240,84,84,.08)' : 'rgba(16,185,129,.08)',
                      border: `1px solid ${importResult.errors?.length ? 'rgba(240,84,84,.3)' : 'rgba(16,185,129,.3)'}`,
                      borderRadius:'var(--radius-md,6px)', fontSize:12 }}>
          <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:4 }}>
            <span style={{ fontWeight:600, color: importResult.errors?.length ? 'var(--danger,#f05454)' : 'var(--success,#10b981)' }}>
              {importResult.imported > 0 || importResult.overwritten > 0
                ? [
                    importResult.imported > 0 && `✓ ${importResult.imported} imported`,
                    importResult.overwritten > 0 && `${importResult.overwritten} overwritten`,
                  ].filter(Boolean).join(' · ')
                : importResult.errors?.length ? '✗ Import failed' : 'Nothing to import'}
              {importResult.skipped > 0 && ` · ${importResult.skipped} duplicate${importResult.skipped===1?'':'s'} skipped`}
            </span>
            <button onClick={()=>setImportResult(null)} style={{ background:'none',border:'none',
              color:'var(--tx3)',cursor:'pointer',fontSize:16,lineHeight:1,padding:2 }}>×</button>
          </div>
          {(importResult.warnings?.length > 0 || importResult.errors?.length > 0) && (
            <details style={{ marginTop:4 }}>
              <summary style={{ cursor:'pointer', color:'var(--tx3)', fontSize:11 }}>
                {(importResult.warnings?.length||0)+(importResult.errors?.length||0)} warning{(importResult.warnings?.length||0)+(importResult.errors?.length||0)===1?'':'s'}
              </summary>
              <ul style={{ margin:'6px 0 0 16px', padding:0, color:'var(--tx2)', fontSize:11, lineHeight:1.7 }}>
                {[...(importResult.errors||[]),...(importResult.warnings||[])].map((w,i)=>(
                  <li key={i}>{w}</li>
                ))}
              </ul>
            </details>
          )}
        </div>
      )}

      {loading && (
        <div style={{ padding:40, textAlign:'center', color:'var(--tx3)',
                      fontFamily:'var(--mono)', fontSize:12 }}>Loading…</div>
      )}

      {!loading && tab==='entries' && (
        <div style={sectionStyle}>
          <div style={innerStyle}>
            {showForm && (
              <TIEntryForm
                key={editing?.id||'new'}
                initial={editing}
                role={role}
                onSaved={()=>{ setShowForm(false); setEditing(null); load(); }}
                onCancel={()=>{ setShowForm(false); setEditing(null); }}
              />
            )}

            {entries.length === 0 && !showForm && (
              <div style={{ ...cardStyle, textAlign:'center', padding:'32px 20px', color:'var(--tx3)' }}>
                <div style={{ fontSize:13, marginBottom:8 }}>No threat intel entries yet</div>
                <div style={{ fontSize:11 }}>Add entries manually or import a .htf file</div>
              </div>
            )}

            {entries.map(e => (
              <div key={e.id} style={{ ...cardStyle, position:'relative' }}>
                {delId===e.id ? (
                  <div style={{ display:'flex', alignItems:'center', gap:10, flexWrap:'wrap' }}>
                    <span style={{ fontSize:12, color:'var(--danger,#f05454)' }}>Delete this entry?</span>
                    <button onClick={()=>doDelete(e.id)} style={{ padding:'3px 10px', background:'none',
                      border:'1px solid var(--danger,#f05454)', borderRadius:'var(--radius-sm,4px)',
                      color:'var(--danger,#f05454)', cursor:'pointer', fontSize:11 }}>Delete</button>
                    <button onClick={()=>setDelId(null)} style={{ padding:'3px 10px', background:'none',
                      border:'1px solid var(--ln)', borderRadius:'var(--radius-sm,4px)',
                      color:'var(--tx3)', cursor:'pointer', fontSize:11 }}>Cancel</button>
                  </div>
                ) : (
                  <>
                    <div style={{ display:'flex', alignItems:'flex-start', gap:10, flexWrap:'wrap' }}>
                      <div style={{ flex:1, minWidth:0 }}>
                        <div style={{ display:'flex', alignItems:'center', gap:8, flexWrap:'wrap', marginBottom:6 }}>
                          {e.sig_id && (
                            <span style={{ fontFamily:'var(--mono)', fontSize:11, fontWeight:600,
                              color:'var(--accent)', background:'rgba(99,102,241,.1)',
                              padding:'1px 7px', borderRadius:20, border:'1px solid rgba(99,102,241,.2)' }}>
                              SID {e.sig_id}
                            </span>
                          )}
                          {e.category && (
                            <span style={{ fontFamily:'var(--mono)', fontSize:11,
                              color:'var(--tx2)', background:'var(--s2)',
                              padding:'1px 7px', borderRadius:20, border:'1px solid var(--ln)' }}>
                              {e.category}
                            </span>
                          )}
                          {e.sig_msg && (
                            <span style={{ fontSize:12, fontWeight:500, color:'var(--tx1)' }}>
                              {e.sig_msg}
                            </span>
                          )}
                          <span style={{ fontSize:10, color:'var(--tx3)', marginLeft:'auto', whiteSpace:'nowrap' }}>
                            {fmtDate(e.updated_at)}
                          </span>
                        </div>
                        <div style={{ fontSize:12, color:'var(--tx2)', lineHeight:1.7, whiteSpace:'pre-wrap',
                                      marginBottom: (e.tags?.length||e.refs?.length) ? 8 : 0 }}>
                          {e.explanation}
                        </div>
                        <div style={{ display:'flex', gap:6, flexWrap:'wrap', alignItems:'center' }}>
                          {(e.tags||[]).map(t=>(
                            <span key={t} style={{ fontSize:10, padding:'1px 7px',
                              background:'var(--s2)', border:'1px solid var(--ln)',
                              borderRadius:20, color:'var(--tx3)', fontFamily:'var(--mono)' }}>
                              {t}
                            </span>
                          ))}
                          {(e.refs||[]).map(r=>(
                            <a key={r} href={r} target="_blank" rel="noopener noreferrer"
                               style={{ fontSize:10, color:'var(--accent)', fontFamily:'var(--mono)',
                                        textDecoration:'none', wordBreak:'break-all' }}>
                              {r}
                            </a>
                          ))}
                        </div>
                      </div>
                      {canWrite && (
                        <div style={{ display:'flex', gap:5, flexShrink:0 }}>
                          <button onClick={()=>{setEditing(e);setShowForm(true);}}
                            style={{ padding:'3px 9px', background:'none',
                              border:'1px solid var(--ln)', borderRadius:'var(--radius-sm,4px)',
                              color:'var(--tx2)', cursor:'pointer', fontSize:11 }}>Edit</button>
                          <button onClick={()=>setDelId(e.id)}
                            style={{ padding:'3px 9px', background:'none',
                              border:'1px solid var(--ln)', borderRadius:'var(--radius-sm,4px)',
                              color:'var(--tx3)', cursor:'pointer', fontSize:11 }}>✕</button>
                        </div>
                      )}
                    </div>
                  </>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {!loading && tab==='gaps' && (
        <div style={sectionStyle}>
          <div style={innerStyle}>
            <div style={{ fontSize:11, color:'var(--tx3)', marginBottom:14, lineHeight:1.6 }}>
              Top signatures firing without any intel entry. Click a row to create one.
            </div>
            {gaps.length===0 ? (
              <div style={{ ...cardStyle, textAlign:'center', padding:'24px', color:'var(--tx3)', fontSize:12 }}>
                All firing signatures have intel entries — great coverage!
              </div>
            ) : gaps.map(g=>(
              <div key={g.sig_id} style={{ ...cardStyle, cursor: canWrite?'pointer':'default',
                    display:'flex', alignItems:'center', gap:12, flexWrap:'wrap' }}
                   onClick={()=>{ if(!canWrite) return;
                     setEditing({ sig_id:g.sig_id, sig_msg:g.sig_msg,
                                  category:'', explanation:'', tags:[], refs:[] });
                     setShowForm(true); setTab('entries'); }}>
                <span style={{ fontFamily:'var(--mono)', fontSize:11, color:'var(--accent)',
                  background:'rgba(99,102,241,.1)', padding:'1px 7px', borderRadius:20,
                  border:'1px solid rgba(99,102,241,.2)', flexShrink:0 }}>
                  SID {g.sig_id}
                </span>
                <span style={{ fontSize:12, color:'var(--tx1)', flex:1, minWidth:0 }}>{g.sig_msg}</span>
                <span style={{ fontFamily:'var(--mono)', fontSize:11, color:'var(--tx3)', flexShrink:0 }}>
                  {g.count} alert{g.count===1?'':'s'}
                </span>
                {canWrite && (
                  <span style={{ fontSize:10, color:'var(--accent)', flexShrink:0 }}>+ Add intel →</span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function AIExplainView({ role }) {
  const [settings,     setSettings]     = useState({ provider:'openai', enabled:false, api_key_set:false });
  const [apiKeyInput,  setApiKeyInput]  = useState('');
  const [loading,      setLoading]      = useState(true);
  const [saving,       setSaving]       = useState(false);
  const [saved,        setSaved]        = useState(false);
  const [err,          setErr]          = useState('');
  const isAdmin = role === 'admin';

  useEffect(() => {
    fetch('/ai-config').then(r=>r.json()).then(d=>{ setSettings(d); setLoading(false); }).catch(()=>setLoading(false));
  }, []);

  async function save() {
    setSaving(true); setErr(''); setSaved(false);
    const body = { provider: settings.provider, enabled: settings.enabled };
    if (apiKeyInput.trim()) body.api_key = apiKeyInput.trim();
    try {
      const r = await fetch('/ai-config', { method:'PUT',
        headers:{'Content-Type':'application/json'}, body:JSON.stringify(body) });
      const d = await r.json();
      if (!r.ok) { setErr(d.error||'Save failed'); return; }
      setSettings({ ...d, api_key_set: d.api_key_set });
      setApiKeyInput('');
      setSaved(true);
      setTimeout(()=>setSaved(false), 2500);
    } catch { setErr('Network error'); }
    finally { setSaving(false); }
  }

  const PROVIDERS = [
    { id:'openai',    label:'OpenAI',    hint:'gpt-4o-mini' },
    { id:'anthropic', label:'Anthropic', hint:'claude-3-5-haiku' },
    { id:'deepseek',  label:'DeepSeek',  hint:'deepseek-chat' },
  ];

  const inp = { width:'100%', padding:'8px 11px', background:'var(--s2)',
    border:'1px solid var(--ln)', borderRadius:'var(--radius-sm,4px)',
    color:'var(--tx1)', fontSize:12, fontFamily:'var(--mono)', outline:'none', boxSizing:'border-box' };
  const lbl = { fontSize:9, fontWeight:600, letterSpacing:'.09em', textTransform:'uppercase',
    color:'var(--tx3)', display:'block', marginBottom:6 };

  if (loading) return <div style={{ padding:32, color:'var(--tx3)', fontFamily:'var(--mono)', fontSize:12 }}>Loading…</div>;

  const providerHint = PROVIDERS.find(p=>p.id===settings.provider)?.hint || '';

  return (
    <div style={{ overflowY:'auto', flex:1 }}>
      <div style={{ padding:'20px 24px', maxWidth:760 }}>

        {/* Banner */}
        <div style={{ marginBottom:20, padding:'12px 16px', fontSize:12, color:'var(--tx2)',
                      lineHeight:1.7, background:'rgba(99,102,241,.08)',
                      borderRadius:'var(--radius-md,6px)', border:'1px solid rgba(99,102,241,.2)' }}>
          <strong style={{ color:'var(--accent)' }}>AI Explanation</strong> generates an executive
          summary for every new alert automatically. When enabled, each alert's
          {' '}<strong style={{ color:'var(--tx1)' }}>Explain</strong> dialog shows an AI Summary tab
          with a short, actionable analysis. Configure your provider and API key below.
        </div>

        {/* Enable toggle */}
        <div style={{ background:'var(--s1)', border:'1px solid var(--ln)',
                      borderRadius:'var(--radius-lg,10px)', padding:'16px 20px', marginBottom:14 }}>
          <div style={{ display:'flex', alignItems:'center', gap:12 }}>
            <div style={{ flex:1 }}>
              <div style={{ fontWeight:500, fontSize:13, color:'var(--tx1)', marginBottom:2 }}>AI Explanation</div>
              <div style={{ fontSize:11, color:'var(--tx3)' }}>
                Auto-explain new alerts and show AI Summary in the Explain dialog
              </div>
            </div>
            {isAdmin ? (
              <button
                onClick={()=>{ setSettings(s=>({...s, enabled:!s.enabled})); }}
                style={{
                  width:44, height:24, borderRadius:12, border:'none', cursor:'pointer', flexShrink:0,
                  background: settings.enabled ? 'var(--accent)' : 'var(--s3)',
                  position:'relative', transition:'background .2s',
                }}>
                <div style={{
                  position:'absolute', top:3, left: settings.enabled ? 23 : 3,
                  width:18, height:18, borderRadius:'50%', background:'white',
                  transition:'left .2s', boxShadow:'0 1px 3px rgba(0,0,0,.3)',
                }}/>
              </button>
            ) : (
              <span style={{ fontSize:11, fontFamily:'var(--mono)',
                color: settings.enabled ? 'var(--accent)' : 'var(--tx3)' }}>
                {settings.enabled ? 'Enabled' : 'Disabled'}
              </span>
            )}
          </div>
        </div>

        {/* Provider & Key */}
        <div style={{ background:'var(--s1)', border:'1px solid var(--ln)',
                      borderRadius:'var(--radius-lg,10px)', padding:'16px 20px', marginBottom:14 }}>
          <div style={{ fontSize:12, fontWeight:500, color:'var(--tx1)', marginBottom:14 }}>Provider Settings</div>

          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:14, marginBottom:14 }}>
            <div>
              <label style={lbl}>AI Provider</label>
              <select
                disabled={!isAdmin}
                value={settings.provider}
                onChange={e=>setSettings(s=>({...s, provider:e.target.value}))}
                style={{ ...inp, cursor: isAdmin ? 'pointer' : 'default' }}>
                {PROVIDERS.map(p=>(
                  <option key={p.id} value={p.id}>{p.label} ({p.hint})</option>
                ))}
              </select>
            </div>
            <div>
              <label style={lbl}>
                API Key
                {settings.api_key_set && (
                  <span style={{ marginLeft:6, color:'var(--success,#4caf82)',
                    fontFamily:'var(--mono)', letterSpacing:0, textTransform:'none' }}>✓ key saved</span>
                )}
              </label>
              <input
                type="password"
                disabled={!isAdmin}
                placeholder={settings.api_key_set ? '••••••••••• (leave blank to keep)' : 'sk-…  or  deepseek-…'}
                value={apiKeyInput}
                onChange={e=>setApiKeyInput(e.target.value)}
                style={{ ...inp, cursor: isAdmin ? 'text' : 'default' }}
              />
            </div>
          </div>

          <div style={{ fontSize:11, color:'var(--tx3)', marginBottom:14 }}>
            API key is stored encrypted in the config database and can also be set in
            {' '}<code style={{ fontFamily:'var(--mono)', background:'var(--s2)',
              padding:'1px 5px', borderRadius:3 }}>/etc/heimdall/heimdall.conf</code>.
            The UI setting takes precedence.
          </div>

          {!isAdmin && (
            <div style={{ fontSize:11, color:'var(--tx3)', fontStyle:'italic' }}>
              Only admins can modify AI settings.
            </div>
          )}

          {err && (
            <div style={{ marginBottom:10, padding:'7px 11px', fontSize:12,
              background:'rgba(240,84,84,.1)', border:'1px solid var(--danger,#f05454)',
              borderRadius:'var(--radius-sm,4px)', color:'var(--danger,#f05454)' }}>{err}</div>
          )}

          {isAdmin && (
            <div style={{ display:'flex', gap:10, justifyContent:'flex-end', alignItems:'center' }}>
              {saved && (
                <span style={{ fontSize:11, color:'var(--success,#4caf82)', fontFamily:'var(--mono)' }}>
                  ✓ Settings saved
                </span>
              )}
              <button onClick={save} disabled={saving} style={{ padding:'6px 20px',
                border:'1px solid var(--accent)', borderRadius:'var(--radius-sm,4px)',
                background:'transparent', color:'var(--accent)', fontSize:12,
                cursor:saving?'wait':'pointer' }}>
                {saving ? 'Saving…' : 'Save Settings'}
              </button>
            </div>
          )}
        </div>

        {/* Model info */}
        <div style={{ background:'var(--s1)', border:'1px solid var(--ln)',
                      borderRadius:'var(--radius-lg,10px)', padding:'16px 20px' }}>
          <div style={{ fontSize:12, fontWeight:500, color:'var(--tx1)', marginBottom:10 }}>Models Used</div>
          <div style={{ display:'grid', gap:8 }}>
            {PROVIDERS.map(p=>(
              <div key={p.id} style={{ display:'flex', alignItems:'center', gap:10,
                opacity: settings.provider===p.id ? 1 : .45 }}>
                <div style={{ width:8, height:8, borderRadius:'50%', flexShrink:0,
                  background: settings.provider===p.id ? 'var(--accent)' : 'var(--tx3)' }}/>
                <span style={{ fontFamily:'var(--mono)', fontSize:11, color:'var(--tx1)' }}>{p.label}</span>
                <span style={{ fontFamily:'var(--mono)', fontSize:11, color:'var(--tx3)' }}>→ {p.hint}</span>
                {settings.provider===p.id && (
                  <span style={{ marginLeft:'auto', fontSize:9, fontFamily:'var(--mono)',
                    textTransform:'uppercase', letterSpacing:'.07em',
                    color:'var(--accent)', border:'1px solid rgba(99,102,241,.3)',
                    borderRadius:20, padding:'1px 7px' }}>Active</span>
                )}
              </div>
            ))}
          </div>
        </div>

      </div>
    </div>
  );
}


// ── ReplayFlushPanel — shared across all skins ───────────────────────────────
function ReplayFlushPanel({ onFlushed }) {
  const [replay,    setReplay]    = useState({ running:false, done:false, inserted:0, skipped:0, total:0, error:null });
  const [flushing,  setFlushing]  = useState(false);
  const [flushDone, setFlushDone] = useState(null);
  const [showFlushConfirm, setShowFlushConfirm] = useState(false);
  const pollRef = React.useRef(null);

  // Poll replay status while running
  React.useEffect(() => {
    if (replay.running) {
      pollRef.current = setInterval(async () => {
        try {
          const d = await fetch('/replay/status').then(r => r.json());
          setReplay(d);
          if (!d.running) clearInterval(pollRef.current);
        } catch {}
      }, 1000);
    }
    return () => clearInterval(pollRef.current);
  }, [replay.running]);

  async function startReplay() {
    const r = await fetch('/replay', { method: 'POST' });
    const d = await r.json();
    if (d.ok) setReplay(s => ({ ...s, running: true, done: false, error: null, inserted: 0, skipped: 0, total: 0 }));
    else alert(d.error || 'Could not start replay');
  }

  async function doFlush() {
    setShowFlushConfirm(false);
    setFlushing(true); setFlushDone(null);
    try {
      const r = await fetch('/flush', { method: 'POST' });
      const d = await r.json();
      if (d.ok) {
        const tot = Object.values(d.deleted).reduce((a, b) => a + b, 0);
        setFlushDone(`Flushed ${tot.toLocaleString()} records`);
        if (onFlushed) onFlushed();
      }
    } catch { setFlushDone('Error — check connection'); }
    setFlushing(false);
  }

  const cardStyle = {
    background:'var(--s1)', border:'1px solid var(--ln)',
    borderRadius:'var(--radius-lg,10px)', marginBottom:12, overflow:'hidden',
  };
  const hdrStyle = {
    padding:'10px 16px', background:'var(--s2)', borderBottom:'1px solid var(--ln)',
    fontSize:11, fontWeight:600, color:'var(--tx1)', letterSpacing:'.06em',
    textTransform:'uppercase', display:'flex', alignItems:'center', gap:8,
  };
  const bodyStyle = { padding:'14px 16px' };
  const desc = { fontSize:12, color:'var(--tx2)', lineHeight:1.65, marginBottom:12 };
  const btnStyle = (color, disabled) => ({
    padding:'6px 16px', border:`1px solid ${color}`, borderRadius:'var(--radius-sm,4px)',
    background:'transparent', color, fontSize:12, cursor: disabled ? 'not-allowed' : 'pointer',
    opacity: disabled ? .5 : 1,
  });

  return (
    <>
      {/* Replay card */}
      <div style={cardStyle}>
        <div style={hdrStyle}>
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 .49-3.87"/>
          </svg>
          Replay eve.json
        </div>
        <div style={bodyStyle}>
          <div style={desc}>
            Re-read <code style={{fontFamily:'var(--mono)',fontSize:11}}>eve.json</code> from the
            beginning and insert any events missed while Heimdall was down. Runs in the background —
            the dashboard stays usable while it works.
          </div>
          {replay.running && (
            <div style={{marginBottom:10, padding:'8px 12px', background:'rgba(99,102,241,.08)',
                border:'1px solid rgba(99,102,241,.25)', borderRadius:'var(--radius-sm,4px)',
                fontSize:12, fontFamily:'var(--mono)', color:'var(--accent)'}}>
              <span style={{marginRight:8}}>⟳</span>
              Running… {replay.total.toLocaleString()} lines read &nbsp;·&nbsp;
              {replay.inserted.toLocaleString()} inserted &nbsp;·&nbsp;
              {replay.skipped.toLocaleString()} skipped
            </div>
          )}
          {replay.done && !replay.running && (
            <div style={{marginBottom:10, padding:'8px 12px',
                background: replay.error ? 'rgba(240,84,84,.08)' : 'rgba(16,185,129,.08)',
                border:`1px solid ${replay.error ? 'rgba(240,84,84,.3)' : 'rgba(16,185,129,.3)'}`,
                borderRadius:'var(--radius-sm,4px)', fontSize:12, fontFamily:'var(--mono)',
                color: replay.error ? 'var(--danger,#f05454)' : 'var(--success,#10b981)'}}>
              {replay.error
                ? `Error: ${replay.error}`
                : `Done — ${replay.total.toLocaleString()} lines · ${replay.inserted.toLocaleString()} inserted · ${replay.skipped.toLocaleString()} skipped`}
            </div>
          )}
          <button style={btnStyle('var(--accent)', replay.running)}
                  disabled={replay.running} onClick={startReplay}>
            {replay.running ? 'Replaying…' : 'Start Replay'}
          </button>
        </div>
      </div>

      {/* Flush card */}
      <div style={cardStyle}>
        <div style={hdrStyle}>
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6m4-6v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/>
          </svg>
          Flush All Records
        </div>
        <div style={bodyStyle}>
          <div style={desc}>
            Delete every alert, flow, DNS query, and HTTP event from the Heimdall database.
            The <code style={{fontFamily:'var(--mono)',fontSize:11}}>eve.json</code> file and Suricata
            are untouched — new events will continue coming in as usual. There is no undo; use
            <strong style={{color:'var(--tx1)'}}> Replay</strong> to re-read records from eve.json.
          </div>
          {flushDone && (
            <div style={{marginBottom:10, padding:'8px 12px', background:'rgba(16,185,129,.08)',
                border:'1px solid rgba(16,185,129,.3)', borderRadius:'var(--radius-sm,4px)',
                fontSize:12, fontFamily:'var(--mono)', color:'var(--success,#10b981)'}}>
              {flushDone}
            </div>
          )}
          {!showFlushConfirm ? (
            <button style={btnStyle('var(--danger,#f05454)', flushing)}
                    disabled={flushing} onClick={() => setShowFlushConfirm(true)}>
              {flushing ? 'Flushing…' : 'Flush All Records'}
            </button>
          ) : (
            <div style={{padding:'10px 14px', background:'rgba(240,84,84,.08)',
                border:'1px solid rgba(240,84,84,.3)', borderRadius:'var(--radius-sm,4px)'}}>
              <div style={{fontSize:12, color:'var(--danger,#f05454)', marginBottom:10, fontWeight:500}}>
                ⚠ This will permanently delete all records. Are you sure?
              </div>
              <div style={{display:'flex', gap:8}}>
                <button style={btnStyle('var(--danger,#f05454)', false)} onClick={doFlush}>Yes, flush everything</button>
                <button style={{...btnStyle('var(--tx3)', false)}} onClick={() => setShowFlushConfirm(false)}>Cancel</button>
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  );
}

function App() {
  const [alerts,         setAlerts]         = useState([]);
  const [alertTotal,     setAlertTotal]     = useState(0);
  const alertOffsetRef = React.useRef(0);
  const [view,           setView]           = useState('alerts');
  const [selectedId,     setSelectedId]     = useState(null);
  const [svFilter,       setSvFilter]       = useState('all');
  const [search,         setSearch]         = useState('');
  const [selectedAlerts, setSelectedAlerts] = useState(new Set());
  const [sparkData,      setSparkData]      = useState(() => Array.from({length:60},()=>Math.floor(Math.random()*3)));
  const [theme,          setTheme]          = useState(() => {
    const s = localStorage.getItem('heimdall-theme');
    if (s) document.documentElement.setAttribute('data-theme', s);
    return s || 'night';
  });
  const [dbStats,   setDbStats]   = useState({ alerts:0, flows:0, dns:0 });
  const [role,      setRole]      = useState('viewer');
  const [username,  setUsername]  = useState('');
  const [connected, setConnected] = useState(false);
  const [showExplain,  setShowExplain]  = useState(false);
  const [explainAlert, setExplainAlert] = useState(null);
  const [aiSettings,     setAiSettings]     = useState({ provider:'openai', enabled:false, api_key_set:false });
  const [aiExplanations, setAiExplanations] = useState({});
  const aiEnabledRef = React.useRef(false);

  // ── Load ─────────────────────────────────────────────────────────────────
  useEffect(() => {
    fetch('/me').then(r=>r.json()).then(d=>{setRole(d.role||'viewer');setUsername(d.username||'');}).catch(()=>{});
    fetch('/alerts?limit=300').then(r=>r.json()).then(d=>{
      const rows=d.alerts||[];
      setAlerts(rows);
      setAlertTotal(d.total||rows.length);
      alertOffsetRef.current=rows.length;
      if(rows.length) setSelectedId(rows[0].id);
    }).catch(()=>{});
    fetch('/health').then(r=>r.json()).then(d=>setDbStats({alerts:d.db?.alerts?.total||0,flows:d.db?.flows?.total||0,dns:d.db?.dns?.total||0})).catch(()=>{});
    fetch('/ai-config').then(r=>r.json()).then(d=>{ setAiSettings(d); aiEnabledRef.current=d.enabled; }).catch(()=>{});
  }, []);

  // ── SSE ───────────────────────────────────────────────────────────────────
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
          if (aiEnabledRef.current) requestAiExplain(a);
        } catch {}
      });
      es.addEventListener('ping', ()=>{});
      es.onopen  = () => setConnected(true);
      es.onerror = () => { setConnected(false); es.close(); setTimeout(connect,3000); };
    }
    connect();
    return () => es?.close();
  }, []);

  // ── Sparkline decay ────────────────────────────────────────────────────────
  useEffect(() => {
    const id = setInterval(() => {
      setSparkData(prev=>[...prev.slice(1),Math.max(0,prev[prev.length-1]-1+Math.floor(Math.random()*2))]);
    }, 4000);
    return () => clearInterval(id);
  }, []);

  // ── AI explain helper ────────────────────────────────────────────────────
  function requestAiExplain(alert) {
    const id = alert.id;
    if (!id) return;
    setAiExplanations(prev => {
      if (prev[id]?.text || prev[id]?.loading) return prev;
      return { ...prev, [id]: { loading:true, text:null, error:null } };
    });
    fetch('/ai-explain', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ alert }),
    })
      .then(r => r.json())
      .then(d => {
        setAiExplanations(prev => ({
          ...prev,
          [id]: d.explanation
            ? { loading:false, text:d.explanation, error:null }
            : { loading:false, text:null, error:d.error||'Unknown error' },
        }));
      })
      .catch(() => {
        setAiExplanations(prev => ({
          ...prev,
          [id]: { loading:false, text:null, error:'Network error' },
        }));
      });
  }

  React.useEffect(() => { aiEnabledRef.current = aiSettings.enabled; }, [aiSettings.enabled]);

  // ── Load More alerts ─────────────────────────────────────────────────────
  async function loadMoreAlerts() {
    const offset = alertOffsetRef.current;
    try {
      const d = await fetch(`/alerts?limit=300&offset=${offset}`).then(r => r.json());
      const rows = d.alerts || [];
      setAlerts(prev => {
        const ids = new Set(prev.map(a => a.id));
        return [...prev, ...rows.filter(a => !ids.has(a.id))];
      });
      setAlertTotal(d.total || 0);
      alertOffsetRef.current = offset + rows.length;
    } catch {}
  }

  function applyTheme(t) { setTheme(t); document.documentElement.setAttribute('data-theme',t); localStorage.setItem('heimdall-theme',t); }
  async function handleLogout() { try { await fetch('/logout',{method:'POST'}); } catch {} window.location.href='/login'; }

  // ── Bulk triage ────────────────────────────────────────────────────────────
  async function bulkSetStatus(status) {
    const ids = [...selectedAlerts];
    await fetch('/alerts/bulk-status', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ alert_ids:ids, status }),
    });
    setAlerts(prev => prev.map(a => selectedAlerts.has(a.id) ? {...a, status} : a));
    setSelectedAlerts(new Set());
  }

  const selectedAlert = alerts.find(a => a.id === selectedId) || null;

  return (
    <div className="shell">

      {/* ── Topbar ── */}
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
          {['alerts','flows','dns','charts','threat-intel','ai-explain','settings'].map(v => (
            <button key={v} className={`nav-pill${view===v?' active':''}`} onClick={()=>{ setView(v); if(v!==view){ alertOffsetRef.current=0; } }}>
              {({'alerts':'Alerts','flows':'Flows','dns':'DNS','charts':'Charts','threat-intel':'Threat Intel','ai-explain':'AI Explain','settings':'Settings'})[v]||v}
            </button>
          ))}
        </nav>

        <div className="tb-right">
          <div style={{ position:'relative' }}><ThemePicker theme={theme} onChange={applyTheme}/></div>
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

      {/* ── Bento strip (alerts view only) ── */}
      {view === 'alerts' && <BentoStrip alerts={alerts} dbStats={dbStats} sparkData={sparkData}/>}

      {/* ── Workspace ── */}
      <div className={`workspace${view==='alerts'?' alerts-view':' full-view'}`}>

        {view === 'alerts' && (
          <>
            <AlertStream
              alerts={alerts} svFilter={svFilter} setSvFilter={setSvFilter}
              search={search} setSearch={setSearch}
              selectedId={selectedId} setSelectedId={setSelectedId}/>

            <DetailPanel alert={selectedAlert} role={role} setAlerts={setAlerts}
              onExplain={a=>{setExplainAlert(a);setShowExplain(true);}}/>

            <IpContextPanel alert={selectedAlert} alerts={alerts}/>
          </>
        )}


          {view==='alerts' && alertTotal>alerts.length && (
            <div style={{textAlign:'center',padding:'12px 0'}}>
              <button onClick={loadMoreAlerts} style={{padding:'6px 18px',
                border:'1px solid var(--ln)',borderRadius:'var(--radius-sm,4px)',
                background:'transparent',color:'var(--tx2)',fontSize:12,cursor:'pointer'}}>
                Load more  <span style={{color:'var(--tx3)',fontSize:11}}>
                  ({alerts.length.toLocaleString()} / {alertTotal.toLocaleString()} loaded)
                </span>
              </button>
            </div>
          )}
        {view !== 'alerts' && (
          <div className="main-view">
            {view === 'flows' && (
              <><div className="main-head"><span className="main-title">Flow events</span></div><FlowsView/></>
            )}
            {view === 'dns' && (
              <><div className="main-head"><span className="main-title">DNS queries</span></div><DNSView/></>
            )}
            {view === 'charts'   && <ChartsView/>}
            {view === 'threat-intel' && <ThreatIntelView role={role}/>}
            {view === 'ai-explain'   && <AIExplainView   role={role}/>}
            {view === 'settings' && (
              <SettingsView theme={theme} setTheme={applyTheme} role={role} username={username} onLogout={handleLogout}
              onDataFlushed={() => { setAlerts([]); setAlertTotal(0); alertOffsetRef.current=0; }}/>
            )}
          </div>
        )}
      </div>

      {/* ── Status bar ── */}
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

      {showExplain && explainAlert && (
        <ExplainDialog
          alert={explainAlert} role={role}
          aiEnabled={aiSettings.enabled}
          aiExplanation={aiExplanations[explainAlert.id]}
          onRequestAiExplain={requestAiExplain}
          onClose={() => setShowExplain(false)}/>
      )}
    </div>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<App/>);

/* eslint-disable */
'use strict';
const { useState, useEffect, useRef, useMemo } = React;

// ── Themes ────────────────────────────────────────────────────────────────────
const THEMES = [
  { id:'night',     label:'Night',          accent:'#58a6e8', dot:'#0a0f1a' },
  { id:'light',     label:'Light',          accent:'#185a9a', dot:'#eef2f8' },
  { id:'midnight',  label:'Midnight Blue',  accent:'#58a6ff', dot:'#0d1117' },
  { id:'solarized', label:'Solarized Dark', accent:'#268bd2', dot:'#002b36' },
  { id:'dracula',   label:'Dracula',        accent:'#bd93f9', dot:'#191a21' },
  { id:'nord',      label:'Nord',           accent:'#88c0d0', dot:'#2e3440' },
];

function ThemePicker({ theme, onChange }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  const current = THEMES.find(t => t.id === theme) || THEMES[0];
  useEffect(() => {
    function h(e) { if (ref.current && !ref.current.contains(e.target)) setOpen(false); }
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

// ── Constants & utils ─────────────────────────────────────────────────────────
const SEV_ORDER = ['critical','high','medium','low','info'];
const SEV_META  = {
  critical:{ color:'var(--sev-critical)', bg:'var(--sev-critical-bg)', label:'CRITICAL' },
  high:    { color:'var(--sev-high)',     bg:'var(--sev-high-bg)',     label:'HIGH'     },
  medium:  { color:'var(--sev-medium)',   bg:'var(--sev-medium-bg)',   label:'MEDIUM'   },
  low:     { color:'var(--sev-low)',      bg:'var(--sev-low-bg)',      label:'LOW'      },
  info:    { color:'var(--sev-info)',     bg:'var(--sev-info-bg)',     label:'INFO'     },
};
const TRIAGE_META = {
  acknowledged:{ label:'Acknowledged', color:'var(--sev-info)',   bg:'var(--sev-info-bg)'   },
  investigating:{ label:'Investigating',color:'var(--sev-medium)', bg:'var(--sev-medium-bg)' },
  closed:       { label:'Closed',       color:'var(--success)',    bg:'var(--success-bg)'    },
};
const ROLE_META     = { admin:{label:'Admin'}, analyst:{label:'Analyst'}, viewer:{label:'Viewer'} };
const ALL_SEVS      = ['critical','high','medium','low','info'];
const WEBHOOK_TYPES = ['slack','discord','generic'];
const CHART_WINDOWS = [{hrs:24,label:'24h'},{hrs:168,label:'7d'},{hrs:720,label:'30d'},{hrs:1440,label:'60d'},{hrs:2160,label:'90d'}];

function fmtAlertTime(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  if (isNaN(d)) return ts;
  const now  = new Date();
  const time = d.toLocaleTimeString([], { hour:'numeric', minute:'2-digit', hour12:true });
  const todayMid = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const yestMid  = new Date(todayMid - 864e5);
  if (d >= todayMid) return time;
  if (d >= yestMid)  return 'Yesterday ' + time;
  return d.toLocaleDateString([], { month:'short', day:'numeric' }) + ' ' + time;
}
function fmtDetailTime(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  if (isNaN(d)) return ts;
  return d.toLocaleDateString([], { month:'short', day:'numeric', year:'numeric' })
    + ' · ' + d.toLocaleTimeString([], { hour:'numeric', minute:'2-digit', hour12:true });
}

// ── Confirm dialog ────────────────────────────────────────────────────────────
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

// ── Threat strip ──────────────────────────────────────────────────────────────
function ThreatStrip({ alerts, dbStats }) {
  const counts = useMemo(() => {
    const c = { critical:0,high:0,medium:0,low:0,info:0,unreviewed:0 };
    alerts.forEach(a => { if (c[a.severity]!==undefined) c[a.severity]++; if (!a.status) c.unreviewed++; });
    return c;
  }, [alerts]);
  const topIp = useMemo(() => {
    const freq = {};
    alerts.forEach(a => { if (a.src_ip) freq[a.src_ip]=(freq[a.src_ip]||0)+1; });
    const ips = Object.entries(freq).sort((a,b) => b[1]-a[1]);
    return ips.length ? { ip:ips[0][0], count:ips[0][1] } : null;
  }, [alerts]);
  const unrevPct = alerts.length ? Math.round(counts.unreviewed/alerts.length*100) : 0;
  const topPct   = topIp && alerts.length ? Math.round(topIp.count/alerts.length*100) : 0;
  return (
    <div className="threat-strip">
      <div className="threat-card">
        <div className="tc-label">TOTAL ALERTS</div>
        <div className="tc-val">{alerts.length}</div>
        <div className="tc-sub">{counts.critical>0?`${counts.critical} critical`:`${counts.high} high`}</div>
        <div className="tc-bar"><div className="tc-fill" style={{ width:`${Math.min(100,alerts.length/2)}%`,background:'var(--accent)' }}/></div>
      </div>
      <div className="threat-card">
        <div className="tc-label">UNREVIEWED</div>
        <div className="tc-val" style={{ color:counts.unreviewed>0?'var(--sev-high)':'var(--success)' }}>{counts.unreviewed}</div>
        <div className="tc-sub">{unrevPct}% of total</div>
        <div className="tc-bar"><div className="tc-fill" style={{ width:`${unrevPct}%`,background:'var(--sev-high)' }}/></div>
      </div>
      <div className="threat-card">
        <div className="tc-label">TOP SOURCE IP</div>
        <div className="tc-val" style={{ fontSize:12,paddingTop:2 }}>{topIp?.ip||'—'}</div>
        <div className="tc-sub">{topIp?`${topIp.count} alerts · ${topPct}%`:'no data'}</div>
        <div className="tc-bar"><div className="tc-fill" style={{ width:`${topPct}%`,background:'var(--sev-info)' }}/></div>
      </div>
      <div className="threat-card">
        <div className="tc-label">BY SEVERITY</div>
        <div style={{ display:'flex',gap:6,alignItems:'flex-end',marginTop:2 }}>
          {SEV_ORDER.slice(0,4).map(s => {
            const m = SEV_META[s];
            const h = alerts.length ? Math.max(3,Math.round(counts[s]/alerts.length*28)) : 3;
            return (
              <div key={s} title={`${m.label}: ${counts[s]}`} style={{ display:'flex',flexDirection:'column',alignItems:'center',gap:2 }}>
                <div style={{ width:14,height:h,background:m.color,borderRadius:'1px 1px 0 0',opacity:counts[s]>0?1:0.15 }}/>
                <div style={{ fontSize:8,color:m.color,fontFamily:'var(--mono)' }}>{counts[s]}</div>
              </div>
            );
          })}
        </div>
      </div>
      <div className="threat-card">
        <div className="tc-label">DB EVENTS</div>
        <div className="tc-val" style={{ fontSize:13,paddingTop:1 }}>{dbStats.flows.toLocaleString()}</div>
        <div className="tc-sub">{dbStats.dns} dns · {dbStats.alerts.toLocaleString()} alerts</div>
        <div className="tc-bar"><div className="tc-fill" style={{ width:'70%',background:'var(--tx4)' }}/></div>
      </div>
    </div>
  );
}

// ── Trend strip ───────────────────────────────────────────────────────────────
function TrendStrip({ data }) {
  const max = Math.max(...data, 1);
  return (
    <div className="trend-strip">
      <div className="trend-label">60s VOLUME</div>
      {data.map((v,i) => {
        const h  = Math.max(2, Math.round((v/max)*28));
        const bg = v>max*.75?'var(--sev-critical)':v>max*.45?'var(--sev-high)':'var(--s4)';
        return <div key={i} className="t-bar" style={{ height:h,background:bg }}/>;
      })}
    </div>
  );
}

// ── Inline detail (expands below each row) ────────────────────────────────────
function InlineDetail({ alert:a, role }) {
  const [meta,    setMeta]    = useState(null);
  const [newNote, setNewNote] = useState('');
  const [saving,  setSaving]  = useState(false);
  const canTriage = role==='admin'||role==='analyst';
  const m = SEV_META[a.severity]||SEV_META.info;

  useEffect(() => {
    fetch(`/alerts/${encodeURIComponent(a.id)}/meta`)
      .then(r=>r.json()).then(setMeta)
      .catch(()=>setMeta({ status:null,notes:[],activity:[] }));
  }, [a.id]);

  async function setStatus(status) {
    if (!canTriage) return;
    const next = meta?.status===status ? null : status;
    await fetch(`/alerts/${encodeURIComponent(a.id)}/status`,{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({ status:next }),
    });
    a.status = next;
    const r2 = await fetch(`/alerts/${encodeURIComponent(a.id)}/meta`);
    setMeta(await r2.json());
  }

  async function addNote() {
    if (!newNote.trim()||!canTriage) return;
    setSaving(true);
    const r = await fetch(`/alerts/${encodeURIComponent(a.id)}/notes`,{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({ note:newNote.trim() }),
    });
    if (r.ok) {
      const n = await r.json();
      setMeta(prev => ({ ...prev,notes:[...(prev?.notes||[]),n] }));
      setNewNote('');
    }
    setSaving(false);
  }

  return (
    <div className="inline-detail">
      {/* Col 1 — Network + Signature + Timestamp */}
      <div className="id-col">
        <div className="id-section-title">Network</div>
        <div className="id-kv"><span className="id-key">Source</span>      <span className="id-val">{a.src_ip}:{a.src_port}</span></div>
        <div className="id-kv"><span className="id-key">Destination</span> <span className="id-val">{a.dst_ip}:{a.dst_port}</span></div>
        <div className="id-kv"><span className="id-key">Protocol</span>    <span className="id-val">{a.proto}</span></div>
        <div className="id-kv"><span className="id-key">Interface</span>   <span className="id-val">{a.iface||'—'}</span></div>
        <div className="id-kv"><span className="id-key">Flow ID</span>     <span className="id-val">{a.flow_id||'—'}</span></div>
        <div className="id-section-title id-section-gap">Signature</div>
        <div className="id-kv"><span className="id-key">SID</span>      <span className="id-val">{a.sig_id}</span></div>
        <div className="id-kv"><span className="id-key">Category</span> <span className="id-val">{a.category}</span></div>
        <div className="id-kv"><span className="id-key">Severity</span> <span className="id-val" style={{ color:m.color }}>{a.severity?.toUpperCase()}</span></div>
        <div className="id-section-title id-section-gap">Timestamp</div>
        <div className="id-kv"><span className="id-key">Time</span> <span className="id-val" style={{ color:'var(--tx1)' }}>{fmtDetailTime(a.ts)}</span></div>
      </div>

      {/* Col 2 — Triage + Notes */}
      <div className="id-col">
        <div className="id-section-title">Triage</div>
        {canTriage ? (
          <>
            <div className="triage-list">
              {['acknowledged','investigating','closed'].map(s => {
                const act = meta?.status===s;
                const cls = act ? `triage-btn active-${s.slice(0,3)}` : 'triage-btn';
                return (
                  <button key={s} className={cls} onClick={() => setStatus(s)}>
                    [{act?'x':' '}] {TRIAGE_META[s].label}
                  </button>
                );
              })}
            </div>
            <div className="id-section-title id-section-gap">Notes ({meta?.notes?.length||0})</div>
            {meta?.notes?.map((n,i) => (
              <div key={i} className="note-entry">
                <div className="note-entry-meta">{n.username} · {fmtDetailTime(new Date(n.created_at*1000).toISOString())}</div>
                <div className="note-entry-text">{n.note}</div>
              </div>
            ))}
            <div className="note-form">
              <textarea className="note-input" rows={2} placeholder="Add analyst note… (Ctrl+Enter)"
                value={newNote} onChange={e=>setNewNote(e.target.value)}
                onKeyDown={e=>{ if(e.key==='Enter'&&e.ctrlKey) addNote(); }}/>
              <button className="note-submit" onClick={addNote} disabled={saving||!newNote.trim()}>
                {saving?'SAVING…':'ADD NOTE'}
              </button>
            </div>
          </>
        ) : (
          <div className="id-empty">Read-only — analyst role required</div>
        )}
      </div>

      {/* Col 3 — Activity log */}
      <div className="id-col">
        <div className="id-section-title">Activity Log</div>
        {meta===null && <div className="id-empty">Loading…</div>}
        {meta!==null && (!meta.activity||meta.activity.length===0) && <div className="id-empty">No activity yet</div>}
        {meta?.activity?.length>0 && (
          <div className="act-log">
            {[...meta.activity].reverse().map((ev,i) => (
              <div key={i} className="act-log-item">
                <div className={`act-log-dot${i===0?' latest':''}`}/>
                <div>
                  <div className="act-log-action">{ev.action}</div>
                  <div className="act-log-meta">{ev.username} · {fmtDetailTime(new Date(ev.created_at*1000).toISOString())}</div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Alert row ─────────────────────────────────────────────────────────────────
function AlertRow({ alert:a, expanded, onToggle, role, selected, onSelect }) {
  const m = SEV_META[a.severity]||SEV_META.info;
  const canTriage = role==='admin'||role==='analyst';
  const sCls = a.status==='acknowledged'?'ack':a.status==='investigating'?'inv':a.status==='closed'?'clo':'';
  return (
    <div className="alert-row-wrap">
      <div className={`alert-row${expanded?' expanded':''}${a._new?' new-in':''}${selected?' row-selected':''}`} onClick={onToggle}>
        {canTriage ? (
          <div className="ar-check" onClick={e=>{ e.stopPropagation(); onSelect(a.id); }}>
            <div className={`ar-checkbox${selected?' checked':''}`}>
              {selected && <svg width="8" height="8" viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="2.2"><path d="M1.5 5l2.5 2.5L8.5 2"/></svg>}
            </div>
          </div>
        ) : <div/>}
        <div className="ar-bar" style={{ background:m.color }}/>
        <div className="ar-time">{fmtAlertTime(a.ts)}</div>
        <div className={`ar-sev ${a.severity}`}>{m.label}</div>
        <div className="ar-msg">{a.sig_msg}</div>
        <div className="ar-net">{a.src_ip}:{a.src_port} → {a.dst_ip}:{a.dst_port}</div>
        <div className="ar-status-cell">{a.status&&<span className={`ar-status ${sCls}`}>{a.status}</span>}</div>
      </div>
      {expanded && <InlineDetail alert={a} role={role}/>}
    </div>
  );
}

// ── Bulk Triage Command Bar ────────────────────────────────────────────────────
function BulkTriageBar({ selectedIds, alerts, onAction, onClear }) {
  const selected = alerts.filter(a => selectedIds.has(a.id));
  const sevBreakdown = selected.reduce((acc, a) => {
    acc[a.severity] = (acc[a.severity]||0)+1; return acc;
  }, {});
  const prominent = ['critical','high','medium','low'].filter(s => sevBreakdown[s]);
  return (
    <div className={`bulk-bar${selectedIds.size>0?' visible':''}`}>
      <div className="bulk-bar-inner">
        <div className="bulk-bar-info">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="9 11 12 14 22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>
          <span className="bulk-count">{selectedIds.size} selected</span>
          {prominent.map(s => (
            <span key={s} className="bulk-sev-tag" style={{ color:SEV_META[s].color, borderColor:SEV_META[s].color }}>
              {sevBreakdown[s]}{s[0].toUpperCase()}
            </span>
          ))}
        </div>
        <div className="bulk-bar-divider"/>
        <div className="bulk-bar-actions">
          <button className="bulk-act-btn ack" onClick={()=>onAction('acknowledged')}>
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="20 6 9 17 4 12"/></svg>
            ACK
          </button>
          <button className="bulk-act-btn inv" onClick={()=>onAction('investigating')}>
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            INVESTIGATE
          </button>
          <button className="bulk-act-btn clo" onClick={()=>onAction('closed')}>
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
            CLOSE
          </button>
        </div>
        <div className="bulk-bar-divider"/>
        <button className="bulk-clear-btn" onClick={onClear} title="Clear selection">
          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        </button>
      </div>
    </div>
  );
}

// ── Alert table ───────────────────────────────────────────────────────────────
function AlertTable({ alerts, svFilter, setSvFilter, search, setSearch, role, setAlerts }) {
  const [expandedId,     setExpandedId]     = useState(null);
  const [showUnreviewed, setShowUnreviewed] = useState(false);
  const [selectedIds,    setSelectedIds]    = useState(new Set());
  const canTriage = role==='admin'||role==='analyst';

  const counts = useMemo(() => {
    const c={all:alerts.length,critical:0,high:0,medium:0,low:0,info:0};
    alerts.forEach(a=>{if(c[a.severity]!==undefined)c[a.severity]++;});
    return c;
  }, [alerts]);
  const filtered = useMemo(() => alerts.filter(a => {
    if (svFilter!=='all'&&a.severity!==svFilter) return false;
    if (showUnreviewed&&a.status) return false;
    if (search) {
      const q=search.toLowerCase();
      if (!a.sig_msg?.toLowerCase().includes(q)&&!a.src_ip?.includes(q)&&!a.dst_ip?.includes(q)) return false;
    }
    return true;
  }), [alerts,svFilter,search,showUnreviewed]);

  const allSelected = filtered.length>0 && filtered.every(a=>selectedIds.has(a.id));

  function toggleSelectAll() {
    if (allSelected) {
      setSelectedIds(prev => { const next=new Set(prev); filtered.forEach(a=>next.delete(a.id)); return next; });
    } else {
      setSelectedIds(prev => { const next=new Set(prev); filtered.forEach(a=>next.add(a.id)); return next; });
    }
  }

  function toggleSelect(id) {
    setSelectedIds(prev => { const next=new Set(prev); next.has(id)?next.delete(id):next.add(id); return next; });
  }

  async function handleBulkAction(status) {
    const ids = [...selectedIds];
    await Promise.all(ids.map(id =>
      fetch(`/alerts/${encodeURIComponent(id)}/status`,{
        method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({ status }),
      })
    ));
    setAlerts(prev=>prev.map(a=>selectedIds.has(a.id)?{...a,status}:a));
    setSelectedIds(new Set());
  }

  return (
    <div className="feed-area" style={{position:'relative'}}>
      <div className="feed-controls">
        <div className="fc-label">SEV</div>
        {['all','critical','high','medium','low'].map(s => {
          const active = svFilter===s;
          const label  = s==='all'?`ALL · ${counts.all}`:`${s.toUpperCase()} · ${counts[s]}`;
          return <div key={s} className={`sev-chip${active?` active-${s}`:''}`} onClick={()=>setSvFilter(s)}>{label}</div>;
        })}
        <input className="feed-search" placeholder="search ip, signature, sid…"
               value={search} onChange={e=>setSearch(e.target.value)}/>
        <div className="fc-spacer"/>
        <button className={`view-toggle${showUnreviewed?' active':''}`}
                onClick={()=>setShowUnreviewed(p=>!p)}>UNREVIEWED ONLY</button>
        {canTriage && (
          <button className={`view-toggle select-all-btn${allSelected?' active':''}`} onClick={toggleSelectAll}>
            {allSelected ? (
              <><svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg> DESELECT ALL</>
            ) : (
              <><svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="18" height="18" rx="2"/><polyline points="9 11 12 14 22 4"/></svg> SELECT ALL</>
            )}
          </button>
        )}
        <div className="feed-count">{filtered.length} events</div>
      </div>
      <div className="feed-table">
        <div className="tbl-header">
          <span/><span/><span>Time</span><span>Sev</span><span>Signature</span>
          <span>Network path</span><span>Status</span>
        </div>
        {!filtered.length && (
          <div className="empty-state">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            No matching alerts
          </div>
        )}
        {filtered.map(a => (
          <AlertRow key={a.id} alert={a}
                    expanded={a.id===expandedId}
                    onToggle={()=>setExpandedId(a.id===expandedId?null:a.id)}
                    role={role}
                    selected={selectedIds.has(a.id)}
                    onSelect={toggleSelect}/>
        ))}
      </div>
      {canTriage && (
        <BulkTriageBar
          selectedIds={selectedIds}
          alerts={alerts}
          onAction={handleBulkAction}
          onClear={()=>setSelectedIds(new Set())}
        />
      )}
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
    <div className="table-view">
      <table className="data-table">
        <thead><tr><th style={{width:80}}>Time</th><th style={{width:150}}>Source</th><th style={{width:150}}>Destination</th><th style={{width:60}}>Proto</th><th style={{width:80}}>App</th><th style={{width:90}}>↑ Bytes</th><th style={{width:90}}>↓ Bytes</th><th>State</th></tr></thead>
        <tbody>{flows.map((f,i)=>(
          <tr key={i}>
            <td>{fmtAlertTime(f.ts)}</td>
            <td className="td-primary">{f.src_ip}:{f.src_port}</td>
            <td>{f.dst_ip}:{f.dst_port}</td>
            <td>{f.proto?.toUpperCase()}</td>
            <td>{f.app_proto||'—'}</td>
            <td>{(f.bytes_toserver||0).toLocaleString()}</td>
            <td>{(f.bytes_toclient||0).toLocaleString()}</td>
            <td style={{color:f.state==='closed'?'var(--tx3)':'var(--success)'}}>{f.state||'—'}</td>
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
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none"
               stroke="var(--sev-info)" strokeWidth="2" strokeLinecap="round">
            <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/>
            <line x1="12" y1="16" x2="12.01" y2="16"/>
          </svg>
        </div>
        <div className="confirm-title" style={{ marginBottom:4 }}>DNS Record Detail</div>
        <div className="confirm-body" style={{ marginBottom:14 }}>
          <span className="dns-rrname" style={{ fontSize:12 }}>{record.rrname||'—'}</span>
        </div>
        <pre style={{
          background:'var(--s2)', border:'1px solid var(--ln)',
          borderRadius:'var(--radius-sm)', padding:'11px 13px',
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
  const [records, setRecords] = useState([]);
  const [loading, setLoading] = useState(true);
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
      <div className="table-view">
        <table className="data-table">
          <thead><tr><th style={{width:80}}>Time</th><th style={{width:130}}>Client</th><th>Query</th><th style={{width:60}}>Type</th><th style={{width:60}}>Dir</th><th style={{width:80}}>RCode</th><th style={{width:55}}>TTL</th></tr></thead>
          <tbody>{records.map((d,i)=>(
            <tr key={i} onClick={()=>setSelected(d)} style={{cursor:'pointer'}} className="row-hover">
              <td>{fmtAlertTime(d.ts)}</td>
              <td className="td-primary">{d.src_ip}</td>
              <td><span className="dns-rrname">{d.rrname||'—'}</span></td>
              <td>{d.rrtype||'—'}</td>
              <td>{d.dns_type||'—'}</td>
              <td style={{color:d.rcode==='NOERROR'?'var(--success)':d.rcode?'var(--danger)':'var(--tx3)'}}>{d.rcode||'—'}</td>
              <td>{d.ttl??'—'}</td>
            </tr>
          ))}</tbody>
        </table>
      </div>
      {selected&&<DNSDetailModal record={selected} onClose={()=>setSelected(null)}/>}
    </>
  );
}

// ── Shared remote data hook ───────────────────────────────────────────────────
function useRemote(url, key) {
  const [data,    setData]    = useState([]);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    fetch(url).then(r=>r.json()).then(d=>{setData(d[key]||[]);setLoading(false);}).catch(()=>setLoading(false));
  }, [url]);
  return [data, loading];
}

// ── Donut chart ───────────────────────────────────────────────────────────────
function DonutChart({ data }) {
  const COLORS=['var(--accent)','var(--sev-high)','var(--sev-medium)','var(--sev-low)','var(--sev-critical)','var(--sev-info)','#a78bfa','#f472b6','#34d399','#fb923c'];
  const total=data.reduce((s,d)=>s+d.count,0)||1;
  const R=70,cx=90,cy=90,sw=22,circ=2*Math.PI*R;
  let offset=0;
  const slices=data.map((d,i)=>{const dash=(d.count/total)*circ;const sl={offset,dash,gap:circ-dash,color:COLORS[i%COLORS.length],label:d.category,count:d.count};offset+=dash;return sl;});
  const [hovered,setHovered]=useState(null);
  return (
    <div style={{display:'flex',gap:20,alignItems:'center',flexWrap:'wrap'}}>
      <svg width="180" height="180" viewBox="0 0 180 180" style={{flexShrink:0}}>
        <circle cx={cx} cy={cy} r={R} fill="none" stroke="var(--s3)" strokeWidth={sw}/>
        {slices.map((sl,i)=>(
          <circle key={i} cx={cx} cy={cy} r={R} fill="none" stroke={sl.color}
                  strokeWidth={hovered===i?sw+4:sw}
                  strokeDasharray={`${sl.dash} ${sl.gap}`}
                  strokeDashoffset={circ/4-sl.offset}
                  style={{cursor:'pointer',transition:'stroke-width .15s',transform:'rotate(-90deg)',transformOrigin:`${cx}px ${cy}px`}}
                  onMouseEnter={()=>setHovered(i)} onMouseLeave={()=>setHovered(null)}/>
        ))}
        <text x={cx} y={cy-6} textAnchor="middle" fill="var(--tx1)" fontSize="18" fontWeight="700" fontFamily="var(--mono)">{total}</text>
        <text x={cx} y={cy+10} textAnchor="middle" fill="var(--tx4)" fontSize="9" letterSpacing="0.08em" fontFamily="var(--mono)">TOTAL</text>
      </svg>
      <div style={{display:'flex',flexDirection:'column',gap:6,flex:1,minWidth:140}}>
        {slices.map((sl,i)=>(
          <div key={i} style={{display:'flex',alignItems:'center',gap:7,opacity:hovered!==null&&hovered!==i?0.35:1,transition:'opacity .15s',cursor:'default'}}
               onMouseEnter={()=>setHovered(i)} onMouseLeave={()=>setHovered(null)}>
            <div style={{width:8,height:8,borderRadius:2,background:sl.color,flexShrink:0}}/>
            <span style={{fontSize:10,color:'var(--tx2)',flex:1,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap',fontFamily:'var(--mono)'}}>{sl.label||'—'}</span>
            <span style={{fontSize:10,color:'var(--tx1)',fontFamily:'var(--mono)',flexShrink:0}}>{sl.count}</span>
            <span style={{fontSize:9,color:'var(--tx3)',flexShrink:0,width:34,textAlign:'right',fontFamily:'var(--mono)'}}>{Math.round(sl.count/total*100)}%</span>
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
  const [chartHrs,setChartHrs]=useState(24);
  function load(hrs){setLoading(true);fetch(`/charts?trend=${hrs}`).then(r=>r.json()).then(d=>{setData(d);setLoading(false);}).catch(()=>setLoading(false));}
  useEffect(()=>{load(chartHrs);},[chartHrs]);
  if (loading) return <div className="empty-state">Loading charts…</div>;
  if (!data)   return <div className="empty-state">No chart data</div>;
  const trendData=data.trend||[],sevData=data.by_severity||[],talkerData=data.top_talkers||[],catData=data.by_category||[];
  const maxTrend=Math.max(...trendData.map(t=>t.count),1);
  const maxSev=Math.max(...sevData.map(x=>x.count),1);
  const maxTalker=Math.max(...talkerData.map(x=>x.count),1);
  const labelEvery=Math.max(1,Math.ceil(trendData.length/8));
  const IP_COLORS=[
    {color:'var(--sev-info)',bg:'var(--sev-info-bg)'},{color:'var(--sev-medium)',bg:'var(--sev-medium-bg)'},
    {color:'var(--accent)',bg:'var(--accent-bg)'},{color:'var(--sev-high)',bg:'var(--sev-high-bg)'},
    {color:'var(--sev-critical)',bg:'var(--sev-critical-bg)'},{color:'var(--sev-low)',bg:'var(--sev-low-bg)'},
  ];
  return (
    <div className="charts-layout">
      <div className="charts-controls">
        <div className="view-tabs" style={{marginLeft:'auto'}}>
          {CHART_WINDOWS.map(w=>(
            <button key={w.hrs} className={`tab-btn${chartHrs===w.hrs?' active':''}`} onClick={()=>setChartHrs(w.hrs)}>{w.label}</button>
          ))}
        </div>
      </div>
      <div className="charts-grid">
        <div className="chart-card wide">
          <div className="chart-card-title">Alert Trend</div>
          <div style={{display:'flex',alignItems:'flex-end',gap:2,height:130,paddingBottom:22,position:'relative'}}>
            {[0.25,0.5,0.75,1].map(pct=>(
              <div key={pct} style={{position:'absolute',left:0,right:0,bottom:22+pct*108,borderTop:'1px dashed var(--ln)',pointerEvents:'none'}}/>
            ))}
            {trendData.map((t,i)=>{
              const h=Math.max(2,Math.round(t.count/maxTrend*108));
              const col=t.count>maxTrend*.75?'var(--sev-critical)':t.count>maxTrend*.45?'var(--sev-high)':'var(--accent)';
              return (
                <div key={i} title={`${t.ts}: ${t.count}`} style={{flex:1,display:'flex',flexDirection:'column',alignItems:'center',justifyContent:'flex-end',position:'relative'}}>
                  <div style={{width:'100%',height:h,background:col,opacity:.85,borderRadius:'2px 2px 0 0',transition:'height .2s'}}/>
                  {i%labelEvery===0&&<div style={{position:'absolute',bottom:-18,fontSize:9,color:'var(--tx4)',whiteSpace:'nowrap',transform:'translateX(-50%)',left:'50%',fontFamily:'var(--mono)'}}>{t.ts}</div>}
                </div>
              );
            })}
          </div>
          <div style={{display:'flex',justifyContent:'space-between',marginTop:4}}>
            <span style={{fontSize:8,color:'var(--tx4)',fontFamily:'var(--mono)'}}>0</span>
            <span style={{fontSize:8,color:'var(--tx4)',fontFamily:'var(--mono)'}}>peak: {maxTrend}</span>
          </div>
        </div>
        <div className="chart-card">
          <div className="chart-card-title">By Severity</div>
          <div className="bar-list">
            {sevData.map(r=>{const m=SEV_META[r.severity]||SEV_META.info;return(
              <div key={r.severity} className="bar-row">
                <span className="bar-label" style={{color:m.color}}>{m.label}</span>
                <div className="bar-track" style={{background:m.bg}}><div className="bar-fill" style={{width:`${Math.round(r.count/maxSev*100)}%`,background:m.color}}/></div>
                <span className="bar-val" style={{color:m.color}}>{r.count}</span>
              </div>
            );})}
          </div>
        </div>
        <div className="chart-card">
          <div className="chart-card-title">Top Source IPs</div>
          <div className="bar-list">
            {talkerData.map((r,i)=>{const c=IP_COLORS[i%IP_COLORS.length];return(
              <div key={r.ip} className="bar-row">
                <span className="bar-label mono" style={{color:c.color}}>{r.ip}</span>
                <div className="bar-track" style={{background:c.bg}}><div className="bar-fill" style={{width:`${Math.round(r.count/maxTalker*100)}%`,background:c.color}}/></div>
                <span className="bar-val" style={{color:c.color}}>{r.count}</span>
              </div>
            );})}
          </div>
        </div>
        <div className="chart-card wide">
          <div className="chart-card-title">By Category</div>
          {catData.length?<DonutChart data={catData}/>:<div className="empty-state" style={{padding:'20px 0'}}>No category data</div>}
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
  function toggleSev(s){setSevs(p=>p.includes(s)?p.filter(x=>x!==s):[...p,s]);}
  async function submit(){
    if(!name.trim()||!url.trim())return;
    const body={name:name.trim(),type,url:url.trim(),severities:sevs,enabled:true};
    const endpoint=editing?`/webhooks/${initial.id}`:'/webhooks';
    const method=editing?'PUT':'POST';
    const res=await fetch(endpoint,{method,headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    if(res.ok){onSave();onClose();}
  }
  return (
    <div className="modal-backdrop" onClick={e=>e.target===e.currentTarget&&onClose()}>
      <div className="modal">
        <div className="modal-title">{editing?'Edit Webhook':'Add Webhook'}</div>
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
  const [role,    setRole]    =useState(initial?.role||'analyst');
  async function submit(){
    if(!editing&&(!username.trim()||!password))return;
    const body=editing?{role}:{username:username.trim(),password,role};
    const endpoint=editing?`/users/${initial.id}`:'/users';
    const method=editing?'PUT':'POST';
    const res=await fetch(endpoint,{method,headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    if(res.ok){onSave();onClose();}
  }
  return (
    <div className="modal-backdrop" onClick={e=>e.target===e.currentTarget&&onClose()}>
      <div className="modal">
        <div className="modal-title">{editing?'Edit User':'Add User'}</div>
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
function SettingsView({ theme, setTheme, role, username, onLogout }) {
  const [users,   setUsers]   =useState([]);
  const [health,  setHealth]  =useState(null);
  const [modal,   setModal]   =useState(null);
  const [whModal, setWhModal] =useState(null);
  const [webhooks,setWebhooks]=useState([]);
  const [testMsg, setTestMsg] =useState({});
  const [confirm, setConfirm] =useState(null);
  const isAdmin = role==='admin';
  async function loadUsers()   {const r=await fetch('/users');   const d=await r.json();setUsers(d.users||[]);}
  async function loadHealth()  {const r=await fetch('/health');  const d=await r.json();setHealth(d);}
  async function loadWebhooks(){const r=await fetch('/webhooks');const d=await r.json();setWebhooks(d.webhooks||[]);}
  useEffect(()=>{loadUsers();loadHealth();if(isAdmin)loadWebhooks();},[]);
  function confirmDeleteUser(u){setConfirm({title:'Delete user',body:`Delete <strong>${u.username}</strong>? This cannot be undone.`,confirmLabel:'Delete user',variant:'danger',onConfirm:async()=>{await fetch(`/users/${u.id}`,{method:'DELETE'});loadUsers();}});}
  function confirmClearData(ep,label,count){setConfirm({title:`Clear all ${label}`,body:`Permanently delete <strong>${count} ${label} records</strong>. Cannot be undone.`,confirmLabel:`Clear ${label}`,variant:'warning',onConfirm:async()=>{await fetch(ep,{method:'DELETE'});loadHealth();}});}
  async function toggleWebhook(wh){await fetch(`/webhooks/${wh.id}`,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:!wh.enabled})});loadWebhooks();}
  function confirmDeleteWebhook(wh){setConfirm({title:'Delete webhook',body:`Delete <strong>${wh.name}</strong>? All configuration will be lost.`,confirmLabel:'Delete webhook',variant:'danger',onConfirm:async()=>{await fetch(`/webhooks/${wh.id}`,{method:'DELETE'});loadWebhooks();}});}
  async function testWebhook(id){
    setTestMsg(p=>({...p,[id]:'Sending…'}));
    const r=await fetch(`/webhooks/${id}/test`,{method:'POST'});
    const d=await r.json();
    setTestMsg(p=>({...p,[id]:d.ok?'✓ Delivered':'✗ '+(d.error||'Failed')}));
    setTimeout(()=>setTestMsg(p=>{const n={...p};delete n[id];return n;}),3000);
  }
  function initials(name){return name.slice(0,2).toUpperCase();}
  return (
    <div className="settings-layout">
      {isAdmin&&(
        <div className="settings-card">
          <div className="settings-card-header"><span className="settings-card-title">Users</span><button className="btn-sm primary" onClick={()=>setModal({})}>Add user</button></div>
          <div className="settings-card-body">
            {users.map(u=>(
              <div key={u.id} className={`user-row${!u.enabled?' user-disabled':''}`}>
                <div className="user-avatar">{initials(u.username)}</div>
                <div className="user-info">
                  <div className="user-name">{u.username}{u.username===username&&<span style={{fontSize:9,color:'var(--tx3)',marginLeft:6}}>(you)</span>}</div>
                  <div className="user-meta">{u.last_login?`Last login: ${new Date(u.last_login*1000).toLocaleDateString()}`:'Never logged in'}</div>
                </div>
                <span className={`role-badge ${u.role}`}>{ROLE_META[u.role]?.label||u.role}</span>
                <button className="btn-sm" onClick={()=>setModal(u)}>Edit</button>
                <button className="btn-sm danger" onClick={()=>confirmDeleteUser(u)}>Delete</button>
              </div>
            ))}
          </div>
        </div>
      )}
      {isAdmin&&(
        <div className="settings-card">
          <div className="settings-card-header"><span className="settings-card-title">Webhooks</span><button className="btn-sm primary" onClick={()=>setWhModal({})}>Add webhook</button></div>
          <div className="settings-card-body">
            {!webhooks.length&&<div style={{color:'var(--tx3)',fontSize:11,fontFamily:'var(--mono)'}}>No webhooks configured.</div>}
            {webhooks.map(wh=>(
              <div key={wh.id} className="wh-settings-card">
                <div className="wh-top"><span className="wh-name">{wh.name}</span><span className="wh-type-badge">{wh.type.toUpperCase()}</span><button className={`wh-toggle${wh.enabled?' on':''}`} onClick={()=>toggleWebhook(wh)}/></div>
                <div className="wh-url">{wh.url}</div>
                <div className="wh-sev">{ALL_SEVS.map(s=>{const m=SEV_META[s];const on=(wh.severities||[]).includes(s);return(<span key={s} className={`wh-sev-pill${on?' on':''}`} style={{color:m.color,background:m.bg,border:`1px solid ${m.color}40`}}>{m.label}</span>);})}</div>
                <div className="wh-meta"><span>Fired {wh.fire_count||0}×</span>{wh.last_fired&&<span>Last: {new Date(wh.last_fired*1000).toLocaleTimeString()}</span>}</div>
                <div className="wh-actions">
                  <button className="btn-sm" onClick={()=>setWhModal(wh)}>Edit</button>
                  <button className="btn-sm" onClick={()=>testWebhook(wh.id)}>{testMsg[wh.id]||'Test'}</button>
                  <button className="btn-sm danger" onClick={()=>confirmDeleteWebhook(wh)}>Delete</button>
                </div>
                {wh.last_error&&<div className="wh-error">Last error: {wh.last_error}</div>}
              </div>
            ))}
          </div>
        </div>
      )}
      <div className="settings-card">
        <div className="settings-card-header"><span className="settings-card-title">Theme</span></div>
        <div className="settings-card-body">
          <div className="theme-grid">
            {THEMES.map(t=>(
              <div key={t.id} className={`theme-tile${theme===t.id?' active':''}`}
                   onClick={()=>{setTheme(t.id);document.documentElement.setAttribute('data-theme',t.id);localStorage.setItem('heimdall-theme',t.id);}}>
                <div style={{display:'flex',gap:3}}><div style={{width:10,height:10,borderRadius:3,background:t.dot,border:'1px solid rgba(0,0,0,.18)'}}/><div style={{width:10,height:10,borderRadius:3,background:t.accent}}/></div>
                <span>{t.label}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
      {isAdmin&&(
        <div className="settings-card">
          <div className="settings-card-header"><span className="settings-card-title">Data management</span></div>
          <div className="settings-card-body">
            {[{label:'Alerts',sub:`${health?.db?.alerts?.total??'—'} records`,ep:'/alerts',count:health?.db?.alerts?.total??0},
              {label:'Flows', sub:`${health?.db?.flows?.total??'—'} records`, ep:'/flows', count:health?.db?.flows?.total??0},
              {label:'DNS events',sub:`${health?.db?.dns?.total??'—'} records`,ep:'/dns',count:health?.db?.dns?.total??0}
            ].map(row=>(
              <div key={row.label} className="data-action-row">
                <div><div className="data-action-info">{row.label}</div><div className="data-action-sub">{row.sub}</div></div>
                <button className="btn-sm danger" onClick={()=>confirmClearData(row.ep,row.label.toLowerCase(),row.count)}>Clear all</button>
              </div>
            ))}
          </div>
        </div>
      )}
      {health&&(
        <div className="settings-card">
          <div className="settings-card-header"><span className="settings-card-title">Server health</span></div>
          <div className="settings-card-body">
            <div className="health-grid">
              {[{l:'ALERTS',v:health.db?.alerts?.total,s:`${health.db?.alerts?.recent} recent`},
                {l:'FLOWS', v:health.db?.flows?.total, s:`${health.db?.flows?.recent} recent`},
                {l:'DNS',   v:health.db?.dns?.total,   s:`${health.db?.dns?.recent} recent`},
                {l:'HTTP',  v:health.db?.http?.total,  s:`${health.db?.http?.recent} recent`},
                {l:'CLIENTS',v:health.clients,          s:'connected'},
              ].map(r=>(
                <div key={r.l} className="health-stat">
                  <div className="health-stat-label">{r.l}</div>
                  <div className="health-stat-value">{(r.v||0).toLocaleString()}</div>
                  <div className="health-stat-sub">{r.s}</div>
                </div>
              ))}
              <div className="health-stat" style={{gridColumn:'span 2'}}>
                <div className="health-stat-label">OLDEST RECORD</div>
                <div className="health-stat-value" style={{fontSize:11}}>{health.db?.oldest?new Date(health.db.oldest).toLocaleDateString():'—'}</div>
              </div>
            </div>
          </div>
        </div>
      )}
      <div className="settings-card">
        <div className="settings-card-header"><span className="settings-card-title">Account</span></div>
        <div className="settings-card-body">
          <div style={{display:'flex',alignItems:'center',justifyContent:'space-between'}}>
            <div>
              <div style={{fontSize:13,fontWeight:600,color:'var(--tx1)',fontFamily:'var(--mono)'}}>{username}</div>
              <div style={{fontSize:9,color:'var(--tx3)',fontFamily:'var(--mono)',marginTop:3}}>{ROLE_META[role]?.label||role} · Currently signed in</div>
            </div>
            <button className="btn-sm danger" onClick={()=>setConfirm({title:'Sign out',body:'Sign out of Heimdall?',confirmLabel:'Sign out',variant:'warning',onConfirm:onLogout})}>Sign out</button>
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
  const [alerts,   setAlerts]   = useState([]);
  const [view,     setView]     = useState('alerts');
  const [svFilter, setSvFilter] = useState('all');
  const [search,   setSearch]   = useState('');
  const [sparkData,setSparkData]= useState(()=>Array.from({length:60},()=>Math.floor(Math.random()*3)));
  const [theme,    setTheme]    = useState(()=>{
    const saved=localStorage.getItem('heimdall-theme');
    if(saved)document.documentElement.setAttribute('data-theme',saved);
    return saved||'night';
  });
  const [dbStats,  setDbStats]  = useState({alerts:0,flows:0,dns:0});
  const [role,     setRole]     = useState('viewer');
  const [username, setUsername] = useState('');
  const [connected,setConnected]= useState(false);

  useEffect(()=>{
    fetch('/me').then(r=>r.json()).then(d=>{setRole(d.role||'viewer');setUsername(d.username||'');}).catch(()=>{});
    fetch('/alerts?limit=500').then(r=>r.json()).then(d=>setAlerts(d.alerts||[])).catch(()=>{});
    fetch('/health').then(r=>r.json()).then(d=>setDbStats({alerts:d.db?.alerts?.total||0,flows:d.db?.flows?.total||0,dns:d.db?.dns?.total||0})).catch(()=>{});
  },[]);

  useEffect(()=>{
    let es;
    function connect(){
      es=new EventSource('/events');
      es.addEventListener('alert',e=>{
        try{
          const a=JSON.parse(e.data);a._new=true;
          setAlerts(prev=>{if(prev.find(x=>x.id===a.id))return prev;return[a,...prev].slice(0,500);});
          setSparkData(prev=>{const n=[...prev.slice(1)];n.push(prev[prev.length-1]+1);return n;});
          setTimeout(()=>setAlerts(prev=>prev.map(x=>x.id===a.id?{...x,_new:false}:x)),600);
        }catch{}
      });
      es.addEventListener('ping',()=>{});
      es.onopen =()=>setConnected(true);
      es.onerror=()=>{setConnected(false);es.close();setTimeout(connect,3000);};
    }
    connect();
    return ()=>es?.close();
  },[]);

  useEffect(()=>{
    const id=setInterval(()=>{
      setSparkData(prev=>[...prev.slice(1),Math.max(0,prev[prev.length-1]-1+Math.floor(Math.random()*2))]);
    },4000);
    return ()=>clearInterval(id);
  },[]);

  function applyTheme(t){setTheme(t);document.documentElement.setAttribute('data-theme',t);localStorage.setItem('heimdall-theme',t);}
  async function handleLogout(){try{await fetch('/logout',{method:'POST'});}catch{}window.location.href='/login';}

  const sevCounts = useMemo(()=>{
    const c={critical:0,high:0,medium:0};
    alerts.forEach(a=>{if(c[a.severity]!==undefined)c[a.severity]++;});
    return c;
  },[alerts]);

  return (
    <div className="shell">
      <header className="topbar">
        <div className="logo">
          <div className="logo-icon">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
              <ellipse cx="12" cy="12" rx="9.5" ry="6.5" stroke="white" strokeWidth="1.8"/>
              <circle cx="12" cy="12" r="2.8" fill="white"/>
              <circle cx="12" cy="12" r="1.1" fill="var(--logo-a)"/>
            </svg>
          </div>
          <div>
            <div className="logo-name">HEIMDALL</div>
            <div className="logo-sub">IDS DASHBOARD</div>
          </div>
        </div>
        <div className="tb-divider"/>
        <div className="tb-stat"><div className="tb-sev-dot" style={{background:'var(--sev-critical)'}}/>CRIT<strong>{sevCounts.critical}</strong></div>
        <div className="tb-stat"><div className="tb-sev-dot" style={{background:'var(--sev-high)'}}/>HIGH<strong>{sevCounts.high}</strong></div>
        <div className="tb-stat"><div className="tb-sev-dot" style={{background:'var(--sev-medium)'}}/>MED<strong>{sevCounts.medium}</strong></div>
        <div className="tb-spacer"/>
        <div className="view-tabs">
          {['alerts','flows','dns','charts','settings'].map(v=>(
            <button key={v} className={`tab-btn${view===v?' active':''}`} onClick={()=>setView(v)}>{v.toUpperCase()}</button>
          ))}
        </div>
        <div style={{position:'relative'}}><ThemePicker theme={theme} onChange={applyTheme}/></div>
        <div className="live-pill">
          <div className="live-dot" style={{background:connected?'var(--success)':'var(--sev-medium)'}}/>
          {connected?'LIVE':'RECONN'}
        </div>
        {username&&(
          <button className="logout-btn" onClick={handleLogout} title="Sign out">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
            {username}
          </button>
        )}
      </header>

      {view==='alerts'&&<ThreatStrip alerts={alerts} dbStats={dbStats}/>}
      {view==='alerts'&&<TrendStrip data={sparkData}/>}

      {view==='alerts'&&(
        <AlertTable alerts={alerts} svFilter={svFilter} setSvFilter={setSvFilter}
                    search={search} setSearch={setSearch} role={role} setAlerts={setAlerts}/>
      )}

      {view!=='alerts'&&(
        <div className="main-view">
          {view==='flows'&&<><div className="main-header"><span className="main-title">FLOW EVENTS</span></div><FlowsView/></>}
          {view==='dns'&&<><div className="main-header"><span className="main-title">DNS QUERIES</span></div><DNSView/></>}
          {view==='charts'&&<ChartsView/>}
          {view==='settings'&&<SettingsView theme={theme} setTheme={applyTheme} role={role} username={username} onLogout={handleLogout}/>}
        </div>
      )}

      <footer className="statusbar">
        <div className="status-item"><div className="status-dot" style={{background:'var(--success)'}}/>DATABASE</div>
        <div className="status-item"><div className="status-dot" style={{background:connected?'var(--success)':'var(--sev-medium)'}}/>{connected?'TAIL ACTIVE':'RECONNECTING…'}</div>
        <span className="status-sep">|</span>
        <div className="status-item">RETAIN 90 DAYS</div>
        {username&&<div className="status-item" style={{color:'var(--tx3)'}}>{username} · {role}</div>}
        <div style={{flex:1}}/>
        <div className="status-item" style={{color:'var(--tx4)'}}>{new Date().toLocaleDateString([],{month:'short',day:'numeric',year:'numeric'})}</div>
      </footer>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<App/>);

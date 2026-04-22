/* eslint-disable */
/**
 * Heimdall IDS Dashboard — Frontend App (Reconciled v3)
 *
 * Fixes reconciled from backend:
 *  - All alert fields use real backend names: severity, sig_msg, src_ip,
 *    src_port, dst_ip, dst_port, action, category, flow_id, sig_id
 *  - Flows and DNS use flat (non-nested) field structure from fetch_flows/fetch_dns
 *  - ThemePicker inlined from themes.js (dropdown style)
 *  - Role loaded via /me (not hardcoded)
 *  - Alert triage status (acknowledged / investigating / closed) via /alerts/<id>/status
 *  - Analyst notes via /alerts/<id>/notes and /alerts/<id>/meta
 *  - Charts view via /charts
 */
'use strict';

const { useState, useEffect, useRef, useCallback, useMemo } = React;

// ══════════════════════════════════════════════════════════════════════════════
// THEMES  (inlined from themes.js — source of truth)
// ══════════════════════════════════════════════════════════════════════════════

const THEMES = [
  { id: 'night',     label: 'Night',          accent: '#e8533a', dot: '#0e0e0f'  },
  { id: 'light',     label: 'Light',          accent: '#3466c8', dot: '#f4f3f0'  },
  { id: 'midnight',  label: 'Midnight Blue',  accent: '#58a6ff', dot: '#0d1117'  },
  { id: 'solarized', label: 'Solarized Dark', accent: '#268bd2', dot: '#002b36'  },
  { id: 'dracula',   label: 'Dracula',        accent: '#bd93f9', dot: '#191a21'  },
  { id: 'nord',      label: 'Nord',           accent: '#88c0d0', dot: '#2e3440'  },
];

function ThemePicker({ theme, onChange }) {
  const [open, setOpen] = useState(false);
  const ref             = useRef(null);
  const current         = THEMES.find(t => t.id === theme) || THEMES[0];

  useEffect(() => {
    function handler(e) {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    }
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  return (
    <div style={{ position: 'relative' }} ref={ref}>
      <button className="theme-btn" onClick={() => setOpen(o => !o)}>
        <div className="theme-swatch-dot" style={{ background: current.accent }} />
        <span>{current.label}</span>
        <svg width="10" height="10" viewBox="0 0 10 10" fill="none"
             stroke="currentColor" strokeWidth="1.5">
          <path d="M2 4l3 3 3-3"/>
        </svg>
      </button>

      {open && (
        <div className="theme-dropdown">
          {THEMES.map(t => (
            <div
              key={t.id}
              className={`theme-option${theme === t.id ? ' active' : ''}`}
              onClick={() => { onChange(t.id); setOpen(false); }}
            >
              <div style={{
                width: 10, height: 10, borderRadius: '50%', flexShrink: 0,
                background: t.dot, border: `2px solid ${t.accent}`,
              }} />
              <div style={{
                width: 10, height: 10, borderRadius: '50%', flexShrink: 0,
                background: t.accent,
              }} />
              <span>{t.label}</span>
              {theme === t.id && (
                <svg style={{ marginLeft: 'auto' }} width="10" height="10"
                     viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M2 5l2.5 2.5L8 3"/>
                </svg>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ══════════════════════════════════════════════════════════════════════════════

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

const SEV_META = {
  critical: { color: 'var(--sev-critical)', bg: 'var(--sev-critical-bg)', label: 'CRITICAL', order: 0 },
  high:     { color: 'var(--sev-high)',     bg: 'var(--sev-high-bg)',     label: 'HIGH',     order: 1 },
  medium:   { color: 'var(--sev-medium)',   bg: 'var(--sev-medium-bg)',   label: 'MEDIUM',   order: 2 },
  low:      { color: 'var(--sev-low)',      bg: 'var(--sev-low-bg)',      label: 'LOW',      order: 3 },
  info:     { color: 'var(--sev-info)',     bg: 'var(--sev-info-bg)',     label: 'INFO',     order: 4 },
};

const TRIAGE_META = {
  acknowledged: { label: 'Acknowledged', color: 'var(--sev-info)',   bg: 'var(--sev-info-bg)'   },
  investigating: { label: 'Investigating', color: 'var(--sev-medium)', bg: 'var(--sev-medium-bg)' },
  closed:        { label: 'Closed',        color: 'var(--success)',    bg: 'var(--success-bg)'    },
};

const ROLE_META = {
  admin:   { label: 'Admin',   cls: 'admin'   },
  analyst: { label: 'Analyst', cls: 'analyst' },
  viewer:  { label: 'Viewer',  cls: 'viewer'  },
};

const ALL_SEVS       = ['critical', 'high', 'medium', 'low', 'info'];
const WEBHOOK_TYPES  = ['slack', 'discord', 'generic'];



/**
 * Smart alert timestamp formatter:
 *   Today     → "8:30 PM"
 *   Yesterday → "Yesterday at 8:30 PM"
 *   Older     → "Apr 15 · 8:30 PM"
 */
function fmtAlertTime(ts) {
  if (!ts) return '';
  const d   = new Date(ts);
  if (isNaN(d)) return ts;
  const now  = new Date();
  const time = d.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit', hour12: true });
  const todayMidnight = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const yestMidnight  = new Date(todayMidnight - 864e5);
  if (d >= todayMidnight)  return time;
  if (d >= yestMidnight)   return `Yesterday at ${time}`;
  return d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' · ' + time;
}

/** Full readable timestamp for detail panel: "Apr 18, 2026 · 2:48 PM" */
function fmtDetailTime(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  if (isNaN(d)) return ts;
  return d.toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' })
    + ' · '
    + d.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit', hour12: true });
}

// ══════════════════════════════════════════════════════════════════════════════
// SMALL SHARED COMPONENTS
// ══════════════════════════════════════════════════════════════════════════════

function SevBadge({ sev }) {
  const m = SEV_META[sev] || SEV_META.info;
  return <span className="sev-badge" style={{ color: m.color, background: m.bg }}>{m.label}</span>;
}

function Sparkline({ data }) {
  const max = Math.max(...data, 1);
  return (
    <div className="sparkline">
      {data.map((v, i) => {
        const h   = Math.max(3, Math.round((v / max) * 22));
        const col = v > max * .75 ? 'var(--sev-critical)' :
                    v > max * .45 ? 'var(--sev-high)'     : 'var(--spark-bar)';
        return <div key={i} className="spark-bar" style={{ height: h, background: col }} />;
      })}
    </div>
  );
}

// ── Confirm Dialog ─────────────────────────────────────────────────────────

function ConfirmDialog({ title, body, confirmLabel = 'Confirm', variant = 'danger', onConfirm, onClose }) {
  const iconColor = variant === 'danger' ? 'var(--danger)' : 'var(--sev-medium)';
  const icon = variant === 'danger'
    ? <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={iconColor} strokeWidth="2">
        <polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/>
        <path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/>
      </svg>
    : <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={iconColor} strokeWidth="2">
        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
        <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
      </svg>;

  return (
    <div className="confirm-backdrop" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="confirm-box">
        <div className={`confirm-icon ${variant}`}>{icon}</div>
        <div className="confirm-title">{title}</div>
        <div className="confirm-body">{body}</div>
        <div className="confirm-footer">
          <button className="btn-modal" onClick={onClose}>Cancel</button>
          <button
            className="btn-modal confirm"
            style={variant === 'danger' ? { background: 'var(--danger-bg)', borderColor: 'var(--danger)', color: 'var(--danger)' } : {}}
            onClick={() => { onConfirm(); onClose(); }}>
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// JSON VIEWER  — stringify + regex tokenizer, span-only, no dangerouslySetInnerHTML
// ══════════════════════════════════════════════════════════════════════════════

const JSON_TOKEN_COLORS = {
  key:     '#88c0d0',  // arctic blue  — object keys
  string:  '#a3e4b0',  // mint green   — string values
  number:  '#f4c96e',  // amber        — numbers
  boolean: '#bd93f9',  // purple       — true / false
  null:    '#ff79c6',  // pink         — null
  punct:   '#6272a4',  // slate        — { } [ ] : ,
};

// Tokenise pre-formatted JSON text into [{type, text}] segments.
// Operates entirely on the stringified output — never touches raw HTML.
function tokenizeJson(text) {
  const tokens = [];
  // Matches: quoted strings (with optional trailing colon → key), booleans, null, numbers, punctuation, whitespace
  const RE = /("(?:\\[\s\S]|[^"\\])*")(\s*:)?|(true|false)|(null)|(-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)|([{}[\],:])|(\s+)/g;
  let m;
  while ((m = RE.exec(text)) !== null) {
    const [full, str, colon, bool, nul, num, punct, ws] = m;
    if (ws  !== undefined) { tokens.push({ type: 'plain', text: ws });   continue; }
    if (str !== undefined) {
      if (colon) {
        tokens.push({ type: 'key',   text: str });
        tokens.push({ type: 'punct', text: colon });
      } else {
        tokens.push({ type: 'string', text: str });
      }
      continue;
    }
    if (bool  !== undefined) { tokens.push({ type: 'boolean', text: bool  }); continue; }
    if (nul   !== undefined) { tokens.push({ type: 'null',    text: nul   }); continue; }
    if (num   !== undefined) { tokens.push({ type: 'number',  text: num   }); continue; }
    if (punct !== undefined) { tokens.push({ type: 'punct',   text: punct }); continue; }
    tokens.push({ type: 'plain', text: full });
  }
  return tokens;
}

function SidebarJsonViewer({ alert }) {
  const [collapsed, setCollapsed] = useState(true);
  if (!alert) return null;

  // Strip internal UI-only fields before displaying
  const { _new, ...safeAlert } = alert;
  const tokens = useMemo(() => {
    try { return tokenizeJson(JSON.stringify(safeAlert, null, 2)); }
    catch { return [{ type: 'plain', text: String(safeAlert) }]; }
  }, [alert.id, alert.status]);   // re-tokenise only when identity or status changes

  return (
    <div className="sidebar-json-viewer">
      <div className="sidebar-json-header" onClick={() => setCollapsed(c => !c)}>
        <span className="sidebar-json-title">RAW JSON</span>
        <span className="sidebar-json-toggle">{collapsed ? '▶' : '▼'}</span>
      </div>
      {!collapsed && (
        <pre className="sidebar-json-pre">
          {tokens.map((tok, i) => (
            <span key={i} style={{ color: JSON_TOKEN_COLORS[tok.type] || 'var(--tx2)' }}>
              {tok.text}
            </span>
          ))}
        </pre>
      )}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// LEFT SIDEBAR (Alerts view)
// ══════════════════════════════════════════════════════════════════════════════

function Sidebar({ alerts, svFilter, setSvFilter, search, setSearch, selectedAlert }) {
  const counts = useMemo(() => {
    const c = { all: alerts.length, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    alerts.forEach(a => { if (c[a.severity] !== undefined) c[a.severity]++; });
    return c;
  }, [alerts]);

  return (
    <aside className="sidebar">
      <div className="sidebar-section">
        <div className="sidebar-title">Severity</div>

        <div className={`filter-item${svFilter === 'all' ? ' active' : ''}`}
             onClick={() => setSvFilter('all')}>
          <div className="fi-left">
            <div className="fi-dot" style={{ background: 'var(--tx4)' }} />
            <span className="fi-name">All alerts</span>
          </div>
          <span className="fi-count">{counts.all}</span>
        </div>

        {SEV_ORDER.map(s => {
          const m = SEV_META[s]; const active = svFilter === s;
          return (
            <div key={s} className={`filter-item${active ? ' active' : ''}`}
                 onClick={() => setSvFilter(s)}>
              <div className="fi-left">
                {active && <div className="fi-bar" style={{ background: m.color }} />}
                <div className="fi-dot" style={{ background: m.color }} />
                <span className="fi-name" style={active ? { color: m.color } : {}}>
                  {m.label.charAt(0) + m.label.slice(1).toLowerCase()}
                </span>
              </div>
              <span className="fi-count">{counts[s]}</span>
            </div>
          );
        })}
      </div>

      <div className="sidebar-divider" />
      <div className="search-wrap">
        <input className="search-input" placeholder="Search IPs, signatures…"
               value={search} onChange={e => setSearch(e.target.value)} />
      </div>

      {selectedAlert && (
        <>
          <div className="sidebar-divider" />
          <SidebarJsonViewer alert={selectedAlert} />
        </>
      )}
    </aside>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// ALERT FEED
// ══════════════════════════════════════════════════════════════════════════════

function AlertFeed({ alerts, svFilter, search, selectedId, onSelect,
                     selectedAlerts, onToggleSelect, onSelectAll, onFilteredIds }) {
  const filtered = useMemo(() => alerts.filter(a => {
    if (svFilter !== 'all' && a.severity !== svFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      if (!a.sig_msg?.toLowerCase().includes(q) &&
          !a.src_ip?.includes(q) &&
          !a.dst_ip?.includes(q)) return false;
    }
    return true;
  }), [alerts, svFilter, search]);

  const grouped = useMemo(() => {
    const g = {};
    filtered.forEach(a => { (g[a.severity] = g[a.severity] || []).push(a); });
    return g;
  }, [filtered]);

  const filteredIds = useMemo(() => filtered.map(a => a.id), [filtered]);
  const allSelected = filteredIds.length > 0 && filteredIds.every(id => selectedAlerts.has(id));

  // Notify parent of current filtered ids + allSelected so it can render Select All in the header
  useEffect(() => {
    onFilteredIds?.(filteredIds, allSelected);
  }, [filteredIds.join(','), allSelected]);

  if (!filtered.length) return (
    <div className="empty-state">
      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1">
        <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
      </svg>
      No matching alerts
    </div>
  );

  return (
    <div className="feed">
      {SEV_ORDER.filter(s => grouped[s]).map(sev => {
        const m = SEV_META[sev];
        return (
          <div key={sev} className="alert-group">
            <div className="group-header" style={{ color: m.color }}>
              {m.label}
              <span style={{ color: 'var(--tx3)', fontWeight: 400 }}>({grouped[sev].length})</span>
              <div className="group-rule" style={{ background: m.color }} />
            </div>
            <div className="group-cards">
              {grouped[sev].map(a => (
                <AlertCard key={a.id} alert={a}
                           selected={a.id === selectedId} onSelect={onSelect}
                           bulkSelected={selectedAlerts.has(a.id)}
                           onToggleSelect={onToggleSelect} />
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function AlertCard({ alert: a, selected, onSelect, bulkSelected, onToggleSelect }) {
  const m = SEV_META[a.severity] || SEV_META.info;
  return (
    <div className={`alert-card${selected ? ' active' : ''}${a._new ? ' new-in' : ''}${bulkSelected ? ' bulk-selected' : ''}`}
         style={{ borderLeftColor: bulkSelected ? 'var(--accent)' : selected ? 'var(--accent)' : m.color + '30' }}
         onClick={() => onSelect(a.id)}>
      <div className="card-row1">
        <div
          onClick={e => { e.stopPropagation(); onToggleSelect(a.id); }}
          style={{
            width: 13, height: 13, flexShrink: 0, marginRight: 8, cursor: 'pointer',
            borderRadius: 3, border: `1.5px solid ${bulkSelected ? 'var(--accent)' : 'var(--tx3)'}`,
            background: bulkSelected ? 'var(--accent)' : 'transparent',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            transition: 'background .12s, border-color .12s',
          }}
        >
          {bulkSelected && (
            <svg width="8" height="8" viewBox="0 0 8 8" fill="none">
              <polyline points="1.5,4 3,5.5 6.5,2" stroke="white" strokeWidth="1.5"
                        strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          )}
        </div>
        <SevBadge sev={a.severity} />
        <span className="card-msg">{a.sig_msg}</span>
        <span className="card-time">{fmtAlertTime(a.ts)}</span>
      </div>
      <div className="card-row2">
        <span className="card-proto">{a.proto}</span>
        <span className="card-net">
          {a.src_ip}:{a.src_port} → {a.dst_ip}:{a.dst_port}
        </span>
        {a.status && (
          <span className="triage-chip" style={{
            color:      TRIAGE_META[a.status]?.color || 'var(--tx3)',
            background: TRIAGE_META[a.status]?.bg    || 'var(--s3)',
          }}>{a.status}</span>
        )}
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// DETAIL PANEL  (triage status + notes)
// ══════════════════════════════════════════════════════════════════════════════

function DetailPanel({ alert: a, role }) {
  const [meta,    setMeta]    = useState(null);   // { status, notes[] }
  const [newNote, setNewNote] = useState('');
  const [saving,  setSaving]  = useState(false);

  const canTriage = role === 'admin' || role === 'analyst';

  useEffect(() => {
    if (!a?.id) { setMeta(null); return; }
    fetch(`/alerts/${encodeURIComponent(a.id)}/meta`)
      .then(r => r.json())
      .then(setMeta)
      .catch(() => setMeta({ status: null, notes: [] }));
  }, [a?.id]);

  async function setStatus(status) {
    if (!canTriage) return;
    const next = meta?.status === status ? null : status;
    await fetch(`/alerts/${encodeURIComponent(a.id)}/status`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: next }),
    });
    setMeta(prev => ({ ...prev, status: next }));
    // Reflect in the feed card
    a.status = next;
  }

  async function addNote() {
    if (!newNote.trim() || !canTriage) return;
    setSaving(true);
    const r = await fetch(`/alerts/${encodeURIComponent(a.id)}/notes`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ note: newNote.trim() }),
    });
    if (r.ok) {
      const n = await r.json();
      setMeta(prev => ({ ...prev, notes: [...(prev?.notes || []), n] }));
      setNewNote('');
    }
    setSaving(false);
  }

  if (!a) return (
    <aside className="detail-panel">
      <div className="detail-empty">
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none"
             stroke="currentColor" strokeWidth="1">
          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
          <polyline points="14 2 14 8 20 8"/>
          <line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/>
        </svg>
        Select an alert
      </div>
    </aside>
  );

  const m = SEV_META[a.severity] || SEV_META.info;

  return (
    <aside className="detail-panel">
      {/* Head */}
      <div className="detail-head">
        <div className="detail-head-label">Alert Detail</div>
        <div className="detail-sig">{a.sig_msg}</div>
        <div className="detail-sub">SID {a.sig_id} · {a.category}</div>
        <div className="detail-chips">
          <SevBadge sev={a.severity} />
          <span className="sev-badge" style={{ color: 'var(--tx2)', background: 'var(--s3)' }}>{a.proto}</span>
        </div>
      </div>

      {/* Triage status */}
      {canTriage && (
        <div className="detail-section">
          <div className="detail-section-title">Triage</div>
          <div className="triage-buttons">
            {Object.entries(TRIAGE_META).map(([s, tm]) => {
              const active = meta?.status === s;
              return (
                <button key={s} className={`triage-btn${active ? ' active' : ''}`}
                  style={active ? { color: tm.color, background: tm.bg, borderColor: tm.color }
                                : {}}
                  onClick={() => setStatus(s)}>
                  {tm.label}
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* Network */}
      <div className="detail-section">
        <div className="detail-section-title">Network</div>
        <div className="detail-row"><span className="detail-key">Source</span>
          <span className="detail-val">{a.src_ip}:{a.src_port}</span></div>
        <div className="detail-row"><span className="detail-key">Destination</span>
          <span className="detail-val">{a.dst_ip}:{a.dst_port}</span></div>
        <div className="detail-row"><span className="detail-key">Protocol</span>
          <span className="detail-val">{a.proto}</span></div>
        <div className="detail-row"><span className="detail-key">Interface</span>
          <span className="detail-val">{a.iface}</span></div>
        <div className="detail-row"><span className="detail-key">Flow ID</span>
          <span className="detail-val">{a.flow_id || '—'}</span></div>
      </div>

      {/* Signature */}
      <div className="detail-section">
        <div className="detail-section-title">Signature</div>
        <div className="detail-row"><span className="detail-key">SID</span>
          <span className="detail-val">{a.sig_id}</span></div>
        <div className="detail-row"><span className="detail-key">Category</span>
          <span className="detail-val">{a.category}</span></div>
        <div className="detail-row"><span className="detail-key">Severity</span>
          <span className="detail-val" style={{ color: m.color }}>{a.severity?.toUpperCase()}</span></div>
      </div>

      {/* Time */}
      <div className="detail-section">
        <div className="detail-section-title">Timestamp</div>
        <div className="detail-row"><span className="detail-key">Time</span>
          <span className="detail-val" style={{ color: 'var(--tx1)', fontWeight: 500 }}>
            {fmtDetailTime(a.ts)}
          </span></div>
      </div>

      {/* Activity Log */}
      {meta?.activity?.length > 0 && (
        <div className="detail-section">
          <div className="detail-section-title">Activity Log</div>
          <div className="activity-log">
            {[...meta.activity].reverse().map((ev, i) => (
              <div key={i} className="activity-item">
                <div className="activity-dot" />
                <div className="activity-body">
                  <span className="activity-action">{ev.action}</span>
                  <span className="activity-meta">
                    {ev.username} · {fmtDetailTime(new Date(ev.created_at * 1000).toISOString())}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Notes */}
      <div className="detail-section">
        <div className="detail-section-title">Notes ({meta?.notes?.length || 0})</div>
        {meta?.notes?.map((n, i) => (
          <div key={i} className="note-item">
            <div className="note-meta">{n.username} · {new Date(n.created_at * 1000).toLocaleTimeString()}</div>
            <div className="note-text">{n.note}</div>
          </div>
        ))}
        {canTriage && (
          <div className="note-form">
            <textarea className="note-input" rows={2}
              placeholder="Add note…" value={newNote}
              onChange={e => setNewNote(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter' && e.ctrlKey) addNote(); }} />
            <button className="btn-sm primary" onClick={addNote} disabled={saving || !newNote.trim()}>
              {saving ? 'Saving…' : 'Add'}
            </button>
          </div>
        )}
      </div>
    </aside>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// BULK PANEL  (replaces DetailPanel when multiple alerts are selected)
// ══════════════════════════════════════════════════════════════════════════════

function BulkPanel({ selectedAlerts, alerts, role, onBulkStatus, onClearSelection }) {
  const [note,    setNote]    = useState('');
  const [saving,  setSaving]  = useState(false);
  const [saved,   setSaved]   = useState(false);

  const canTriage = role === 'admin' || role === 'analyst';
  const ids       = [...selectedAlerts];

  // Severity breakdown of selected alerts
  const breakdown = useMemo(() => {
    const c = {};
    alerts.forEach(a => {
      if (!selectedAlerts.has(a.id)) return;
      c[a.severity] = (c[a.severity] || 0) + 1;
    });
    return SEV_ORDER.filter(s => c[s]).map(s => ({ sev: s, count: c[s] }));
  }, [selectedAlerts, alerts]);

  async function addMassNote() {
    if (!note.trim() || !canTriage) return;
    setSaving(true);
    await Promise.all(ids.map(id =>
      fetch(`/alerts/${encodeURIComponent(id)}/notes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ note: note.trim() }),
      })
    ));
    setSaving(false);
    setSaved(true);
    setNote('');
    setTimeout(() => setSaved(false), 2500);
  }

  return (
    <aside className="detail-panel">
      <div className="detail-head">
        <div className="detail-head-label">Bulk Selection</div>
        <div className="detail-sig" style={{ fontSize: 22, fontWeight: 700,
             color: 'var(--accent)', fontFamily: 'var(--mono)' }}>
          {ids.length} alerts
        </div>
        <div className="detail-sub">selected across {breakdown.length} severity level{breakdown.length !== 1 ? 's' : ''}</div>

        {/* Severity breakdown pills */}
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 10 }}>
          {breakdown.map(({ sev, count }) => {
            const m = SEV_META[sev];
            return (
              <span key={sev} className="sev-badge"
                    style={{ color: m.color, background: m.bg }}>
                {m.label} · {count}
              </span>
            );
          })}
        </div>
      </div>

      {/* Bulk triage */}
      {canTriage && (
        <div className="detail-section">
          <div className="detail-section-title">Set Status</div>
          <div className="triage-buttons">
            {Object.entries(TRIAGE_META).map(([s, tm]) => (
              <button key={s} className="triage-btn"
                style={{ color: tm.color, background: tm.bg, borderColor: tm.color + '66' }}
                onClick={() => onBulkStatus(s)}>
                {tm.label}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Mass note */}
      {canTriage && (
        <div className="detail-section">
          <div className="detail-section-title">Add Note to All</div>
          <div className="note-form">
            <textarea className="note-input" rows={3}
              placeholder={`Add a note to all ${ids.length} selected alerts…`}
              value={note} onChange={e => setNote(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter' && e.ctrlKey) addMassNote(); }} />
            <button className="btn-sm primary" onClick={addMassNote}
                    disabled={saving || !note.trim()}>
              {saving ? 'Saving…' : saved ? '✓ Saved' : `Add to ${ids.length}`}
            </button>
          </div>
        </div>
      )}

      {/* Deselect */}
      <div className="detail-section">
        <button className="btn-sm" style={{ width: '100%' }} onClick={onClearSelection}>
          Deselect all
        </button>
      </div>
    </aside>
  );
}



function FlowsView() {
  const [flows,   setFlows]   = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/flows?limit=200')
      .then(r => r.json())
      .then(d => { setFlows(d.flows || []); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  if (loading) return <div className="empty-state">Loading flows…</div>;
  if (!flows.length) return <div className="empty-state">No flow events</div>;

  return (
    <div className="table-view">
      <table className="data-table">
        <thead><tr>
          <th>Time</th><th>Source</th><th>Destination</th>
          <th>Proto</th><th>App</th><th>↑ Bytes</th><th>↓ Bytes</th><th>State</th>
        </tr></thead>
        <tbody>
          {flows.map((f, i) => (
            <tr key={i}>
              <td>{f.ts?.slice(11, 19)}</td>
              <td className="td-primary">{f.src_ip}:{f.src_port}</td>
              <td>{f.dst_ip}:{f.dst_port}</td>
              <td>{f.proto?.toUpperCase()}</td>
              <td>{f.app_proto || '—'}</td>
              <td>{(f.bytes_toserver || 0).toLocaleString()}</td>
              <td>{(f.bytes_toclient || 0).toLocaleString()}</td>
              <td style={{ color: f.state === 'closed' ? 'var(--tx3)' : 'var(--success)' }}>
                {f.state || '—'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// DNS VIEW  (flat fields from fetch_dns)
// ══════════════════════════════════════════════════════════════════════════════

function DNSView() {
  const [records, setRecords] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/dns?limit=200')
      .then(r => r.json())
      .then(d => { setRecords(d.dns || []); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  if (loading) return <div className="empty-state">Loading DNS records…</div>;
  if (!records.length) return <div className="empty-state">No DNS events</div>;

  return (
    <div className="table-view">
      <table className="data-table">
        <thead><tr>
          <th>Time</th><th>Client</th><th>Query</th><th>Type</th>
          <th>Dir</th><th>RCode</th><th>TTL</th>
        </tr></thead>
        <tbody>
          {records.map((d, i) => (
            <tr key={i}>
              <td>{d.ts?.slice(11, 19)}</td>
              <td className="td-primary">{d.src_ip}</td>
              <td><span className="dns-rrname">{d.rrname || '—'}</span></td>
              <td>{d.rrtype || '—'}</td>
              <td>{d.dns_type || '—'}</td>
              <td style={{ color: d.rcode === 'NOERROR' ? 'var(--success)' :
                           d.rcode ? 'var(--danger)' : 'var(--tx3)' }}>
                {d.rcode || '—'}
              </td>
              <td>{d.ttl ?? '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// DONUT CHART COMPONENT
// ══════════════════════════════════════════════════════════════════════════════

function DonutChart({ data }) {
  const COLORS = [
    'var(--accent)', 'var(--sev-high)', 'var(--sev-medium)',
    'var(--sev-low)', 'var(--sev-critical)', 'var(--sev-info)',
    '#a78bfa', '#f472b6', '#34d399', '#fb923c',
  ];
  const total = data.reduce((s, d) => s + d.count, 0) || 1;
  const R = 70, cx = 90, cy = 90, strokeW = 22;
  const circ = 2 * Math.PI * R;

  let offset = 0;
  const slices = data.map((d, i) => {
    const dash = (d.count / total) * circ;
    const sl   = { offset, dash, gap: circ - dash, color: COLORS[i % COLORS.length],
                   label: d.category, count: d.count };
    offset += dash;
    return sl;
  });

  const [hovered, setHovered] = useState(null);

  return (
    <div style={{ display: 'flex', gap: 20, alignItems: 'center', flexWrap: 'wrap' }}>
      <svg width="180" height="180" viewBox="0 0 180 180" style={{ flexShrink: 0 }}>
        <circle cx={cx} cy={cy} r={R} fill="none" stroke="var(--s3)" strokeWidth={strokeW} />
        {slices.map((sl, i) => (
          <circle key={i} cx={cx} cy={cy} r={R} fill="none"
                  stroke={sl.color}
                  strokeWidth={hovered === i ? strokeW + 4 : strokeW}
                  strokeDasharray={`${sl.dash} ${sl.gap}`}
                  strokeDashoffset={circ / 4 - sl.offset}
                  style={{ cursor: 'pointer', transition: 'stroke-width .15s',
                           transform: 'rotate(-90deg)', transformOrigin: `${cx}px ${cy}px` }}
                  onMouseEnter={() => setHovered(i)}
                  onMouseLeave={() => setHovered(null)} />
        ))}
        <text x={cx} y={cy - 6} textAnchor="middle" fill="var(--tx1)"
              fontSize="18" fontWeight="600" fontFamily="var(--mono)">{total}</text>
        <text x={cx} y={cy + 10} textAnchor="middle" fill="var(--tx3)"
              fontSize="9" letterSpacing="0.08em">TOTAL</text>
      </svg>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 6, flex: 1, minWidth: 140 }}>
        {slices.map((sl, i) => (
          <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 7,
                                opacity: hovered !== null && hovered !== i ? 0.35 : 1,
                                transition: 'opacity .15s', cursor: 'default' }}
               onMouseEnter={() => setHovered(i)} onMouseLeave={() => setHovered(null)}>
            <div style={{ width: 8, height: 8, borderRadius: 2, background: sl.color, flexShrink: 0 }} />
            <span style={{ fontSize: 11, color: 'var(--tx2)', flex: 1,
                           overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {sl.label || '—'}
            </span>
            <span style={{ fontSize: 11, color: 'var(--tx1)', fontFamily: 'var(--mono)', flexShrink: 0 }}>
              {sl.count}
            </span>
            <span style={{ fontSize: 10, color: 'var(--tx3)', flexShrink: 0, width: 34, textAlign: 'right' }}>
              {Math.round(sl.count / total * 100)}%
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// CHARTS VIEW  (/charts endpoint)
// ══════════════════════════════════════════════════════════════════════════════

const CHART_WINDOWS = [
  { hrs: 24,   label: '24h' },
  { hrs: 168,  label: '7d'  },
  { hrs: 720,  label: '30d' },
  { hrs: 1440, label: '60d' },
  { hrs: 2160, label: '90d' },
];

function ChartsView() {
  const [data,     setData]     = useState(null);
  const [loading,  setLoading]  = useState(true);
  const [chartHrs, setChartHrs] = useState(24);

  function load(hrs) {
    setLoading(true);
    fetch(`/charts?trend=${hrs}`)
      .then(r => r.json())
      .then(d => { setData(d); setLoading(false); })
      .catch(() => setLoading(false));
  }

  useEffect(() => { load(chartHrs); }, [chartHrs]);

  if (loading) return <div className="empty-state">Loading charts…</div>;
  if (!data)   return <div className="empty-state">No chart data</div>;

  const trendData  = data.trend        || [];
  const sevData    = data.by_severity  || [];
  const talkerData = data.top_talkers  || [];
  const catData    = data.by_category  || [];

  const maxTrend  = Math.max(...trendData.map(t => t.count),  1);
  const maxSev    = Math.max(...sevData.map(x => x.count),    1);
  const maxTalker = Math.max(...talkerData.map(x => x.count), 1);
  const labelEvery = Math.max(1, Math.ceil(trendData.length / 8));

  return (
    <div className="charts-layout">
      {/* Controls */}
      <div className="charts-controls">
        <div className="view-tabs" style={{ marginLeft: 'auto' }}>
          {CHART_WINDOWS.map(w => (
            <button key={w.hrs} className={`tab-btn${chartHrs === w.hrs ? ' active' : ''}`}
                    onClick={() => setChartHrs(w.hrs)}>
              {w.label}
            </button>
          ))}
        </div>
      </div>

      <div className="charts-grid">

        {/* ── Alert Trend — vertical bar chart ── */}
        <div className="chart-card wide">
          <div className="chart-card-title">Alert Trend</div>
          <div style={{ display: 'flex', alignItems: 'flex-end', gap: 2,
                        height: 130, paddingBottom: 22, position: 'relative' }}>
            {[0.25, 0.5, 0.75, 1].map(pct => (
              <div key={pct} style={{
                position: 'absolute', left: 0, right: 0, bottom: 22 + pct * 108,
                borderTop: '1px dashed var(--ln)', pointerEvents: 'none',
              }} />
            ))}
            {trendData.map((t, i) => {
              const h   = Math.max(2, Math.round(t.count / maxTrend * 108));
              const col = t.count > maxTrend * .75 ? 'var(--sev-critical)' :
                          t.count > maxTrend * .45 ? 'var(--sev-high)'     : 'var(--accent)';
              return (
                <div key={i} title={`${t.ts}: ${t.count}`}
                     style={{ flex: 1, display: 'flex', flexDirection: 'column',
                              alignItems: 'center', justifyContent: 'flex-end', position: 'relative' }}>
                  <div style={{ width: '100%', height: h, background: col, opacity: 0.85,
                                borderRadius: '2px 2px 0 0', transition: 'height .2s' }} />
                  {i % labelEvery === 0 && (
                    <div style={{ position: 'absolute', bottom: -18, fontSize: 9,
                                  color: 'var(--tx4)', whiteSpace: 'nowrap',
                                  transform: 'translateX(-50%)', left: '50%' }}>
                      {t.ts}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 4 }}>
            <span style={{ fontSize: 9, color: 'var(--tx3)' }}>0</span>
            <span style={{ fontSize: 9, color: 'var(--tx3)' }}>peak: {maxTrend}</span>
          </div>
        </div>

        {/* ── By Severity ── */}
        <div className="chart-card">
          <div className="chart-card-title">By Severity</div>
          <div className="bar-list">
            {sevData.map(r => {
              const m = SEV_META[r.severity] || SEV_META.info;
              return (
                <div key={r.severity} className="bar-row">
                  <span className="bar-label" style={{ color: m.color }}>{m.label}</span>
                  <div className="bar-track" style={{ background: m.bg }}>
                    <div className="bar-fill"
                         style={{ width: `${Math.round(r.count / maxSev * 100)}%`,
                                  background: m.color }} />
                  </div>
                  <span className="bar-val" style={{ color: m.color }}>{r.count}</span>
                </div>
              );
            })}
          </div>
        </div>

        {/* ── Top Source IPs ── */}
        <div className="chart-card">
          <div className="chart-card-title">Top Source IPs</div>
          <div className="bar-list">
            {(() => {
              const IP_COLORS = [
                { color: 'var(--sev-info)',     bg: 'var(--sev-info-bg)'     },
                { color: 'var(--sev-medium)',   bg: 'var(--sev-medium-bg)'   },
                { color: 'var(--accent)',       bg: 'var(--accent-bg)'       },
                { color: 'var(--sev-high)',     bg: 'var(--sev-high-bg)'     },
                { color: 'var(--sev-critical)', bg: 'var(--sev-critical-bg)' },
                { color: 'var(--sev-low)',      bg: 'var(--sev-low-bg)'      },
              ];
              return talkerData.map((r, i) => {
                const c = IP_COLORS[i % IP_COLORS.length];
                return (
                  <div key={r.ip} className="bar-row">
                    <span className="bar-label mono" style={{ color: c.color }}>{r.ip}</span>
                    <div className="bar-track" style={{ background: c.bg }}>
                      <div className="bar-fill"
                           style={{ width: `${Math.round(r.count / maxTalker * 100)}%`,
                                    background: c.color }} />
                    </div>
                    <span className="bar-val" style={{ color: c.color }}>{r.count}</span>
                  </div>
                );
              });
            })()}
          </div>
        </div>

        {/* ── By Category — Donut ── */}
        <div className="chart-card wide">
          <div className="chart-card-title">By Category</div>
          {catData.length
            ? <DonutChart data={catData} />
            : <div className="empty-state" style={{ padding: '20px 0' }}>No category data</div>
          }
        </div>

      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// WEBHOOK FORM MODAL
// ══════════════════════════════════════════════════════════════════════════════

function WebhookModal({ initial, onSave, onClose }) {
  const editing = Boolean(initial?.id);
  const [name, setName] = useState(initial?.name || '');
  const [type, setType] = useState(initial?.type || 'generic');
  const [url,  setUrl]  = useState(initial?.url  || '');
  const [sevs, setSevs] = useState(initial?.severities || ALL_SEVS);

  function toggleSev(s) {
    setSevs(p => p.includes(s) ? p.filter(x => x !== s) : [...p, s]);
  }

  async function submit() {
    if (!name.trim() || !url.trim()) return;
    const body     = { name: name.trim(), type, url: url.trim(), severities: sevs, enabled: true };
    const endpoint = editing ? `/webhooks/${initial.id}` : '/webhooks';
    const method   = editing ? 'PUT' : 'POST';
    const res = await fetch(endpoint, {
      method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    });
    if (res.ok) { onSave(); onClose(); }
  }

  return (
    <div className="modal-backdrop" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="modal">
        <div className="modal-title">{editing ? 'Edit Webhook' : 'Add Webhook'}</div>
        <div className="modal-sub">Push alert notifications to Slack, Discord, or any HTTP endpoint.</div>
        <div className="form-row">
          <div className="form-group">
            <label className="form-label">Name</label>
            <input className="form-input" value={name} onChange={e => setName(e.target.value)} placeholder="My Webhook" />
          </div>
          <div className="form-group" style={{ maxWidth: 110 }}>
            <label className="form-label">Type</label>
            <select className="form-select" value={type} onChange={e => setType(e.target.value)}>
              {WEBHOOK_TYPES.map(t => <option key={t} value={t}>{t.charAt(0).toUpperCase() + t.slice(1)}</option>)}
            </select>
          </div>
        </div>
        <div className="form-group">
          <label className="form-label">Endpoint URL</label>
          <input className="form-input" value={url} onChange={e => setUrl(e.target.value)} placeholder="https://hooks.slack.com/…" />
        </div>
        <div className="form-group">
          <label className="form-label">Trigger on severity</label>
          <div className="sev-checkboxes">
            {ALL_SEVS.map(s => {
              const m = SEV_META[s]; const on = sevs.includes(s);
              return (
                <label key={s} className={`sev-check${on ? ' checked' : ''}`}
                       style={{ color: m.color, borderColor: on ? m.color : 'var(--ln)' }}>
                  <input type="checkbox" checked={on} onChange={() => toggleSev(s)} />
                  {m.label}
                </label>
              );
            })}
          </div>
        </div>
        <div className="modal-footer">
          <button className="btn-modal" onClick={onClose}>Cancel</button>
          <button className="btn-modal confirm" onClick={submit}>{editing ? 'Save changes' : 'Add webhook'}</button>
        </div>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// SETTINGS VIEW
// ══════════════════════════════════════════════════════════════════════════════

function UserModal({ initial, onSave, onClose }) {
  const editing = Boolean(initial?.id);
  const [username, setUsername] = useState(initial?.username || '');
  const [password, setPassword] = useState('');
  const [role,     setRole]     = useState(initial?.role || 'analyst');

  async function submit() {
    if (!editing && (!username.trim() || !password)) return;
    const body     = editing ? { role } : { username: username.trim(), password, role };
    const endpoint = editing ? `/users/${initial.id}` : '/users';
    const method   = editing ? 'PUT' : 'POST';
    const res = await fetch(endpoint, {
      method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    });
    if (res.ok) { onSave(); onClose(); }
  }

  return (
    <div className="modal-backdrop" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="modal">
        <div className="modal-title">{editing ? 'Edit User' : 'Add User'}</div>
        <div className="modal-sub">Role controls what the user can see and do.</div>
        {!editing && (
          <>
            <div className="form-group">
              <label className="form-label">Username</label>
              <input className="form-input" value={username} onChange={e => setUsername(e.target.value)} placeholder="jsmith" />
            </div>
            <div className="form-group">
              <label className="form-label">Password</label>
              <input className="form-input" type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="••••••••" />
            </div>
          </>
        )}
        <div className="form-group">
          <label className="form-label">Role</label>
          <select className="form-select" value={role} onChange={e => setRole(e.target.value)}>
            <option value="admin">Admin — full access</option>
            <option value="analyst">Analyst — read + triage, no delete</option>
            <option value="viewer">Viewer — alert stream only</option>
          </select>
        </div>
        <div className="modal-footer">
          <button className="btn-modal" onClick={onClose}>Cancel</button>
          <button className="btn-modal confirm" onClick={submit}>{editing ? 'Save' : 'Create user'}</button>
        </div>
      </div>
    </div>
  );
}

function SettingsView({ theme, setTheme, role, username, onLogout }) {
  const [users,    setUsers]    = useState([]);
  const [health,   setHealth]   = useState(null);
  const [modal,    setModal]    = useState(null);
  const [whModal,  setWhModal]  = useState(null);
  const [webhooks, setWebhooks] = useState([]);
  const [testMsg,  setTestMsg]  = useState({});
  const [confirm,  setConfirm]  = useState(null);
  const isAdmin = role === 'admin';

  async function loadUsers()    { const r = await fetch('/users');    const d = await r.json(); setUsers(d.users || []); }
  async function loadHealth()   { const r = await fetch('/health');   const d = await r.json(); setHealth(d); }
  async function loadWebhooks() { const r = await fetch('/webhooks'); const d = await r.json(); setWebhooks(d.webhooks || []); }

  useEffect(() => { loadUsers(); loadHealth(); if (isAdmin) loadWebhooks(); }, []);

  async function toggleUser(u) {
    await fetch(`/users/${u.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: !u.enabled }) });
    loadUsers();
  }

  function confirmDeleteUser(u) {
    setConfirm({
      title: 'Delete user',
      body: <>Are you sure you want to delete <strong>{u.username}</strong>? This cannot be undone.</>,
      confirmLabel: 'Delete user',
      variant: 'danger',
      onConfirm: async () => { await fetch(`/users/${u.id}`, { method: 'DELETE' }); loadUsers(); },
    });
  }

  function confirmClearData(ep, label, count) {
    setConfirm({
      title: `Clear all ${label}`,
      body: <>This will permanently delete <strong>{count} {label} records</strong>. This action cannot be undone.</>,
      confirmLabel: `Clear ${label}`,
      variant: 'warning',
      onConfirm: async () => { await fetch(ep, { method: 'DELETE' }); loadHealth(); },
    });
  }

  async function toggleWebhook(wh) {
    await fetch(`/webhooks/${wh.id}`, { method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: !wh.enabled }) });
    loadWebhooks();
  }

  function confirmDeleteWebhook(wh) {
    setConfirm({
      title: 'Delete webhook',
      body: <>Delete <strong>{wh.name}</strong>? All configuration will be lost.</>,
      confirmLabel: 'Delete webhook',
      variant: 'danger',
      onConfirm: async () => { await fetch(`/webhooks/${wh.id}`, { method: 'DELETE' }); loadWebhooks(); },
    });
  }

  async function testWebhook(id) {
    setTestMsg(p => ({ ...p, [id]: 'Sending…' }));
    const r = await fetch(`/webhooks/${id}/test`, { method: 'POST' });
    const d = await r.json();
    setTestMsg(p => ({ ...p, [id]: d.ok ? '✓ Delivered' : '✗ ' + (d.error || 'Failed') }));
    setTimeout(() => setTestMsg(p => { const n = { ...p }; delete n[id]; return n; }), 3000);
  }

  function initials(name) { return name.slice(0, 2).toUpperCase(); }

  return (
    <div className="settings-layout">

      {/* Users */}
      {isAdmin && (
        <div className="settings-card">
          <div className="settings-card-header">
            <span className="settings-card-title">Users</span>
            <button className="btn-sm primary" onClick={() => setModal({})}>Add user</button>
          </div>
          <div className="settings-card-body">
            {users.map(u => (
              <div key={u.id} className={`user-row${!u.enabled ? ' user-disabled' : ''}`}>
                <div className="user-avatar">{initials(u.username)}</div>
                <div className="user-info">
                  <div className="user-name">{u.username}
                    {u.username === username && <span style={{ fontSize: 10, color: 'var(--tx3)', marginLeft: 6 }}>(you)</span>}
                  </div>
                  <div className="user-meta">
                    {u.last_login ? `Last login: ${new Date(u.last_login * 1000).toLocaleDateString()}` : 'Never logged in'}
                  </div>
                </div>
                <span className={`role-badge ${u.role}`}>{ROLE_META[u.role]?.label || u.role}</span>
                <button className="btn-sm" onClick={() => setModal(u)}>Edit</button>
                <button className="btn-sm danger" onClick={() => confirmDeleteUser(u)}>Delete</button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Webhooks */}
      {isAdmin && (
        <div className="settings-card">
          <div className="settings-card-header">
            <span className="settings-card-title">Webhooks</span>
            <button className="btn-sm primary" onClick={() => setWhModal({})}>Add webhook</button>
          </div>
          <div className="settings-card-body">
            {!webhooks.length && (
              <div style={{ color: 'var(--tx3)', fontSize: 12, padding: '8px 0' }}>No webhooks configured.</div>
            )}
            {webhooks.map(wh => (
              <div key={wh.id} className="wh-settings-card">
                <div className="wh-top">
                  <span className="wh-name">{wh.name}</span>
                  <span className="wh-type-badge">{wh.type.toUpperCase()}</span>
                  <button className={`wh-toggle${wh.enabled ? ' on' : ''}`} onClick={() => toggleWebhook(wh)} />
                </div>
                <div className="wh-url">{wh.url}</div>
                <div className="wh-sev">
                  {ALL_SEVS.map(s => {
                    const m = SEV_META[s]; const on = (wh.severities || []).includes(s);
                    return (
                      <span key={s} className={`wh-sev-pill${on ? ' on' : ''}`}
                            style={{ color: m.color, background: m.bg, border: `1px solid ${m.color}40` }}>
                        {m.label}
                      </span>
                    );
                  })}
                </div>
                <div className="wh-meta">
                  <span>Fired {wh.fire_count || 0}×</span>
                  {wh.last_fired && <span>Last: {new Date(wh.last_fired * 1000).toLocaleTimeString()}</span>}
                </div>
                <div className="wh-actions">
                  <button className="btn-sm" onClick={() => setWhModal(wh)}>Edit</button>
                  <button className="btn-sm" onClick={() => testWebhook(wh.id)}>{testMsg[wh.id] || 'Test'}</button>
                  <button className="btn-sm danger" onClick={() => confirmDeleteWebhook(wh)}>Delete</button>
                </div>
                {wh.last_error && <div className="wh-error">Last error: {wh.last_error}</div>}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Theme */}
      <div className="settings-card">
        <div className="settings-card-header"><span className="settings-card-title">Theme</span></div>
        <div className="settings-card-body">
          <div className="theme-grid">
            {THEMES.map(t => (
              <div key={t.id} className={`theme-tile${theme === t.id ? ' active' : ''}`}
                   onClick={() => { setTheme(t.id); document.documentElement.setAttribute('data-theme', t.id); localStorage.setItem('heimdall-theme', t.id); }}>
                <div style={{ display: 'flex', gap: 3, flexShrink: 0 }}>
                  <div style={{ width: 10, height: 10, borderRadius: 3, background: t.dot, border: '1px solid rgba(0,0,0,.18)', flexShrink: 0 }} />
                  <div style={{ width: 10, height: 10, borderRadius: 3, background: t.accent, flexShrink: 0 }} />
                </div>
                <span>{t.label}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Data management */}
      {isAdmin && (
        <div className="settings-card">
          <div className="settings-card-header"><span className="settings-card-title">Data management</span></div>
          <div className="settings-card-body">
            {[
              { label: 'Alerts',     sub: `${health?.db?.alerts?.total ?? '—'} records`, ep: '/alerts', count: health?.db?.alerts?.total ?? 0 },
              { label: 'Flows',      sub: `${health?.db?.flows?.total  ?? '—'} records`, ep: '/flows',  count: health?.db?.flows?.total  ?? 0 },
              { label: 'DNS events', sub: `${health?.db?.dns?.total    ?? '—'} records`, ep: '/dns',    count: health?.db?.dns?.total    ?? 0 },
            ].map(row => (
              <div key={row.label} className="data-action-row">
                <div>
                  <div className="data-action-info">{row.label}</div>
                  <div className="data-action-sub">{row.sub}</div>
                </div>
                <button className="btn-sm danger"
                        onClick={() => confirmClearData(row.ep, row.label.toLowerCase(), row.count)}>
                  Clear all
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Server health */}
      {health && (
        <div className="settings-card">
          <div className="settings-card-header"><span className="settings-card-title">Server health</span></div>
          <div className="settings-card-body">
            <div className="health-grid">
              {[
                { l: 'ALERTS',  v: health.db?.alerts?.total, s: `${health.db?.alerts?.recent} recent` },
                { l: 'FLOWS',   v: health.db?.flows?.total,  s: `${health.db?.flows?.recent} recent`  },
                { l: 'DNS',     v: health.db?.dns?.total,    s: `${health.db?.dns?.recent} recent`    },
                { l: 'HTTP',    v: health.db?.http?.total,   s: `${health.db?.http?.recent} recent`   },
                { l: 'CLIENTS', v: health.clients,           s: 'connected'                           },
              ].map(r => (
                <div key={r.l} className="health-stat">
                  <div className="health-stat-label">{r.l}</div>
                  <div className="health-stat-value">{(r.v || 0).toLocaleString()}</div>
                  <div className="health-stat-sub">{r.s}</div>
                </div>
              ))}
              <div className="health-stat" style={{ gridColumn: 'span 2' }}>
                <div className="health-stat-label">OLDEST RECORD</div>
                <div className="health-stat-value" style={{ fontSize: 11 }}>
                  {health.db?.oldest ? new Date(health.db.oldest).toLocaleDateString() : '—'}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Account / Sign out */}
      <div className="settings-card">
        <div className="settings-card-header"><span className="settings-card-title">Account</span></div>
        <div className="settings-card-body">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div>
              <div style={{ fontSize: 13, fontWeight: 500, color: 'var(--tx1)' }}>{username}</div>
              <div style={{ fontSize: 10, color: 'var(--tx3)', fontFamily: 'var(--mono)', marginTop: 3 }}>
                {ROLE_META[role]?.label || role} · Currently signed in
              </div>
            </div>
            <button className="btn-sm danger" onClick={() => setConfirm({
              title: 'Sign out',
              body: 'Are you sure you want to sign out of Heimdall?',
              confirmLabel: 'Sign out',
              variant: 'warning',
              onConfirm: onLogout,
            })}>
              Sign out
            </button>
          </div>
        </div>
      </div>

      {modal !== null && (
        <UserModal initial={modal.id ? modal : null} onSave={loadUsers} onClose={() => setModal(null)} />
      )}
      {whModal !== null && (
        <WebhookModal initial={whModal.id ? whModal : null} onSave={loadWebhooks} onClose={() => setWhModal(null)} />
      )}
      {confirm !== null && (
        <ConfirmDialog
          title={confirm.title}
          body={confirm.body}
          confirmLabel={confirm.confirmLabel}
          variant={confirm.variant}
          onConfirm={confirm.onConfirm}
          onClose={() => setConfirm(null)}
        />
      )}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// ROOT APP
// ══════════════════════════════════════════════════════════════════════════════

function App() {
  const [alerts,     setAlerts]     = useState([]);
  const [view,       setView]       = useState('alerts');
  const [selectedId, setSelectedId] = useState(null);
  const [svFilter,   setSvFilter]   = useState('all');
  const [search,     setSearch]     = useState('');
  const [sparkData,  setSparkData]  = useState(() => Array.from({ length: 24 }, () => Math.floor(Math.random() * 5)));
  const [theme,      setTheme]      = useState(() => {
    const saved = localStorage.getItem('heimdall-theme');
    if (saved) document.documentElement.setAttribute('data-theme', saved);
    return saved || 'night';
  });
  const [dbStats,    setDbStats]    = useState({ alerts: 0, flows: 0, dns: 0 });
  const [role,       setRole]       = useState('viewer');   // loaded from /me
  const [username,   setUsername]   = useState('');
  const [connected,  setConnected]  = useState(false);
  const [selectedAlerts, setSelectedAlerts] = useState(new Set());
  const [filteredAlertIds, setFilteredAlertIds] = useState([]);
  const [allFilteredSelected, setAllFilteredSelected] = useState(false);

  function toggleSelectAlert(id) {
    setSelectedAlerts(prev => {
      const n = new Set(prev);
      if (n.has(id)) n.delete(id); else n.add(id);
      return n;
    });
  }

  function selectAllVisible(ids) {
    setSelectedAlerts(new Set(ids));
  }

  function clearSelection() {
    setSelectedAlerts(new Set());
  }

  async function bulkSetStatus(status) {
    const ids = [...selectedAlerts];
    if (!ids.length) return;
    const res = await fetch('/alerts/bulk-status', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ alert_ids: ids, status }),
    });
    if (res.ok) {
      setAlerts(prev => prev.map(a => selectedAlerts.has(a.id) ? { ...a, status } : a));
      clearSelection();
    }
  }

  

  // ── Load current user + initial data ──────────────────────────────────────
  useEffect(() => {
    fetch('/me')
      .then(r => r.json())
      .then(d => { setRole(d.role || 'viewer'); setUsername(d.username || ''); })
      .catch(() => {});

    fetch('/alerts?limit=200')
      .then(r => r.json())
      .then(d => {
        const rows = d.alerts || [];
        setAlerts(rows);
        if (rows.length) setSelectedId(rows[0].id);
      })
      .catch(() => {});

    fetch('/health')
      .then(r => r.json())
      .then(d => setDbStats({
        alerts: d.db?.alerts?.total || 0,
        flows:  d.db?.flows?.total  || 0,
        dns:    d.db?.dns?.total    || 0,
      }))
      .catch(() => {});
  }, []);

  // ── SSE ────────────────────────────────────────────────────────────────────
  useEffect(() => {
    let es;
    function connect() {
      es = new EventSource('/events');
      es.addEventListener('alert', e => {
        try {
          const a = JSON.parse(e.data);
          a._new = true;
          setAlerts(prev => {
            if (prev.find(x => x.id === a.id)) return prev;
            return [a, ...prev].slice(0, 500);
          });
          setSparkData(prev => {
            const n = [...prev.slice(1)];
            n.push(prev[prev.length - 1] + 1);
            return n;
          });
          setTimeout(() => setAlerts(prev => prev.map(x => x.id === a.id ? { ...x, _new: false } : x)), 600);
        } catch {}
      });
      es.addEventListener('ping', () => {});
      es.onopen  = () => setConnected(true);
      es.onerror = () => { setConnected(false); es.close(); setTimeout(connect, 3000); };
    }
    connect();
    return () => es?.close();
  }, []);

  // ── Sparkline idle decay ───────────────────────────────────────────────────
  useEffect(() => {
    const id = setInterval(() => {
      setSparkData(prev => [...prev.slice(1), Math.max(0, prev[prev.length - 1] - 1 + Math.floor(Math.random() * 2))]);
    }, 4000);
    return () => clearInterval(id);
  }, []);

  // ── Theme propagation ──────────────────────────────────────────────────────
  function applyTheme(t) {
    setTheme(t);
    document.documentElement.setAttribute('data-theme', t);
    localStorage.setItem('heimdall-theme', t);
  }

  // ── Logout ─────────────────────────────────────────────────────────────────
  async function handleLogout() {
    try {
      await fetch('/logout', { method: 'POST' });
    } catch {}
    window.location.href = '/login';
  }

  const selectedAlert = alerts.find(a => a.id === selectedId) || null;
  const VIEW_TITLES   = { alerts: 'Alert Feed', flows: 'Flow Events', dns: 'DNS Queries',
                          charts: 'Analytics', settings: 'Settings' };

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <div className="shell">

      {/* Top Bar */}
      <header className="topbar">
        <div className="logo">
          <div className="logo-icon">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none">
              <path d="M12 2L3 6v6c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V6L12 2z"
                    fill="white" fillOpacity="0.15" stroke="white" strokeWidth="1.7"
                    strokeLinejoin="round"/>
              <path d="M9 12l2 2 4-4" stroke="var(--logo-a)" strokeWidth="1.8"
                    strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </div>
          <div className="logo-text">
            <span className="logo-name">Heimdall</span>
            <span className="logo-sub">IDS DASHBOARD</span>
          </div>
        </div>

        <div className="sparkline-wrap">
          <Sparkline data={sparkData} />
          <span className="spark-label">60s volume</span>
        </div>

        <div className="topbar-right">
          <div className="stat-chip"><strong>{dbStats.alerts.toLocaleString()}</strong> alerts</div>
          <div className="stat-chip"><strong>{dbStats.flows.toLocaleString()}</strong> flows</div>
          <div className="stat-chip"><strong>{dbStats.dns.toLocaleString()}</strong> dns</div>

          <div className="view-tabs">
            {['alerts','flows','dns','charts','settings'].map(v => (
              <button key={v} className={`tab-btn${view === v ? ' active' : ''}`}
                      onClick={() => setView(v)}>
                {v.charAt(0).toUpperCase() + v.slice(1)}
              </button>
            ))}
          </div>

          <div className="live-pill">
            <div className="live-dot" style={{ background: connected ? 'var(--success)' : 'var(--sev-medium)' }} />
            <span>{connected ? 'LIVE' : 'RECONNECTING'}</span>
          </div>

          {username && (
            <button className="logout-btn" onClick={handleLogout} title="Sign out">
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none"
                   stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>
                <polyline points="16 17 21 12 16 7"/>
                <line x1="21" y1="12" x2="9" y2="12"/>
              </svg>
              {username}
            </button>
          )}
        </div>
      </header>

      {/* Body */}
      <div className="body">
        {view === 'alerts' && (
          <Sidebar alerts={alerts}
                   svFilter={svFilter} setSvFilter={setSvFilter}
                   search={search}     setSearch={setSearch}
                   selectedAlert={selectedAlerts.size > 0 ? null : selectedAlert} />
        )}

        <div className="main">
          <div className="main-header">
            <span className="main-title">{VIEW_TITLES[view]}</span>
            {view === 'alerts' && <span className="main-count">{alerts.length} events</span>}
            <div className="main-flex" />
            {view === 'alerts' && (
              <>
                <button className="btn-sm"
                  onClick={() => allFilteredSelected ? selectAllVisible([]) : selectAllVisible(filteredAlertIds)}
                  style={{ fontSize: 10, padding: '2px 8px' }}>
                  {allFilteredSelected ? 'Deselect All' : 'Select All'}
                </button>
                <span className="main-sort">Grouped by <span>severity</span></span>
              </>
            )}
          </div>

          {view === 'alerts'   && (
            <>
              <AlertFeed alerts={alerts} svFilter={svFilter}
                         search={search} selectedId={selectedId} onSelect={setSelectedId}
                         selectedAlerts={selectedAlerts}
                         onToggleSelect={toggleSelectAlert}
                         onSelectAll={selectAllVisible}
                         onFilteredIds={(ids, allSel) => { setFilteredAlertIds(ids); setAllFilteredSelected(allSel); }} />
            </>
          )}
          {view === 'flows'    && <FlowsView />}
          {view === 'dns'      && <DNSView />}
          {view === 'charts'   && <ChartsView />}
          {view === 'settings' && <SettingsView theme={theme} setTheme={applyTheme}
                                    role={role} username={username} onLogout={handleLogout} />}
        </div>

        {view === 'alerts' && (
          selectedAlerts.size > 0
            ? <BulkPanel
                selectedAlerts={selectedAlerts}
                alerts={alerts}
                role={role}
                onBulkStatus={bulkSetStatus}
                onClearSelection={clearSelection}
              />
            : <DetailPanel alert={selectedAlert} role={role} />
        )}
      </div>

      {/* Status Bar */}
      <footer className="statusbar">
        <div className="status-item">
          <div className="status-dot" style={{ background: 'var(--success)' }} />Database
        </div>
        <div className="status-item">
          <div className="status-dot" style={{ background: connected ? 'var(--success)' : 'var(--sev-medium)' }} />
          {connected ? 'Tail active' : 'Reconnecting…'}
        </div>
        <span className="status-sep">|</span>
        <div className="status-item">Retain 90 days</div>
        {username && <div className="status-item" style={{ color: 'var(--tx4)' }}>{username} · {role}</div>}
      </footer>

    </div>
  );
}

// ── Mount ──────────────────────────────────────────────────────────────────────
ReactDOM.createRoot(document.getElementById('root')).render(<App />);

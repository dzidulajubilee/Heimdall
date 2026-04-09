/**
 * Heimdall IDS Dashboard — Main React Application
 * Loaded by index.html via <script type="text/babel" src="/frontend/app.jsx">
 *
 * External deps (loaded before this file in index.html):
 *   - React 18  (window.React)
 *   - ReactDOM  (window.ReactDOM)
 *   - Babel standalone (transpiles JSX in the browser)
 *
 * This file must be self-contained: no ES module imports.
 * ThemePicker and THEMES come from themes.js, also loaded in index.html.
 */

/* global React, ReactDOM, ThemePicker */

const { useState, useEffect, useRef } = React;

// ── Constants ────────────────────────────────────────────────────────────────
const MAX_ALERTS = 2000;
const SSE_URL    = '/events';

const SEV_COLORS = {
  critical: 'var(--red)',
  high:     'var(--orange)',
  medium:   'var(--yellow)',
  low:      'var(--green)',
  info:     'var(--accent)',
};

// ── Helpers ───────────────────────────────────────────────────────────────────
function fmtTime(ts) {
  try { return new Date(ts).toLocaleTimeString('en-GB', { hour12: false }); }
  catch { return '--:--:--'; }
}

// ── Clock ─────────────────────────────────────────────────────────────────────
function Clock() {
  const [t, setT] = useState('');
  useEffect(() => {
    const tick = () => setT(new Date().toLocaleTimeString('en-GB', { hour12: false }));
    tick();
    const id = setInterval(tick, 500);
    return () => clearInterval(id);
  }, []);
  return <span className="clock">{t}</span>;
}

// ── Sparkline ─────────────────────────────────────────────────────────────────
function Sparkline({ data }) {
  const max = Math.max(1, ...data);
  return (
    <div className="spark-wrap">
      <div className="spark-label">Alerts / 60s window</div>
      <div className="spark-row">
        {data.map((v, i) => (
          <div key={i} className="spark-bar"
               style={{ height: Math.max(2, Math.round((v / max) * 26)) }} />
        ))}
      </div>
    </div>
  );
}

// ── Timeline ──────────────────────────────────────────────────────────────────
function Timeline({ alerts }) {
  return (
    <div className="tline">
      {alerts.slice(0, 8).map((a, i) => (
        <div key={a.id || i} className="tl-item">
          <div className="tl-dot" style={{ background: SEV_COLORS[a.severity] }} />
          <div className="tl-time">{fmtTime(a.ts)}</div>
          <div className="tl-msg">{a.sig_msg}</div>
        </div>
      ))}
    </div>
  );
}

// ── Detail Panel ──────────────────────────────────────────────────────────────
function Detail({ alert }) {
  if (!alert) return (
    <div className="dscroll">
      <div className="empty" style={{ height: '100%' }}>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1">
          <rect x="3" y="3" width="18" height="18" rx="2" />
          <line x1="3" y1="9" x2="21" y2="9" />
          <line x1="9" y1="21" x2="9"  y2="9" />
        </svg>
        <div>Select an alert</div>
        <div style={{ fontSize: 10 }}>to view full details</div>
      </div>
    </div>
  );

  // Syntax-highlight raw JSON
  const coloredRaw = JSON.stringify(alert.raw || alert, null, 2)
    .replace(/"([^"]+)":/g, (_, k) =>
      `<span style="color:var(--accent)">"${k}"</span>:`)
    .replace(/: "([^"]*)"/g, (_, v) =>
      `: <span style="color:var(--green)">"${v}"</span>`)
    .replace(/: (\d+)/g, (_, v) =>
      `: <span style="color:var(--orange)">${v}</span>`)
    .replace(/: (true|false)/g, (_, v) =>
      `: <span style="color:var(--purple)">${v}</span>`);

  const F = ({ label, val, full, color }) => (
    <div className={`dfield${full ? ' dfull' : ''}`}>
      <div className="dfield-label">{label}</div>
      <div className="dfield-val" style={color ? { color } : {}}>{val ?? '—'}</div>
    </div>
  );

  return (
    <div className="dscroll">
      <div className="dsec">
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
          <span className={`sbadge ${alert.severity}`}>{alert.severity}</span>
          <span style={{ fontSize: 13, fontWeight: 500, lineHeight: 1.3 }}>
            {alert.sig_msg}
          </span>
        </div>
      </div>

      <div className="dsec">
        <div className="dsec-title">Network</div>
        <div className="dgrid">
          <F label="Source IP"   val={alert.src_ip} />
          <F label="Source Port" val={alert.src_port} />
          <F label="Dest IP"     val={alert.dst_ip} />
          <F label="Dest Port"   val={alert.dst_port} />
          <F label="Protocol"    val={alert.proto} />
          <F label="Action"      val={alert.action}
             color={alert.action === 'blocked' ? 'var(--red)' : 'var(--green)'} />
        </div>
      </div>

      <div className="dsec">
        <div className="dsec-title">Signature</div>
        <div className="dgrid">
          <F label="SID"        val={alert.sig_id} />
          <F label="Category"   val={alert.category} />
          <F label="Flow ID"    val={alert.flow_id}  full />
          <F label="Timestamp"  val={alert.ts}        full />
        </div>
      </div>

      <div className="dsec">
        <div className="dsec-title">Raw EVE JSON</div>
        <pre className="rawjson"
             dangerouslySetInnerHTML={{ __html: coloredRaw }} />
      </div>
    </div>
  );
}

// ── App ───────────────────────────────────────────────────────────────────────
function App() {
  // ── State ──────────────────────────────────────────────────────────────────
  const [alerts,       setAlerts]       = useState([]);
  const [selected,     setSelected]     = useState(null);
  const [paused,       setPaused]       = useState(false);
  const [search,       setSearch]       = useState('');
  const [activeSev,    setActiveSev]    = useState(
    new Set(['critical', 'high', 'medium', 'low', 'info'])
  );
  const [connState,    setConnState]    = useState('connecting');
  const [sparkData,    setSparkData]    = useState(new Array(30).fill(0));
  const [rate,         setRate]         = useState(0);
  const [historyCount, setHistoryCount] = useState(0);
  const [showConfirm,  setShowConfirm]  = useState(false);
  const [clearing,     setClearing]     = useState(false);
  const [theme,        setTheme]        = useState(
    () => localStorage.getItem('heimdall-theme') || 'night'
  );

  const pausedRef   = useRef(false);
  const accumRef    = useRef(0);
  const sparkIdxRef = useRef(0);
  const newIdsRef   = useRef(new Set());

  // ── Theme ──────────────────────────────────────────────────────────────────
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('heimdall-theme', theme);
  }, [theme]);

  // ── Load history ───────────────────────────────────────────────────────────
  useEffect(() => {
    fetch('/alerts?limit=5000')
      .then(r => {
        if (r.status === 401) { window.location.href = '/login'; throw new Error(); }
        return r.json();
      })
      .then(rows => {
        if (!Array.isArray(rows)) return;
        const loaded = rows.map(r => ({ ...r, tsStr: fmtTime(r.ts) }));
        setAlerts(loaded);
        setHistoryCount(loaded.length);
      })
      .catch(() => {});
  }, []);

  // ── SSE connection ─────────────────────────────────────────────────────────
  useEffect(() => {
    let es;
    let retryTimer;

    function connect() {
      setConnState('connecting');
      es = new EventSource(SSE_URL);

      es.addEventListener('ping', () => setConnState('live'));

      es.addEventListener('alert', e => {
        setConnState('live');
        if (pausedRef.current) return;
        try {
          const evt = JSON.parse(e.data);
          evt.tsStr = fmtTime(evt.ts);
          accumRef.current++;
          newIdsRef.current.add(evt.id);
          setTimeout(() => newIdsRef.current.delete(evt.id), 400);
          setAlerts(prev => {
            if (prev.some(x => x.id === evt.id)) return prev;
            return [evt, ...prev].slice(0, MAX_ALERTS);
          });
        } catch {}
      });

      es.onerror = () => {
        es.close();
        fetch('/health')
          .then(r => {
            if (r.status === 401) {
              window.location.href = '/login';
            } else {
              setConnState('reconnecting');
              retryTimer = setTimeout(connect, 3000);
            }
          })
          .catch(() => {
            setConnState('reconnecting');
            retryTimer = setTimeout(connect, 3000);
          });
      };
    }

    connect();
    return () => { es && es.close(); clearTimeout(retryTimer); };
  }, []);

  // ── Pause ref sync ─────────────────────────────────────────────────────────
  useEffect(() => { pausedRef.current = paused; }, [paused]);

  // ── Sparkline ticker (1 s) ─────────────────────────────────────────────────
  useEffect(() => {
    const id = setInterval(() => {
      const n = accumRef.current;
      accumRef.current = 0;
      setRate(n);
      setSparkData(prev => {
        const next = [...prev];
        next[sparkIdxRef.current % 30] = n;
        sparkIdxRef.current++;
        return next;
      });
    }, 1000);
    return () => clearInterval(id);
  }, []);

  // ── Clear handler ──────────────────────────────────────────────────────────
  async function handleClear() {
    setClearing(true);
    try { await fetch('/alerts', { method: 'DELETE' }); } catch {}
    setAlerts([]);
    setSelected(null);
    setHistoryCount(0);
    setClearing(false);
    setShowConfirm(false);
  }

  // ── Derived state ──────────────────────────────────────────────────────────
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  alerts.forEach(a => { counts[a.severity] = (counts[a.severity] || 0) + 1; });

  const uniqueSrcs = new Set(alerts.map(a => a.src_ip)).size;

  const topCat = (() => {
    const cc = {};
    alerts.forEach(a => { cc[a.category] = (cc[a.category] || 0) + 1; });
    let top = '—', mx = 0;
    for (const [k, v] of Object.entries(cc)) { if (v > mx) { mx = v; top = k; } }
    return { name: top, count: mx };
  })();

  const topSrcs = (() => {
    const cc = {};
    alerts.forEach(a => { cc[a.src_ip] = (cc[a.src_ip] || 0) + 1; });
    return Object.entries(cc).sort((a, b) => b[1] - a[1]).slice(0, 5);
  })();

  const q = search.toLowerCase();
  const filtered = alerts.filter(a =>
    activeSev.has(a.severity) && (
      !q ||
      a.sig_msg?.toLowerCase().includes(q) ||
      a.src_ip?.includes(q) ||
      a.dst_ip?.includes(q) ||
      String(a.sig_id).includes(q) ||
      a.category?.toLowerCase().includes(q)
    )
  );

  function toggleSev(s) {
    setActiveSev(prev => {
      const next = new Set(prev);
      if (next.has(s)) { if (next.size > 1) next.delete(s); }
      else next.add(s);
      return next;
    });
  }

  const connColor = {
    live: 'var(--green)', connecting: 'var(--yellow)', reconnecting: 'var(--text3)',
  }[connState];
  const connLabel = {
    live: 'LIVE', connecting: 'CONNECTING…', reconnecting: 'RECONNECTING…',
  }[connState];

  // ── Render ─────────────────────────────────────────────────────────────────
  return (
    <div className="shell">

      {/* ── Topbar ── */}
      <header className="topbar">
        <div className="logo">
          <div className="logo-box">
            <svg className="logo-eye" viewBox="0 0 24 24" fill="none">
              <ellipse cx="12" cy="12" rx="10" ry="7"
                       stroke="white" strokeWidth="1.8" strokeOpacity=".9"/>
              <circle  cx="12" cy="12" r="3"
                       fill="white" fillOpacity=".9"/>
              <circle  cx="12" cy="12" r="1.2"
                       fill="white" fillOpacity=".4"/>
            </svg>
          </div>
          HEIMDALL
        </div>
        <div className="sep"/>
        <div className="badge">
          <div className="dot" style={{ background: connColor }}/>
          <span style={{
            color: connColor,
            fontFamily: 'var(--mono)',
            fontSize: 11,
            letterSpacing: '.06em',
          }}>{connLabel}</span>
        </div>
        <div className="sep"/>
        <div className="pill">Interface: <b style={{ marginLeft: 4 }}>eth0</b></div>
        <div className="pill">Engine:
          <b style={{ marginLeft: 4, color: 'var(--green)' }}>Running</b>
        </div>
        <div className="right">
          <div className="pill">Alerts/s: <b style={{ marginLeft: 4 }}>{rate}</b></div>
          <Clock/>
          <ThemePicker theme={theme} onChange={setTheme}/>
          <a href="/logout" className="signout">SIGN OUT</a>
        </div>
      </header>

      {/* ── Sidebar ── */}
      <aside className="sidebar">
        <div className="s-label">Views</div>
        <div className="nav-item active">
          <svg width="14" height="14" viewBox="0 0 16 16"
               fill="none" stroke="currentColor" strokeWidth="1.5">
            <path d="M8 2L14 13H2L8 2Z"/>
            <line x1="8" y1="7" x2="8" y2="10"/>
            <circle cx="8" cy="12" r=".5" fill="currentColor"/>
          </svg>
          Alerts
          <span className="nav-badge">
            {alerts.length > 999 ? '999+' : alerts.length}
          </span>
        </div>

        <div className="divider"/>

        <div className="s-label">Severity</div>
        {['critical', 'high', 'medium', 'low', 'info'].map(s => (
          <div key={s}
               className={`sev-row${activeSev.has(s) ? ' on' : ''}`}
               onClick={() => toggleSev(s)}>
            <div className="sev-dot" style={{ background: SEV_COLORS[s] }}/>
            {s.charAt(0).toUpperCase() + s.slice(1)}
            <span className="sev-cnt">{counts[s]}</span>
          </div>
        ))}

        <div className="divider"/>

        <div className="s-label">Top Sources</div>
        {topSrcs.map(([ip, cnt]) => (
          <div key={ip} className="src-row">
            <span className="src-ip">{ip}</span>
            <span className="src-cnt">{cnt}</span>
          </div>
        ))}
        {topSrcs.length === 0 && (
          <div style={{
            padding: '4px 18px', fontSize: 11,
            color: 'var(--text3)', fontFamily: 'var(--mono)',
          }}>no data yet</div>
        )}
      </aside>

      {/* ── Main ── */}
      <main className="main">

        {/* Metrics */}
        <div className="metrics">
          {[
            { label: 'Total Alerts',    val: alerts.length, color: '' },
            { label: 'Critical',        val: counts.critical, color: 'var(--red)' },
            { label: 'High',            val: counts.high,     color: 'var(--orange)' },
            { label: 'Medium',          val: counts.medium,   color: 'var(--yellow)' },
            { label: 'Unique Sources',  val: uniqueSrcs,      color: '' },
            { label: 'Top Category',    val: topCat.name,     color: '',
              sub: topCat.count ? `${topCat.count} alerts` : '' },
          ].map(m => (
            <div key={m.label} className="metric">
              <div className="metric-label">{m.label}</div>
              <div className="metric-val"
                   style={m.color ? { color: m.color } : { fontSize: m.label === 'Top Category' ? 14 : undefined, paddingTop: m.label === 'Top Category' ? 4 : undefined }}>
                {m.val}
              </div>
              {m.sub && <div className="metric-sub">{m.sub}</div>}
            </div>
          ))}
        </div>

        {/* Content area */}
        <div className="content">

          {/* Alert table */}
          <div style={{
            display: 'flex', flexDirection: 'column',
            overflow: 'hidden', borderRight: '1px solid var(--border)',
          }}>
            <div className="pane-head">
              <span className="pane-title">Alert Stream</span>
              <span className="pane-cnt">{filtered.length.toLocaleString()}</span>
              {historyCount > 0 && (
                <span style={{
                  fontSize: 10, fontFamily: 'var(--mono)', color: 'var(--text3)',
                  background: 'var(--bg2)', border: '1px solid var(--border)',
                  padding: '1px 7px', borderRadius: 10,
                }}>
                  {historyCount.toLocaleString()} stored
                </span>
              )}
              <div className="pane-actions">
                <div className="search">
                  <svg width="12" height="12" viewBox="0 0 16 16"
                       fill="none" stroke="currentColor" strokeWidth="1.5">
                    <circle cx="7" cy="7" r="4"/>
                    <path d="M10 10l3 3"/>
                  </svg>
                  <input placeholder="Search alerts…"
                         value={search}
                         onChange={e => setSearch(e.target.value)}/>
                </div>
                <button className={`btn${paused ? '' : ' on'}`}
                        onClick={() => setPaused(p => !p)}>
                  {paused ? 'Resume' : 'Pause'}
                </button>
                <button className="btn"
                        onClick={() => setShowConfirm(true)}>
                  Clear
                </button>
              </div>
            </div>

            <div className="tscroll">
              {filtered.length === 0 ? (
                <div className="empty">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1">
                    <rect x="3" y="3" width="18" height="18" rx="2"/>
                    <line x1="3" y1="9"  x2="21" y2="9"/>
                    <line x1="9" y1="21" x2="9"  y2="9"/>
                  </svg>
                  <div>
                    {connState === 'live'
                      ? 'No alerts match current filters'
                      : 'Connecting…'}
                  </div>
                </div>
              ) : (
                <table>
                  <thead>
                    <tr>
                      <th style={{ width: 80  }}>Time</th>
                      <th style={{ width: 82  }}>Severity</th>
                      <th style={{ width: 52  }}>Proto</th>
                      <th>Signature</th>
                      <th style={{ width: 115 }}>Source</th>
                      <th style={{ width: 115 }}>Destination</th>
                      <th style={{ width: 52  }}>SID</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.slice(0, 300).map((a, i) => (
                      <tr key={a.id || i}
                          className={[
                            'arow',
                            selected?.id === a.id     ? 'sel' : '',
                            newIdsRef.current.has(a.id) ? 'new' : '',
                          ].filter(Boolean).join(' ')}
                          onClick={() => setSelected(a)}>
                        <td className="mono-dim">{a.tsStr || fmtTime(a.ts)}</td>
                        <td>
                          <span className={`sbadge ${a.severity}`}>
                            {a.severity}
                          </span>
                        </td>
                        <td><span className="proto">{a.proto}</span></td>
                        <td style={{ fontSize: 12, color: 'var(--text1)' }}>
                          {a.sig_msg}
                        </td>
                        <td className="mono">{a.src_ip}:{a.src_port}</td>
                        <td className="mono">{a.dst_ip}:{a.dst_port}</td>
                        <td className="mono-dim">{a.sig_id}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>

          {/* Detail + sparkline + timeline */}
          <div className="detail">
            <div className="pane-head">
              <span className="pane-title">Event Detail</span>
            </div>
            <Detail alert={selected}/>
            <Sparkline data={sparkData}/>
            <Timeline alerts={alerts}/>
          </div>
        </div>
      </main>

      {/* Confirm clear modal */}
      {showConfirm && (
        <div className="modal-bg" onClick={() => setShowConfirm(false)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <div style={{ fontSize: 15, fontWeight: 500, marginBottom: 10 }}>
              Clear all alerts?
            </div>
            <div style={{
              fontSize: 12, color: 'var(--text2)',
              lineHeight: 1.7, marginBottom: 24,
            }}>
              This will permanently delete{' '}
              <b style={{ color: 'var(--text1)' }}>
                {(historyCount || alerts.length).toLocaleString()} stored alerts
              </b>{' '}
              from the database. This action cannot be undone.
            </div>
            <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
              <button className="btn"
                      onClick={() => setShowConfirm(false)}
                      disabled={clearing}
                      style={{ minWidth: 80 }}>
                Cancel
              </button>
              <button onClick={handleClear}
                      disabled={clearing}
                      style={{
                        minWidth: 80, padding: '4px 14px',
                        borderRadius: 'var(--radius-sm)',
                        border: '1px solid var(--red)',
                        background: 'var(--red-d)',
                        color: 'var(--red)', fontSize: 11,
                        fontFamily: 'var(--sans)',
                        cursor: clearing ? 'wait' : 'pointer',
                        transition: 'all .15s',
                      }}>
                {clearing ? 'Clearing…' : 'Yes, delete all'}
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}

// ── Mount ─────────────────────────────────────────────────────────────────────
ReactDOM.createRoot(document.getElementById('root')).render(<App/>);

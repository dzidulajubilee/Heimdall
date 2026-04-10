/**
 * Heimdall IDS Dashboard — Main React Application
 * Loaded by index.html via <script type="text/babel" src="/frontend/app.jsx">
 *
 * External deps (loaded before this file in index.html):
 *   - React 18  (window.React)
 *   - ReactDOM  (window.ReactDOM)
 *   - Babel standalone (transpiles JSX in the browser)
 *   - themes.js (provides THEMES and ThemePicker)
 *
 * This file must be self-contained: no ES module imports.
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

function fmtBytes(n) {
  if (!n || n === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(n) / Math.log(1024));
  return (n / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1) + ' ' + units[i];
}

function fmtDur(s) {
  if (!s || s === 0) return '0s';
  if (s < 60)  return s.toFixed(1) + 's';
  if (s < 3600) return Math.floor(s / 60) + 'm ' + Math.floor(s % 60) + 's';
  return Math.floor(s / 3600) + 'h ' + Math.floor((s % 3600) / 60) + 'm';
}

function statusClass(code) {
  if (!code) return '';
  if (code >= 500) return 'status-err';
  if (code >= 400) return 'status-err';
  if (code >= 300) return 'status-redir';
  return 'status-ok';
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



// ── FlowsView ─────────────────────────────────────────────────────────────────
function FlowsView({ rows, loading, selected, onSelect, onClear }) {
  const [search, setSearch] = useState('');
  const [showClearConfirm, setShowClearConfirm] = useState(false);
  const q = search.toLowerCase();
  const filtered = rows.filter(r =>
    !q || r.src_ip?.includes(q) || r.dst_ip?.includes(q) ||
    r.proto?.toLowerCase().includes(q) || r.app_proto?.toLowerCase().includes(q)
  );

  const handleClearClick = () => {
    setShowClearConfirm(true);
  };

  const handleConfirmClear = () => {
    setShowClearConfirm(false);
    onClear && onClear();
  };

  return (
    <div style={{display:'flex',flexDirection:'column',overflow:'hidden',flex:1}}>
      <div className="pane-head">
        <span className="pane-title" style={{color:'var(--teal)'}}>Flow Events</span>
        <span className="pane-cnt">{filtered.length.toLocaleString()}</span>
        <div className="pane-actions">
          <div className="search">
            <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
              <circle cx="7" cy="7" r="4"/><path d="M10 10l3 3"/>
            </svg>
            <input placeholder="Filter flows…" value={search} onChange={e=>setSearch(e.target.value)}/>
          </div>
          <button className="btn" onClick={handleClearClick}>Clear</button>
        </div>
      </div>
      <div className="tscroll">
        {loading ? (
          <div className="empty"><div>Loading…</div></div>
        ) : filtered.length === 0 ? (
          <div className="empty">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
            <div>No flow events yet</div>
          </div>
        ) : (
          <table>
            <thead><tr>
              <th style={{width:80}}>Time</th>
              <th style={{width:52}}>Proto</th>
              <th style={{width:105}}>Source</th>
              <th style={{width:105}}>Destination</th>
              <th style={{width:72}}>App Proto</th>
              <th style={{width:70}}>State</th>
              <th style={{width:80}}>↑ Bytes</th>
              <th style={{width:80}}>↓ Bytes</th>
              <th style={{width:65}}>Duration</th>
              <th style={{width:52}}>Alert</th>
            </tr></thead>
            <tbody>
              {filtered.slice(0,300).map((r,i) => (
                <tr key={r.flow_id||i}
                    className={`arow${selected?.flow_id===r.flow_id?' sel':''}`}
                    onClick={()=>onSelect(r)}>
                  <td className="mono-dim">{fmtTime(r.ts)}</td>
                  <td><span className="proto">{r.proto}</span></td>
                  <td className="mono">{r.src_ip}:{r.src_port}</td>
                  <td className="mono">{r.dst_ip}:{r.dst_port}</td>
                  <td className="mono-dim">{r.app_proto||'—'}</td>
                  <td className="mono-dim">{r.state}</td>
                  <td className="mono-dim">{fmtBytes(r.bytes_toserver)}</td>
                  <td className="mono-dim">{fmtBytes(r.bytes_toclient)}</td>
                  <td className="mono-dim">{fmtDur(r.duration_s)}</td>
                  <td><span style={{color:r.alerted?'var(--red)':'var(--text3)',fontSize:10,fontFamily:'var(--mono)'}}>{r.alerted?'YES':'—'}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {showClearConfirm && (
        <div className="modal-bg" onClick={() => setShowClearConfirm(false)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <div style={{ fontSize: 15, fontWeight: 500, marginBottom: 10 }}>
              Clear all flow events?
            </div>
            <div style={{
              fontSize: 12, color: 'var(--text2)',
              lineHeight: 1.7, marginBottom: 24,
            }}>
              This will permanently delete{' '}
              <b style={{ color: 'var(--text1)' }}>
                {rows.length.toLocaleString()} stored flows
              </b>{' '}
              from the database. This action cannot be undone.
            </div>
            <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
              <button className="btn"
                      onClick={() => setShowClearConfirm(false)}
                      style={{ minWidth: 80 }}>
                Cancel
              </button>
              <button onClick={handleConfirmClear}
                      style={{
                        minWidth: 80, padding: '4px 14px',
                        borderRadius: 'var(--radius-sm)',
                        border: '1px solid var(--red)',
                        background: 'var(--red-d)',
                        color: 'var(--red)', fontSize: 11,
                        fontFamily: 'var(--sans)',
                        cursor: 'pointer',
                        transition: 'all .15s',
                      }}>
                Yes, delete all
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── FlowDetail ────────────────────────────────────────────────────────────────
function FlowDetail({ item }) {
  if (!item) return (
    <div className="dscroll">
      <div className="empty" style={{height:'100%'}}>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
        <div>Select a flow</div>
      </div>
    </div>
  );
  const F = ({label,val,full,color})=>(
    <div className={`dfield${full?' dfull':''}`}>
      <div className="dfield-label">{label}</div>
      <div className="dfield-val" style={color?{color}:{}}>{val??'—'}</div>
    </div>
  );
  return (
    <div className="dscroll">
      <div className="dsec">
        <div className="dsec-title">Connection</div>
        <div className="dgrid">
          <F label="Source IP"    val={item.src_ip}/>
          <F label="Source Port"  val={item.src_port}/>
          <F label="Dest IP"      val={item.dst_ip}/>
          <F label="Dest Port"    val={item.dst_port}/>
          <F label="Protocol"     val={item.proto}/>
          <F label="App Protocol" val={item.app_proto||'—'}/>
          <F label="State"        val={item.state}/>
          <F label="Reason"       val={item.reason}/>
          <F label="Duration"     val={fmtDur(item.duration_s)}/>
          <F label="Alerted"      val={item.alerted?'Yes':'No'} color={item.alerted?'var(--red)':'var(--green)'}/>
        </div>
      </div>
      <div className="dsec">
        <div className="dsec-title">Traffic</div>
        <div className="dgrid">
          <F label="Pkts → Server"  val={item.pkts_toserver}/>
          <F label="Pkts → Client"  val={item.pkts_toclient}/>
          <F label="Bytes → Server" val={fmtBytes(item.bytes_toserver)}/>
          <F label="Bytes → Client" val={fmtBytes(item.bytes_toclient)}/>
          <F label="Timestamp" val={item.ts} full/>
        </div>
      </div>
    </div>
  );
}

// ── DNSView ───────────────────────────────────────────────────────────────────
function DNSView({ rows, loading, selected, onSelect }) {
  const [search, setSearch] = useState('');
  const q = search.toLowerCase();
  const filtered = rows.filter(r =>
    !q || r.rrname?.toLowerCase().includes(q) || r.src_ip?.includes(q) ||
    r.rrtype?.toLowerCase().includes(q) || r.rcode?.toLowerCase().includes(q)
  );

  return (
    <div style={{display:'flex',flexDirection:'column',overflow:'hidden',flex:1}}>
      <div className="pane-head">
        <span className="pane-title" style={{color:'var(--purple)'}}>DNS Queries</span>
        <span className="pane-cnt">{filtered.length.toLocaleString()}</span>
        <div className="pane-actions">
          <div className="search">
            <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
              <circle cx="7" cy="7" r="4"/><path d="M10 10l3 3"/>
            </svg>
            <input placeholder="Filter by name, IP…" value={search} onChange={e=>setSearch(e.target.value)}/>
          </div>
        </div>
      </div>
      <div className="tscroll">
        {loading ? (
          <div className="empty"><div>Loading…</div></div>
        ) : filtered.length === 0 ? (
          <div className="empty">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
            <div>No DNS events yet</div>
          </div>
        ) : (
          <table>
            <thead><tr>
              <th style={{width:80}}>Time</th>
              <th style={{width:60}}>Type</th>
              <th>Query Name</th>
              <th style={{width:60}}>RR Type</th>
              <th style={{width:60}}>RCode</th>
              <th style={{width:105}}>Source</th>
              <th style={{width:105}}>Resolver</th>
            </tr></thead>
            <tbody>
              {filtered.slice(0,300).map((r,i) => (
                <tr key={r.id||i}
                    className={`arow${selected?.id===r.id?' sel':''}`}
                    onClick={()=>onSelect(r)}>
                  <td className="mono-dim">{fmtTime(r.ts)}</td>
                  <td><span className="proto">{r.dns_type}</span></td>
                  <td style={{fontSize:12,color:'var(--text1)',fontFamily:'var(--mono)',maxWidth:0,overflow:'hidden',textOverflow:'ellipsis'}}>{r.rrname||'—'}</td>
                  <td className="mono-dim">{r.rrtype||'—'}</td>
                  <td className="mono-dim">{r.rcode||'—'}</td>
                  <td className="mono">{r.src_ip}</td>
                  <td className="mono">{r.dst_ip}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// ── DNSDetail ─────────────────────────────────────────────────────────────────
function DNSDetail({ item }) {
  if (!item) return (
    <div className="dscroll">
      <div className="empty" style={{height:'100%'}}>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/></svg>
        <div>Select a DNS event</div>
      </div>
    </div>
  );
  const F = ({label,val,full})=>(
    <div className={`dfield${full?' dfull':''}`}>
      <div className="dfield-label">{label}</div>
      <div className="dfield-val">{val??'—'}</div>
    </div>
  );
  return (
    <div className="dscroll">
      <div className="dsec">
        <div className="dsec-title">DNS Query</div>
        <div className="dgrid">
          <F label="Name"       val={item.rrname} full/>
          <F label="Type"       val={item.dns_type}/>
          <F label="RR Type"    val={item.rrtype}/>
          <F label="RCode"      val={item.rcode}/>
          <F label="TTL"        val={item.ttl?item.ttl+'s':'—'}/>
          <F label="Source IP"  val={item.src_ip}/>
          <F label="Resolver"   val={item.dst_ip}/>
          <F label="Flow ID"    val={item.flow_id}/>
          <F label="TX ID"      val={item.tx_id}/>
          <F label="Timestamp"  val={item.ts} full/>
        </div>
      </div>
      {item.answers && item.answers.length > 0 && (
        <div className="dsec">
          <div className="dsec-title">Answers</div>
          <pre className="rawjson">{JSON.stringify(item.answers, null, 2)}</pre>
        </div>
      )}
    </div>
  );
}

// ── WebhooksView component ────────────────────────────────────────────────────
const SEV_OPTIONS = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_COLORS_WH = {
  critical: 'var(--red)', high: 'var(--orange)',
  medium: 'var(--yellow)', low: 'var(--green)', info: 'var(--accent)',
};
const TYPE_LABELS = { slack: 'Slack', discord: 'Discord', generic: 'Generic / Other' };

function WebhookForm({ initial, onSave, onCancel }) {
  const blank = { name: '', type: 'generic', url: '', enabled: true,
                  severities: ['critical', 'high', 'medium', 'low', 'info'] };
  const [form, setForm] = useState(initial || blank);
  const [saving, setSaving]   = useState(false);
  const [error,  setError]    = useState('');

  function toggleSev(s) {
    setForm(f => {
      const sevs = f.severities.includes(s)
        ? f.severities.filter(x => x !== s)
        : [...f.severities, s];
      return { ...f, severities: sevs };
    });
  }

  async function handleSave() {
    if (!form.name.trim()) { setError('Name is required.'); return; }
    if (!form.url.trim())  { setError('URL is required.');  return; }
    if (form.severities.length === 0) { setError('Select at least one severity.'); return; }
    setSaving(true); setError('');
    try {
      const method = form.id ? 'PUT' : 'POST';
      const url    = form.id ? `/webhooks/${form.id}` : '/webhooks';
      const r = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(form),
      });
      const data = await r.json();
      if (!r.ok) { setError(data.error || 'Save failed.'); return; }
      onSave(data);
    } catch { setError('Network error.'); }
    finally { setSaving(false); }
  }

  const inputStyle = {
    width: '100%', padding: '8px 10px',
    background: 'var(--bg2)', border: '1px solid var(--border2)',
    borderRadius: 'var(--radius-sm)', color: 'var(--text1)',
    fontSize: 12, fontFamily: 'var(--sans)', outline: 'none',
  };
  const labelStyle = {
    display: 'block', fontSize: 10, fontWeight: 600,
    letterSpacing: '.09em', textTransform: 'uppercase',
    color: 'var(--text3)', marginBottom: 5,
  };
  const rowStyle = { marginBottom: 14 };

  return (
    <div style={{
      background: 'var(--bg2)', border: '1px solid var(--border2)',
      borderRadius: 'var(--radius-lg)', padding: 20, marginBottom: 16,
    }}>
      <div style={{ fontSize: 13, fontWeight: 500, marginBottom: 16 }}>
        {form.id ? 'Edit Webhook' : 'New Webhook'}
      </div>

      <div style={rowStyle}>
        <label style={labelStyle}>Name</label>
        <input style={inputStyle} placeholder="e.g. Security Alerts"
          value={form.name} onChange={e => setForm(f => ({...f, name: e.target.value}))}/>
      </div>

      <div style={rowStyle}>
        <label style={labelStyle}>Type</label>
        <select style={{...inputStyle, cursor: 'pointer'}}
          value={form.type} onChange={e => setForm(f => ({...f, type: e.target.value}))}>
          <option value="slack">Slack</option>
          <option value="discord">Discord</option>
          <option value="generic">Generic / Other (Teams, Mattermost, custom…)</option>
        </select>
      </div>

      <div style={rowStyle}>
        <label style={labelStyle}>Webhook URL</label>
        <input style={{...inputStyle, fontFamily: 'var(--mono)', fontSize: 11}}
          placeholder={
            form.type === 'slack'   ? 'https://hooks.slack.com/services/…' :
            form.type === 'discord' ? 'https://discord.com/api/webhooks/…' :
                                     'https://your-endpoint.com/webhook'
          }
          value={form.url} onChange={e => setForm(f => ({...f, url: e.target.value}))}/>
      </div>

      <div style={rowStyle}>
        <label style={labelStyle}>Trigger on Severities</label>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {SEV_OPTIONS.map(s => {
            const on = form.severities.includes(s);
            return (
              <div key={s} onClick={() => toggleSev(s)} style={{
                display: 'flex', alignItems: 'center', gap: 5,
                padding: '4px 10px', borderRadius: 20,
                border: `1px solid ${on ? SEV_COLORS_WH[s] : 'var(--border)'}`,
                background: on ? `${SEV_COLORS_WH[s]}18` : 'transparent',
                color: on ? SEV_COLORS_WH[s] : 'var(--text3)',
                fontSize: 11, fontFamily: 'var(--mono)',
                cursor: 'pointer', userSelect: 'none', transition: 'all .15s',
                textTransform: 'uppercase',
              }}>
                <div style={{
                  width: 6, height: 6, borderRadius: '50%',
                  background: on ? SEV_COLORS_WH[s] : 'var(--text3)',
                }}/>
                {s}
              </div>
            );
          })}
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
        <div onClick={() => setForm(f => ({...f, enabled: !f.enabled}))} style={{
          width: 34, height: 18, borderRadius: 9,
          background: form.enabled ? 'var(--green)' : 'var(--bg3)',
          position: 'relative', cursor: 'pointer', transition: 'background .2s',
          border: '1px solid var(--border2)',
        }}>
          <div style={{
            position: 'absolute', top: 2,
            left: form.enabled ? 17 : 2,
            width: 12, height: 12, borderRadius: '50%',
            background: 'white', transition: 'left .2s',
          }}/>
        </div>
        <span style={{ fontSize: 12, color: 'var(--text2)' }}>
          {form.enabled ? 'Enabled' : 'Disabled'}
        </span>
      </div>

      {error && (
        <div style={{
          marginBottom: 12, padding: '7px 10px', borderRadius: 5,
          background: 'var(--red-d)', border: '1px solid var(--red)',
          color: 'var(--red)', fontSize: 12,
        }}>{error}</div>
      )}

      <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
        <button className="btn" onClick={onCancel} disabled={saving}>Cancel</button>
        <button onClick={handleSave} disabled={saving} style={{
          padding: '4px 14px', borderRadius: 'var(--radius-sm)',
          border: '1px solid var(--accent)', background: 'var(--accent-d)',
          color: 'var(--accent)', fontSize: 11, fontFamily: 'var(--sans)',
          cursor: saving ? 'wait' : 'pointer',
        }}>
          {saving ? 'Saving…' : (form.id ? 'Save Changes' : 'Create Webhook')}
        </button>
      </div>
    </div>
  );
}

function WebhookCard({ wh, onEdit, onDelete, onTest }) {
  const [testing,    setTesting]    = useState(false);
  const [testResult, setTestResult] = useState(null); // null | 'ok' | 'error: ...'
  const [delConfirm, setDelConfirm] = useState(false);

  async function handleTest() {
    setTesting(true); setTestResult(null);
    try {
      const r = await fetch(`/webhooks/${wh.id}/test`, { method: 'POST' });
      const d = await r.json();
      setTestResult(d.ok ? 'ok' : (d.error || 'failed'));
    } catch { setTestResult('Network error'); }
    finally { setTesting(false); }
  }

  const firedAt = wh.last_fired
    ? new Date(wh.last_fired * 1000).toLocaleString('en-GB', {hour12:false})
    : 'Never';

  return (
    <div style={{
      background: 'var(--bg1)', border: '1px solid var(--border)',
      borderRadius: 'var(--radius-lg)', padding: '14px 16px', marginBottom: 10,
      borderLeft: `3px solid ${wh.enabled ? 'var(--green)' : 'var(--border2)'}`,
    }}>
      {/* Header row */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
        <div style={{
          padding: '2px 8px', borderRadius: 4,
          background: 'var(--bg3)', border: '1px solid var(--border)',
          fontSize: 10, fontFamily: 'var(--mono)', color: 'var(--text2)',
          textTransform: 'uppercase',
        }}>{wh.type}</div>
        <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--text1)' }}>{wh.name}</span>
        <div style={{
          marginLeft: 'auto', padding: '2px 8px', borderRadius: 10, fontSize: 10,
          background: wh.enabled ? 'var(--green-d)' : 'var(--bg3)',
          color: wh.enabled ? 'var(--green)' : 'var(--text3)',
          border: `1px solid ${wh.enabled ? 'var(--green)' : 'var(--border)'}`,
          fontFamily: 'var(--mono)',
        }}>{wh.enabled ? 'ENABLED' : 'DISABLED'}</div>
      </div>

      {/* URL */}
      <div style={{
        fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--text3)',
        background: 'var(--bg2)', padding: '5px 8px', borderRadius: 4,
        marginBottom: 10, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
      }}>{wh.url}</div>

      {/* Severity pills */}
      <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginBottom: 10 }}>
        {SEV_OPTIONS.map(s => {
          const on = (wh.severities || []).includes(s);
          return (
            <span key={s} style={{
              padding: '1px 7px', borderRadius: 10, fontSize: 10,
              fontFamily: 'var(--mono)', textTransform: 'uppercase',
              background: on ? `${SEV_COLORS_WH[s]}18` : 'transparent',
              color: on ? SEV_COLORS_WH[s] : 'var(--text3)',
              border: `1px solid ${on ? SEV_COLORS_WH[s] : 'var(--border)'}`,
              opacity: on ? 1 : 0.4,
            }}>{s}</span>
          );
        })}
      </div>

      {/* Stats row */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 16,
        fontSize: 10, fontFamily: 'var(--mono)', color: 'var(--text3)',
        marginBottom: 12,
      }}>
        <span>Fired: <b style={{color:'var(--text2)'}}>{wh.fire_count || 0}</b></span>
        <span>Last: <b style={{color:'var(--text2)'}}>{firedAt}</b></span>
        {wh.last_error && (
          <span style={{ color: 'var(--red)', marginLeft: 'auto' }}>
            ⚠ {wh.last_error.slice(0, 60)}
          </span>
        )}
      </div>

      {/* Test result */}
      {testResult && (
        <div style={{
          marginBottom: 10, padding: '6px 10px', borderRadius: 5, fontSize: 11,
          background: testResult === 'ok' ? 'var(--green-d)' : 'var(--red-d)',
          border: `1px solid ${testResult === 'ok' ? 'var(--green)' : 'var(--red)'}`,
          color: testResult === 'ok' ? 'var(--green)' : 'var(--red)',
        }}>
          {testResult === 'ok' ? '✓ Test delivered successfully' : `✗ ${testResult}`}
        </div>
      )}

      {/* Action buttons */}
      <div style={{ display: 'flex', gap: 7 }}>
        <button className="btn" onClick={handleTest} disabled={testing} style={{ fontSize: 11 }}>
          {testing ? 'Sending…' : 'Test'}
        </button>
        <button className="btn" onClick={() => onEdit(wh)} style={{ fontSize: 11 }}>
          Edit
        </button>
        {!delConfirm ? (
          <button className="btn" onClick={() => setDelConfirm(true)}
            style={{ fontSize: 11, marginLeft: 'auto' }}>
            Delete
          </button>
        ) : (
          <div style={{ display: 'flex', gap: 6, marginLeft: 'auto', alignItems: 'center' }}>
            <span style={{ fontSize: 11, color: 'var(--text3)' }}>Confirm?</span>
            <button className="btn" onClick={() => setDelConfirm(false)} style={{ fontSize: 11 }}>
              Cancel
            </button>
            <button onClick={() => onDelete(wh.id)} style={{
              padding: '4px 10px', borderRadius: 'var(--radius-sm)',
              border: '1px solid var(--red)', background: 'var(--red-d)',
              color: 'var(--red)', fontSize: 11, fontFamily: 'var(--sans)', cursor: 'pointer',
            }}>
              Delete
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

function WebhooksView({ webhooks, loading, setLoading, onRefresh }) {
  const [showForm, setShowForm]   = useState(false);
  const [editing,  setEditing]    = useState(null); // null = new

  async function handleDelete(id) {
    await fetch(`/webhooks/${id}`, { method: 'DELETE' }).catch(() => {});
    onRefresh();
  }

  function handleEdit(wh) {
    setEditing(wh);
    setShowForm(true);
  }

  function handleNew() {
    setEditing(null);
    setShowForm(true);
  }

  function handleSaved() {
    setShowForm(false);
    setEditing(null);
    onRefresh();
  }

  return (
    <div style={{
      flex: 1, display: 'flex', flexDirection: 'column',
      overflow: 'hidden', background: 'var(--bg0)',
    }}>
      {/* Header */}
      <div className="pane-head">
        <span className="pane-title">Webhook Notifications</span>
        <span className="pane-cnt">{webhooks.length} configured</span>
        <div className="pane-actions">
          <button className="btn on" onClick={handleNew}>+ Add Webhook</button>
        </div>
      </div>

      {/* Scrollable content */}
      <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>

        {/* Guidance box */}
        <div style={{
          background: 'var(--accent-d)', border: '1px solid rgba(79,156,249,.2)',
          borderRadius: 'var(--radius-md)', padding: '10px 14px',
          fontSize: 12, color: 'var(--text2)', marginBottom: 20, lineHeight: 1.7,
        }}>
          <b style={{color:'var(--accent)'}}>Webhooks</b> send a POST request to your URL whenever
          a matching alert fires. Choose <b style={{color:'var(--text1)'}}>Slack</b> or{' '}
          <b style={{color:'var(--text1)'}}>Discord</b> for formatted messages, or{' '}
          <b style={{color:'var(--text1)'}}>Generic</b> for a plain JSON payload compatible
          with Teams, Mattermost, or any custom endpoint.
          Use the <b style={{color:'var(--text1)'}}>severity filter</b> to only send the alerts
          that matter.
        </div>

        {/* Add / Edit form */}
        {showForm && (
          <WebhookForm
            initial={editing}
            onSave={handleSaved}
            onCancel={() => { setShowForm(false); setEditing(null); }}
          />
        )}

        {/* Webhook cards */}
        {webhooks.length === 0 && !showForm && (
          <div className="empty" style={{ height: 200 }}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1">
              <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/>
              <path d="M13.73 21a2 2 0 0 1-3.46 0"/>
            </svg>
            <div>No webhooks configured</div>
            <div style={{fontSize:11}}>Click "+ Add Webhook" to get started</div>
          </div>
        )}
        {webhooks.map(wh => (
          <WebhookCard
            key={wh.id}
            wh={wh}
            onEdit={handleEdit}
            onDelete={handleDelete}
            onTest={() => {}}
          />
        ))}
      </div>
    </div>
  );
}

// ── App ───────────────────────────────────────────────────────────────────────
function App() {
  // ── State ──────────────────────────────────────────────────────────────────
  const [view,         setView]         = useState('alerts');
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
  const [activeView,   setActiveView]   = useState('alerts'); // 'alerts' | 'webhooks'
  const [webhooks,     setWebhooks]     = useState([]);
  const [whLoading,    setWhLoading]    = useState(false);
  const [flows,        setFlows]        = useState([]);
  const [dnsEvents,    setDnsEvents]    = useState([]);
  const [flowSel,      setFlowSel]      = useState(null);
  const [dnsSel,       setDnsSel]       = useState(null);
  const [evtLoading,   setEvtLoading]   = useState(false);

  const pausedRef   = useRef(false);
  const accumRef    = useRef(0);
  const sparkIdxRef = useRef(0);
  const newIdsRef   = useRef(new Set());

  // ── Theme ──────────────────────────────────────────────────────────────────
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('heimdall-theme', theme);
  }, [theme]);

  // ── Fetch webhooks ────────────────────────────────────────────────────────────
  const fetchWebhooks = () => {
    fetch('/webhooks')
      .then(r => r.json())
      .then(data => { if (Array.isArray(data)) setWebhooks(data); })
      .catch(() => {});
  };
  useEffect(() => { fetchWebhooks(); }, []);

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

  // ── Load flow/dns history on first view ────────────────────────────────
  useEffect(() => {
    if (activeView === 'flows' && flows.length === 0) {
      setEvtLoading(true);
      fetch('/flows?limit=5000').then(r=>r.json()).then(d=>{
        if(Array.isArray(d)) setFlows(d.map(r=>({...r,tsStr:fmtTime(r.ts)})));
        setEvtLoading(false);
      }).catch(()=>setEvtLoading(false));
    }
    if (activeView === 'dns' && dnsEvents.length === 0) {
      setEvtLoading(true);
      fetch('/dns?limit=5000').then(r=>r.json()).then(d=>{
        if(Array.isArray(d)) setDnsEvents(d.map(r=>({...r,tsStr:fmtTime(r.ts)})));
        setEvtLoading(false);
      }).catch(()=>setEvtLoading(false));
    }
  }, [activeView]);

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

      es.addEventListener('flow', e => {
        try {
          const evt = JSON.parse(e.data);
          evt.tsStr = fmtTime(evt.ts);
          setFlows(prev => {
            if (prev.some(x => x.flow_id === evt.flow_id)) return prev;
            return [evt, ...prev].slice(0, MAX_ALERTS);
          });
        } catch {}
      });

      es.addEventListener('dns', e => {
        try {
          const evt = JSON.parse(e.data);
          evt.tsStr = fmtTime(evt.ts);
          setDnsEvents(prev => [evt, ...prev].slice(0, MAX_ALERTS));
        } catch {}
      });

      // HTTP event listener removed

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

  // ── Clear handlers ──────────────────────────────────────────────────────────
  async function handleClearAlerts() {
    setClearing(true);
    try { await fetch('/alerts', { method: 'DELETE' }); } catch {}
    setAlerts([]);
    setSelected(null);
    setHistoryCount(0);
    setClearing(false);
    setShowConfirm(false);
  }

  const handleClearFlows = async () => {
    try {
      await fetch('/flows', { method: 'DELETE' });
      setFlows([]);
      setFlowSel(null);
    } catch (e) {
      alert('Failed to clear flows');
    }
  };

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
        <div className={`nav-item${activeView === 'alerts' ? ' active' : ''}`}
             onClick={() => setActiveView('alerts')}>
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
        <div className={`nav-item${activeView === 'flows' ? ' active' : ''}`}
             style={activeView==='flows'?{background:'var(--teal-d)',color:'var(--teal)',borderColor:'rgba(45,212,191,.2)'}:{}}
             onClick={() => setActiveView('flows')}>
          <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path d="M2 4h12M2 8h8M2 12h10"/>
          </svg>
          Flow Events
          <span style={{marginLeft:'auto',fontFamily:'var(--mono)',fontSize:10,
                        padding:'1px 6px',borderRadius:10,
                        background:'var(--teal-d)',color:'var(--teal)'}}>
            {flows.length > 999 ? '999+' : flows.length}
          </span>
        </div>

        <div className={`nav-item${activeView === 'dns' ? ' active' : ''}`}
             style={activeView==='dns'?{background:'rgba(159,122,234,.14)',color:'var(--purple)',borderColor:'rgba(159,122,234,.2)'}:{}}
             onClick={() => setActiveView('dns')}>
          <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
            <circle cx="8" cy="8" r="6"/><path d="M2 8h12M8 2a9 9 0 010 12"/>
          </svg>
          DNS Queries
          <span style={{marginLeft:'auto',fontFamily:'var(--mono)',fontSize:10,
                        padding:'1px 6px',borderRadius:10,
                        background:'rgba(159,122,234,.14)',color:'var(--purple)'}}>
            {dnsEvents.length > 999 ? '999+' : dnsEvents.length}
          </span>
        </div>

        <div className={`nav-item${activeView === 'webhooks' ? ' active' : ''}`}
             onClick={() => { setActiveView('webhooks'); fetchWebhooks(); }}>
          <svg width="14" height="14" viewBox="0 0 16 16"
               fill="none" stroke="currentColor" strokeWidth="1.5">
            <path d="M2 4h12M2 8h8M2 12h10"/>
            <circle cx="13" cy="12" r="2" fill="currentColor" stroke="none"/>
          </svg>
          Webhooks
          <span style={{
            marginLeft:'auto', fontFamily:'var(--mono)', fontSize:10,
            padding:'1px 6px', borderRadius:10,
            background:'var(--accent-d)', color:'var(--accent)'
          }}>
            {webhooks.filter(w => w.enabled).length}
          </span>
        </div>

        {activeView === 'alerts' && <div className="divider"/>}

        {activeView === 'alerts' && <div className="s-label">Severity</div>}
        {activeView === 'alerts' && ['critical', 'high', 'medium', 'low', 'info'].map(s => (
          <div key={s}
               className={`sev-row${activeSev.has(s) ? ' on' : ''}`}
               onClick={() => toggleSev(s)}>
            <div className="sev-dot" style={{ background: SEV_COLORS[s] }}/>
            {s.charAt(0).toUpperCase() + s.slice(1)}
            <span className="sev-cnt">{counts[s]}</span>
          </div>
        ))}

        {activeView === 'alerts' && <div className="divider"/>}

        {activeView === 'alerts' && <div className="s-label">Top Sources</div>}
        {activeView === 'alerts' && topSrcs.length === 0 && (
          <div style={{
            padding: '4px 18px', fontSize: 11,
            color: 'var(--text3)', fontFamily: 'var(--mono)',
          }}>no data yet</div>
        )}
        {activeView === 'alerts' && topSrcs.length > 0 && (
          <div style={{padding:'0 12px'}}>
            {topSrcs.map(([ip, cnt]) => {
              const maxCount = topSrcs[0][1];
              const percent = (cnt / maxCount) * 100;
              return (
                <div key={ip} style={{marginBottom:8}}>
                  <div style={{display:'flex',justifyContent:'space-between',fontSize:11,marginBottom:2}}>
                    <span className="src-ip" style={{overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap',maxWidth:100}}>{ip}</span>
                    <span className="src-cnt">{cnt}</span>
                  </div>
                  <div style={{height:4,background:'var(--bg3)',borderRadius:2,overflow:'hidden'}}>
                    <div style={{width:`${percent}%`,height:'100%',background:'var(--accent)',borderRadius:2}}/>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </aside>

      {/* ── Main ── */}
      <main className="main" style={{display: activeView === 'alerts' ? '' : 'none'}}>

        {/* Metrics — 5 columns only */}
        <div className="metrics" style={{gridTemplateColumns: 'repeat(5,1fr)'}}>
          <div className="metric">
            <div className="metric-label">Total Alerts</div>
            <div className="metric-val">{alerts.length.toLocaleString()}</div>
          </div>
          <div className="metric">
            <div className="metric-label">Critical</div>
            <div className="metric-val" style={{color:'var(--red)'}}>{counts.critical}</div>
          </div>
          <div className="metric">
            <div className="metric-label">High</div>
            <div className="metric-val" style={{color:'var(--orange)'}}>{counts.high}</div>
          </div>
          <div className="metric">
            <div className="metric-label">Medium</div>
            <div className="metric-val" style={{color:'var(--yellow)'}}>{counts.medium}</div>
          </div>
          <div className="metric">
            <div className="metric-label">Unique Sources</div>
            <div className="metric-val">{uniqueSrcs}</div>
          </div>
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

      {/* ── Flow Events view ── */}
      {activeView === 'flows' && (
        <main className="main">
          <div className="content" style={{gridTemplateColumns:'1fr 310px'}}>
            <FlowsView rows={flows} loading={evtLoading} selected={flowSel} onSelect={setFlowSel} onClear={handleClearFlows}/>
            <div className="detail">
              <div className="pane-head"><span className="pane-title">Flow Detail</span></div>
              <FlowDetail item={flowSel}/>
            </div>
          </div>
        </main>
      )}

      {/* ── DNS view ── */}
      {activeView === 'dns' && (
        <main className="main">
          <div className="content" style={{gridTemplateColumns:'1fr 310px'}}>
            <DNSView rows={dnsEvents} loading={evtLoading} selected={dnsSel} onSelect={setDnsSel}/>
            <div className="detail">
              <div className="pane-head"><span className="pane-title">DNS Detail</span></div>
              <DNSDetail item={dnsSel}/>
            </div>
          </div>
        </main>
      )}

      {/* ── Webhooks view ── */}
      {activeView === 'webhooks' && (
        <WebhooksView
          webhooks={webhooks}
          loading={whLoading}
          setLoading={setWhLoading}
          onRefresh={fetchWebhooks}
        />
      )}

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
              <button onClick={handleClearAlerts}
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


/**
 * Heimdall IDS — Skin Loader
 * Reads the chosen skin from localStorage, fetches the asset manifest to get
 * content-hashed filenames, then injects CSS + JS for the active skin.
 *
 * Loading order:
 *   index.html → react.min.js → react-dom.min.js → skin-loader.js (no-cache)
 *   skin-loader.js → manifest.json (no-cache) → skins/{id}/app-{hash}.js
 *                                              → skins/{id}/styles-{hash}.css
 *
 * Because every asset filename contains a content hash the browser can cache
 * them as immutable forever — a changed file automatically gets a new URL.
 * No manual version bumping or hard reloads ever needed.
 */

(function () {
  'use strict';

  /* ── Skin registry ────────────────────────────────────────────────────────
     Add new skins here; everything else is automatic.
  ── */
  const SKINS = [
    {
      id:      'original',
      label:   'Original',
      desc:    'Warm charcoal · Space Grotesk',
      accent:  '#5b8ef0',
      bg:      '#0e0e0f',
      preview: ['#0e0e0f', '#141415', '#5b8ef0'],
    },
    {
      id:      'chronicles',
      label:   'Chronicles',
      desc:    'Obsidian violet · Inter',
      accent:  '#7c6cf0',
      bg:      '#09080e',
      preview: ['#09080e', '#100e1a', '#7c6cf0'],
    },
    {
      id:      'mosaic',
      label:   'Mosaic',
      desc:    'Glass indigo · Inter',
      accent:  '#818cf8',
      bg:      '#07080f',
      preview: ['#07080f', '#111428', '#818cf8'],
    },
    {
      id:      'seal',
      label:   'Seal',
      desc:    'Navy steel · Space Mono',
      accent:  '#58a6e8',
      bg:      '#0a0f1a',
      preview: ['#0a0f1a', '#060d18', '#58a6e8'],
    },
  ];

  const STORAGE_KEY = 'heimdall_skin';
  const DEFAULT_ID  = 'original';

  /* ── Skin resolution ─────────────────────────────────────────────────── */
  function currentSkinId() {
    const saved = localStorage.getItem(STORAGE_KEY);
    return SKINS.find(s => s.id === saved) ? saved : DEFAULT_ID;
  }

  function skinById(id) {
    return SKINS.find(s => s.id === id) || SKINS[0];
  }

  /* ── Manifest fetch ──────────────────────────────────────────────────── */
  async function fetchManifest() {
    // Always fetch fresh — manifest.json is served no-cache.
    const r = await fetch('/frontend/manifest.json', { cache: 'no-store' });
    if (!r.ok) throw new Error('manifest fetch failed: ' + r.status);
    return r.json();
  }

  /* ── CSS injection ───────────────────────────────────────────────────── */
  function injectCSS(href) {
    return new Promise(resolve => {
      const old = document.getElementById('skin-css');
      if (old) old.remove();
      const link = document.createElement('link');
      link.id   = 'skin-css';
      link.rel  = 'stylesheet';
      link.href = href;
      link.onload  = resolve;
      link.onerror = resolve; // fail-open so the app still boots
      document.head.appendChild(link);
    });
  }

  /* ── JS injection ────────────────────────────────────────────────────── */
  function injectJS(src) {
    return new Promise((resolve, reject) => {
      const old = document.getElementById('skin-js');
      if (old) old.remove();
      const s = document.createElement('script');
      s.id      = 'skin-js';
      s.src     = src;
      s.defer   = true;
      s.onload  = resolve;
      s.onerror = reject;
      document.body.appendChild(s);
    });
  }

  /* ── Skin switcher widget ─────────────────────────────────────────────
     Fully self-styled — immune to whichever skin is active.
  ── */
  function buildSwitcher(activeSkinId) {
    const old = document.getElementById('skin-switcher');
    if (old) old.remove();

    let open = false;

    const wrap = document.createElement('div');
    wrap.id = 'skin-switcher';
    Object.assign(wrap.style, {
      position:   'fixed',
      bottom:     '18px',
      right:      '18px',
      zIndex:     '99999',
      fontFamily: 'system-ui, -apple-system, sans-serif',
      fontSize:   '12px',
    });

    const btn = document.createElement('button');
    btn.title = 'Switch skin';
    Object.assign(btn.style, {
      display:        'flex',
      alignItems:     'center',
      gap:            '6px',
      padding:        '7px 11px',
      background:     'rgba(15,15,20,0.88)',
      border:         '1px solid rgba(255,255,255,0.10)',
      borderRadius:   '20px',
      color:          '#c8cfe8',
      cursor:         'pointer',
      backdropFilter: 'blur(10px)',
      boxShadow:      '0 2px 12px rgba(0,0,0,0.45)',
      whiteSpace:     'nowrap',
      transition:     'border-color .15s, box-shadow .15s',
      lineHeight:     '1',
    });

    const activeSkin = skinById(activeSkinId);
    const dot = document.createElement('div');
    Object.assign(dot.style, {
      width:        '8px',
      height:       '8px',
      borderRadius: '50%',
      background:   activeSkin.accent,
      flexShrink:   '0',
    });

    const label = document.createElement('span');
    label.textContent = activeSkin.label;

    const caret = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    caret.setAttribute('width', '9');
    caret.setAttribute('height', '9');
    caret.setAttribute('viewBox', '0 0 10 10');
    caret.setAttribute('fill', 'none');
    caret.setAttribute('stroke', 'currentColor');
    caret.setAttribute('stroke-width', '1.8');
    const caretPath = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    caretPath.setAttribute('d', 'M2 4l3 3 3-3');
    caret.appendChild(caretPath);

    btn.appendChild(dot);
    btn.appendChild(label);
    btn.appendChild(caret);

    const panel = document.createElement('div');
    Object.assign(panel.style, {
      display:        'none',
      position:       'absolute',
      bottom:         'calc(100% + 8px)',
      right:          '0',
      background:     'rgba(13,13,18,0.96)',
      border:         '1px solid rgba(255,255,255,0.10)',
      borderRadius:   '12px',
      padding:        '6px',
      minWidth:       '210px',
      boxShadow:      '0 8px 32px rgba(0,0,0,0.6)',
      backdropFilter: 'blur(14px)',
    });

    const hdr = document.createElement('div');
    Object.assign(hdr.style, {
      fontSize:     '9px',
      fontWeight:   '600',
      letterSpacing:'.1em',
      textTransform:'uppercase',
      color:        'rgba(255,255,255,0.28)',
      padding:      '5px 8px 8px',
    });
    hdr.textContent = 'Choose skin';
    panel.appendChild(hdr);

    SKINS.forEach(skin => {
      const row = document.createElement('div');
      const isActive = skin.id === activeSkinId;
      Object.assign(row.style, {
        display:      'flex',
        alignItems:   'center',
        gap:          '10px',
        padding:      '8px 9px',
        borderRadius: '8px',
        cursor:       isActive ? 'default' : 'pointer',
        background:   isActive ? 'rgba(255,255,255,0.07)' : 'transparent',
        transition:   'background .12s',
        userSelect:   'none',
      });

      if (!isActive) {
        row.addEventListener('mouseenter', () => { row.style.background = 'rgba(255,255,255,0.05)'; });
        row.addEventListener('mouseleave', () => { row.style.background = 'transparent'; });
      }

      const swatchWrap = document.createElement('div');
      Object.assign(swatchWrap.style, {
        display:      'flex',
        gap:          '2px',
        borderRadius: '5px',
        overflow:     'hidden',
        flexShrink:   '0',
        border:       '1px solid rgba(255,255,255,0.10)',
      });
      skin.preview.forEach(c => {
        const sq = document.createElement('div');
        Object.assign(sq.style, { width: '10px', height: '22px', background: c });
        swatchWrap.appendChild(sq);
      });

      const txt = document.createElement('div');
      Object.assign(txt.style, { flex: '1' });

      const name = document.createElement('div');
      name.textContent = skin.label;
      Object.assign(name.style, {
        color:      isActive ? '#e8eaf0' : '#9098b0',
        fontWeight: isActive ? '600' : '400',
        fontSize:   '12px',
        lineHeight: '1.3',
      });

      const desc = document.createElement('div');
      desc.textContent = skin.desc;
      Object.assign(desc.style, {
        color:    'rgba(255,255,255,0.25)',
        fontSize: '10px',
        marginTop:'1px',
      });

      txt.appendChild(name);
      txt.appendChild(desc);

      if (isActive) {
        const chk = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        chk.setAttribute('width', '12'); chk.setAttribute('height', '12');
        chk.setAttribute('viewBox', '0 0 12 12'); chk.setAttribute('fill', 'none');
        chk.setAttribute('stroke', skin.accent); chk.setAttribute('stroke-width', '2');
        const p = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        p.setAttribute('d', 'M2 6l2.5 2.5L10 3'); chk.appendChild(p);
        row.appendChild(swatchWrap); row.appendChild(txt); row.appendChild(chk);
      } else {
        row.appendChild(swatchWrap); row.appendChild(txt);
        row.addEventListener('click', () => {
          localStorage.setItem(STORAGE_KEY, skin.id);
          fetch('/skin', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ skin: skin.id }),
          }).catch(() => {});
          location.reload();
        });
      }

      panel.appendChild(row);
    });

    btn.addEventListener('click', e => {
      e.stopPropagation();
      open = !open;
      panel.style.display = open ? 'block' : 'none';
      btn.style.borderColor = open ? 'rgba(255,255,255,0.22)' : 'rgba(255,255,255,0.10)';
    });

    document.addEventListener('click', e => {
      if (!wrap.contains(e.target)) {
        open = false;
        panel.style.display = 'none';
        btn.style.borderColor = 'rgba(255,255,255,0.10)';
      }
    });

    btn.addEventListener('mouseenter', () => { btn.style.boxShadow = '0 2px 18px rgba(0,0,0,0.6)'; });
    btn.addEventListener('mouseleave', () => { btn.style.boxShadow = '0 2px 12px rgba(0,0,0,0.45)'; });

    wrap.appendChild(panel);
    wrap.appendChild(btn);
    document.body.appendChild(wrap);
  }

  /* ── Bootstrap ────────────────────────────────────────────────────────── */
  async function boot() {
    const skinId = currentSkinId();

    // 1. Fetch the content-hash manifest (always fresh, served no-cache)
    let manifest;
    try {
      manifest = await fetchManifest();
    } catch (e) {
      console.error('[heimdall] Could not load manifest.json:', e);
      return;
    }

    const skinFiles = manifest[skinId];
    if (!skinFiles) {
      console.error('[heimdall] Skin not found in manifest:', skinId);
      return;
    }

    const base = `/frontend/skins/${skinId}/`;

    // 2. Inject CSS first — page won't be unstyled when JS mounts
    await injectCSS(base + skinFiles.css);

    // 3. Inject and run the compiled JS (mounts React)
    await injectJS(base + skinFiles.js);

    // 4. Mount the skin switcher
    buildSwitcher(skinId);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();

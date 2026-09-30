#!/usr/bin/env python3
"""
strip-ai.py  —  produce an AI-free copy of the Heimdall IDS source tree.

Usage:
    python3 strip-ai.py <src_dir> <dst_dir>

Copies <src_dir> to <dst_dir>, then surgically removes every AI touchpoint so
the result compiles and runs with zero AI dependencies.  All other features
(Alerts, Flows, DNS, Charts, Threat Intel, Suppression, Webhooks, auth) are
preserved exactly.

What is removed
  Backend
    backend/ai_explain.py                    deleted entirely
    backend/handlers.py
      - import ai_explain                    import line
      - ai_db class attribute                None sentinel
      - GET  /ai-config route + body         settings endpoint
      - POST /ai-explain route + body        explain endpoint
      - POST /ai-models route + body         model-list endpoint
      - PUT  /ai-config (do_PUT first branch)
      - _ai_config_update() method
      - _ai_explain() method
    backend/server.py
      - from ai_explain import AIExplainDB
      - ai_db = AIExplainDB(…)
      - Handler.ai_db = ai_db
      - --ai-provider / --ai-key options (ignored with a warning if present
        in heimdall.conf)

  Frontend (all four skins — chronicles, mosaic, original, seal)
    - function AIExplainView(…)              entire component
    - function AIExplanationPanel(…)         entire component
    - function requestAiExplain(…)           inner function in App
    - ExplainDialog: AI Summary tab button   literal block removal
    - ExplainDialog: AIExplanationPanel body literal block removal
    - ExplainDialog: useEffect AI if-block   literal block removal
    - ChronicleView (chronicles skin only):  AI props stripped from sig + call
    - chronicles: fetch /ai-config block     literal block removal
    - Auto-explain SSE if-block              regex — both brace and 1-liner forms
    - Tab state: ai→intel default            regex
    - aiSettings state declaration           line removal
    - aiExplanations state declaration       line removal
    - aiEnabledRef ref + mutations           line removal
    - 'ai-explain' nav entries               inline regex
    - view==='ai-explain' JSX branch         line removal
    - AI prop JSX attributes                 regex

License: AGPL-3.0 — same as the main project.
"""

import re, shutil, sys, textwrap
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def read(p):     return Path(p).read_text(encoding='utf-8')
def write(p, t): Path(p).write_text(t, encoding='utf-8')

def remove_lines_matching(src: str, patterns: list) -> str:
    """Drop every line that matches any regex in *patterns*."""
    compiled = [re.compile(p) for p in patterns]
    return ''.join(
        line for line in src.splitlines(keepends=True)
        if not any(c.search(line) for c in compiled))

def remove_jsx_function(src: str, fn_name: str) -> str:
    """
    Remove a JS/JSX function declaration (top-level or indented).
    Uses paren-depth tracking to skip the param list, then brace-depth tracking
    for the body — so destructured prop signatures with `{…}` don't confuse it.
    """
    pat = re.compile(
        r'^[ \t]*function ' + re.escape(fn_name) + r'\s*\(',
        re.MULTILINE)
    m = pat.search(src)
    if not m:
        return src

    start = m.start()
    i     = m.end() - 1   # back up to the `(`

    # skip param list
    pd = 0
    while i < len(src):
        if   src[i] == '(': pd += 1
        elif src[i] == ')':
            pd -= 1
            if pd == 0: i += 1; break
        i += 1

    # find opening `{` of function body
    while i < len(src) and src[i] != '{':
        i += 1
    if i >= len(src):
        return src

    # track brace depth to closing `}`
    bd = 0
    while i < len(src):
        if   src[i] == '{': bd += 1
        elif src[i] == '}':
            bd -= 1
            if bd == 0:
                end = i + 1
                if end < len(src) and src[end] == '\n':
                    end += 1
                return src[:start] + src[end:]
        i += 1
    return src

def remove_python_function(src: str, fn_name: str) -> str:
    """Remove a Python `def fn_name(…)` block (handles any indentation level)."""
    lines = src.splitlines(keepends=True)
    out = []
    i, n = 0, len(lines)
    while i < n:
        line = lines[i]
        m = re.match(r'^(\s*)def ' + re.escape(fn_name) + r'\s*\(', line)
        if m:
            base = len(m.group(1))
            i += 1
            while i < n:
                l = lines[i]
                s = l.rstrip('\n')
                if not s or s.isspace():
                    i += 1; continue
                if len(l) - len(l.lstrip()) > base:
                    i += 1; continue
                break
        else:
            out.append(line)
            i += 1
    return ''.join(out)


# ─────────────────────────────────────────────────────────────────────────────
# Backend stripping
# ─────────────────────────────────────────────────────────────────────────────

def strip_handlers(src: str) -> str:
    # Step 1 — do_PUT: fix if/elif chain BEFORE any line-removal touches the `if` line
    src = src.replace(
        '        if p.path == "/ai-config":\n'
        '            self._ai_config_update()\n'
        '        elif p.path.startswith("/users/"):',
        '        if p.path.startswith("/users/"):',
        1)

    # Step 2 — POST /ai-explain literal block
    src = src.replace(
        '        elif p.path == "/ai-explain":\n'
        '            self._ai_explain()\n', '', 1)

    # Step 3 — GET /ai-config literal block
    src = src.replace(
        '        elif p.path == "/ai-config":\n'
        '            s = self.ai_db.get_settings()\n'
        '            # Never expose raw key to frontend\n'
        '            self._json({\n'
        '                "provider":       s["provider"],\n'
        '                "enabled":        s["enabled"],\n'
        '                "api_key_set":    s["api_key_set"],\n'
        '                "model":          s["model"],\n'
        '                "models":         s["models"],\n'
        '                "default_models": s["default_models"],\n'
        '            })\n', '', 1)

    # Step 3b — POST /ai-models literal block
    src = src.replace(
        '        elif p.path == "/ai-models":\n'
        '            self._ai_models()\n', '', 1)

    # Step 4 — line-level removals
    src = remove_lines_matching(src, [
        r'import ai_explain',
        r'^\s+ai_db\s*=\s*None',
        r'"/ai-config"',
        r'"/ai-explain"',
        r'"/ai-models"',
    ])

    # Step 5 — remove handler methods
    src = remove_python_function(src, '_ai_config_update')
    src = remove_python_function(src, '_ai_explain')
    src = remove_python_function(src, '_ai_models')

    return src


def strip_server(src: str) -> str:
    return remove_lines_matching(src, [
        r'from ai_explain\s+import',
        r'\bai_db\b\s*=\s*AIExplainDB',
        r'Handler\.ai_db\s*=',
        r'add_argument\("--ai-provider"',   # single-line definitions in server.py
        r'add_argument\("--ai-key"',
    ])


# ─────────────────────────────────────────────────────────────────────────────
# Frontend stripping — applied identically to each app.jsx
# ─────────────────────────────────────────────────────────────────────────────

def strip_jsx(src: str) -> str:
    # ── PHASE 1: whole-function removals ─────────────────────────────────────
    # (must happen before any line-level pass that could strip declaration lines
    #  and orphan their bodies)

    src = remove_jsx_function(src, 'AIExplainView')
    src = remove_jsx_function(src, 'AIExplanationPanel')
    src = remove_jsx_function(src, 'requestAiExplain')

    # ── PHASE 2: literal block removals ──────────────────────────────────────
    # These contain `{` / `}` that defeat character-class regexes, or span
    # multiple lines that need to be removed atomically.

    # AI Summary tab button in ExplainDialog
    src = src.replace(
        "\n            {aiEnabled && (\n"
        "              <button style={tabBtn(tab==='ai')} onClick={()=>{ setTab('ai'); if(onRequestAiExplain && !aiExplanation) onRequestAiExplain(a); }}>\n"
        "                AI Summary\n"
        "              </button>\n"
        "            )}", '')

    # AIExplanationPanel render body in ExplainDialog
    src = src.replace(
        "\n          {tab === 'ai' && aiEnabled && (\n"
        "            <AIExplanationPanel\n"
        "              alert={a}\n"
        "              aiExplanation={aiExplanation}\n"
        "              onRequest={() => onRequestAiExplain && onRequestAiExplain(a)}\n"
        "            />\n"
        "          )}\n", '\n')

    # Trigger-AI useEffect guard (inside ExplainDialog's intel useEffect)
    src = re.sub(
        r'[ \t]*// Trigger AI fetch[^\n]*\n'
        r'[ \t]*if \(aiEnabled[^{]*\{[^}]*\}\n', '', src)

    # chronicles skin: ChronicleView signature
    src = src.replace(
        'function ChronicleView({ alerts, role, setAlerts, '
        'aiExplanations, onRequestAiExplain, aiEnabled }) {',
        'function ChronicleView({ alerts, role, setAlerts }) {')

    # chronicles skin: ChronicleView two-line JSX call-site
    src = src.replace(
        "            {view === 'chronicle' && <ChronicleView alerts={alerts} "
        "role={role} setAlerts={setAlerts}\n"
        "              aiExplanations={aiExplanations} onRequestAiExplain={requestAiExplain} "
        "aiEnabled={aiSettings.enabled}/>}",
        "            {view === 'chronicle' && <ChronicleView alerts={alerts} "
        "role={role} setAlerts={setAlerts}/>}")

    # chronicles skin: fetch /ai-config block inside the initial useEffect
    src = src.replace(
        "    // Load AI settings\n"
        "    fetch('/ai-config').then(r=>r.json()).then(d=>{\n"
        "      setAiSettings(d);\n"
        "      aiEnabledRef.current = d.enabled;\n"
        "    }).catch(()=>{});", '')

    # Auto-explain SSE call-site — brace-block variant (chronicles) and
    # single-line variant (original, mosaic, seal)
    src = re.sub(
        r'[ \t]*// Auto-explain[^\n]*\n'
        r'(?:'
        r'[ \t]*if \(aiEnabledRef\.current\) \{\n'
        r'[ \t]*\w+\([^)]*\);\n'
        r'[ \t]*\}\n'
        r'|'
        r'[ \t]*if \(aiEnabledRef\.current\) \w+\([^)]*\);\n'
        r')', '', src)

    # ── PHASE 3: inline regex subs (entries within otherwise-valid constructs)─
    # These use surgical substitution to remove AI entries without destroying
    # the surrounding array/object literal or JSX element.

    # ExplainDialog tab state default
    src = re.sub(
        r"useState\(aiEnabled\s*\?\s*'ai'\s*:\s*'intel'\)",
        "useState('intel')", src)

    # 'ai-explain':'AI Explain' entries inside label-map objects
    src = re.sub(r",\s*'ai-explain'\s*:\s*'AI Explain'", '', src)
    src = re.sub(r"'ai-explain'\s*:\s*'AI Explain'\s*,\s*", '', src)

    # 'ai-explain' entries inside nav arrays
    src = re.sub(r",\s*'ai-explain'(?!')", '', src)   # trailing entry
    src = re.sub(r"'ai-explain'\s*,(?!')", '', src)   # leading entry

    # Remove AI prop names from function destructured signatures (trailing)
    src = re.sub(r',\s*aiEnabled\b',          '', src)
    src = re.sub(r',\s*aiExplanation\b',       '', src)
    src = re.sub(r',\s*onRequestAiExplain\b',  '', src)
    # Remove AI prop names from function destructured signatures (leading)
    src = re.sub(r'\baiEnabled\s*,\s*',        '', src)
    src = re.sub(r'\baiExplanation\s*,\s*',    '', src)
    src = re.sub(r'\bonRequestAiExplain\s*,\s*', '', src)

    # Remove AI JSX props from component call-sites
    src = re.sub(r'\s*onRequestAiExplain=\{[^}]+\}', '', src)
    src = re.sub(r'\s*aiEnabled=\{[^}]+\}',           '', src)
    src = re.sub(r'\s*aiExplanation=\{[^}]+\}',       '', src)
    src = re.sub(r'\s*aiExplanations=\{[^}]+\}',      '', src)

    # ── PHASE 4: line-level cleanup of purely-AI-only lines ───────────────────
    src = remove_lines_matching(src, [
        r"const \[aiSettings",
        r"\bconst \[aiExplanations",
        r"\bconst \[aiEnabledRef",
        r"aiEnabledRef\.current",
        r"fetch.*ai-config.*setAiSettings",
        r"view\s*===\s*['\"]ai-explain['\"].*AIExplainView",
        r"\bAIExplainView\b",
        r"\bAIExplanationPanel\b",
        r"\bAIExplainDB\b",
        r"\baiSettings\b",
        r"\baiExplanations\b",
        r"\baiEnabledRef\b",
        r"gpt-4o-mini",
        r"claude-3-5-haiku",
        r"\{\s*id:\s*'openai'",
    ])

    return src


# ─────────────────────────────────────────────────────────────────────────────
# README / packaging/control
# ─────────────────────────────────────────────────────────────────────────────

def strip_readme(src: str) -> str:
    note = textwrap.dedent("""\
        > **AI-free build** — This distribution has the AI Explain feature
        > removed.  All other functionality (Alerts, Flows, DNS, Charts,
        > Threat Intel, Suppression, Webhooks, multi-user auth) is fully
        > intact.  No external API calls are made.

    """)
    return re.sub(
        r'(^# [^\n]+\n)', r'\1\n' + note, src,
        count=1, flags=re.MULTILINE)


def strip_control(src: str) -> str:
    src = re.sub(r'^Package:.*$',
                 'Package: heimdall-ids-noai', src, flags=re.MULTILINE)
    src = re.sub(r'^Description:.*$',
                 'Description: Heimdall IDS dashboard (AI-free build)',
                 src, flags=re.MULTILINE)
    return src


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 strip-ai.py <src_dir> <dst_dir>")
        sys.exit(1)

    src_root = Path(sys.argv[1]).resolve()
    dst_root = Path(sys.argv[2]).resolve()

    print(f"Copying {src_root} → {dst_root}")
    if dst_root.exists():
        shutil.rmtree(dst_root)
    shutil.copytree(src_root, dst_root,
                    ignore=shutil.ignore_patterns(
                        'packaging/build', '__pycache__', '*.pyc', '.git'))

    # Backend
    ai_py = dst_root / 'backend' / 'ai_explain.py'
    if ai_py.exists():
        ai_py.unlink()
        print("  Deleted  backend/ai_explain.py")

    h = dst_root / 'backend' / 'handlers.py'
    write(h, strip_handlers(read(h)))
    print("  Stripped backend/handlers.py")

    s = dst_root / 'backend' / 'server.py'
    write(s, strip_server(read(s)))
    print("  Stripped backend/server.py")

    # Frontend skins
    skins_dir = dst_root / 'frontend' / 'skins'
    for skin_dir in sorted(skins_dir.iterdir()):
        jsx = skin_dir / 'app.jsx'
        if jsx.exists():
            write(jsx, strip_jsx(read(jsx)))
            print(f"  Stripped frontend/skins/{skin_dir.name}/app.jsx")

    # Metadata
    readme = dst_root / 'README.md'
    if readme.exists():
        write(readme, strip_readme(read(readme)))
        print("  Updated  README.md")

    ctrl = dst_root / 'packaging' / 'control'
    if ctrl.exists():
        write(ctrl, strip_control(read(ctrl)))
        print("  Updated  packaging/control")

    print("\nDone.")


if __name__ == '__main__':
    main()

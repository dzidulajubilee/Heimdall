"""
Watcher IDS Dashboard — Threat Intelligence Database
Custom explanations for Suricata signatures, keyed by SID or category.

Lookup priority:
  1. Exact sig_id match
  2. Category match (sig_id IS NULL entries)
  3. None

Lives in config.db alongside users/webhooks.
"""

import json
import logging
import time

log = logging.getLogger("watcher.threat_intel")


class ThreatIntelDB:
    def __init__(self, conn_fn):
        self._conn = conn_fn
        self._setup()

    def _setup(self):
        c = self._conn()
        c.execute("""
            CREATE TABLE IF NOT EXISTS threat_intel (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                sig_id      INTEGER,
                sig_msg     TEXT,
                category    TEXT COLLATE NOCASE,
                explanation TEXT NOT NULL,
                tags        TEXT NOT NULL DEFAULT '[]',
                refs        TEXT NOT NULL DEFAULT '[]',
                created_by  TEXT,
                created_at  REAL NOT NULL,
                updated_at  REAL NOT NULL
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_ti_sigid ON threat_intel (sig_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_ti_cat   ON threat_intel (category)")
        c.commit()

    def _hydrate(self, row) -> dict | None:
        if not row:
            return None
        d = dict(row)
        for key in ("tags", "refs"):
            try:
                d[key] = json.loads(d.get(key) or "[]")
            except Exception:
                d[key] = []
        return d

    # ── CRUD ──────────────────────────────────────────────────────────────────

    def get_all(self) -> list[dict]:
        rows = self._conn().execute(
            "SELECT * FROM threat_intel ORDER BY updated_at DESC"
        ).fetchall()
        return [self._hydrate(r) for r in rows]

    def get_by_id(self, tid: int) -> dict | None:
        return self._hydrate(
            self._conn().execute(
                "SELECT * FROM threat_intel WHERE id = ?", (tid,)
            ).fetchone()
        )

    def create(self, sig_id, sig_msg, category, explanation,
               tags, refs, created_by) -> dict:
        now = time.time()
        c   = self._conn()
        cur = c.execute(
            """INSERT INTO threat_intel
               (sig_id, sig_msg, category, explanation, tags, refs,
                created_by, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (int(sig_id) if sig_id else None,
             sig_msg or None, category or None,
             explanation,
             json.dumps(tags or []), json.dumps(refs or []),
             created_by, now, now),
        )
        c.commit()
        return self.get_by_id(cur.lastrowid)

    def update(self, tid: int, **fields) -> dict | None:
        allowed = {"sig_id", "sig_msg", "category", "explanation", "tags", "refs"}
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return self.get_by_id(tid)
        for key in ("tags", "refs"):
            if key in updates and isinstance(updates[key], list):
                updates[key] = json.dumps(updates[key])
        for key in ("sig_msg", "category"):
            if key in updates and not updates[key]:
                updates[key] = None
        if "sig_id" in updates:
            try:
                updates["sig_id"] = int(updates["sig_id"]) if updates["sig_id"] else None
            except (ValueError, TypeError):
                updates["sig_id"] = None
        updates["updated_at"] = time.time()
        cols = ", ".join(f"{k} = ?" for k in updates)
        vals = list(updates.values()) + [tid]
        c    = self._conn()
        c.execute(f"UPDATE threat_intel SET {cols} WHERE id = ?", vals)
        c.commit()
        return self.get_by_id(tid)

    def delete(self, tid: int):
        c = self._conn()
        c.execute("DELETE FROM threat_intel WHERE id = ?", (tid,))
        c.commit()

    # ── Lookup ────────────────────────────────────────────────────────────────

    def lookup(self, sig_id: int = None, category: str = None) -> dict | None:
        """Best explanation for an alert — SID first, category fallback."""
        if sig_id:
            row = self._conn().execute(
                "SELECT * FROM threat_intel WHERE sig_id = ? "
                "ORDER BY updated_at DESC LIMIT 1",
                (int(sig_id),),
            ).fetchone()
            if row:
                return self._hydrate(row)
        if category:
            row = self._conn().execute(
                "SELECT * FROM threat_intel "
                "WHERE sig_id IS NULL AND category = ? COLLATE NOCASE "
                "ORDER BY updated_at DESC LIMIT 1",
                (category,),
            ).fetchone()
            if row:
                return self._hydrate(row)
        return None

    # ── Coverage gaps ─────────────────────────────────────────────────────────

    def coverage_gaps(self, top_sids: list[dict], limit: int = 10) -> list[dict]:
        """
        Given a list of {sig_id, sig_msg, count} dicts (from AlertDB.top_sids),
        return those whose sig_id has no explanation yet, up to `limit`.
        """
        covered = {
            row[0]
            for row in self._conn().execute(
                "SELECT sig_id FROM threat_intel WHERE sig_id IS NOT NULL"
            ).fetchall()
        }
        return [r for r in top_sids if r["sig_id"] not in covered][:limit]

    def stats(self) -> dict:
        c      = self._conn()
        total  = c.execute("SELECT COUNT(*) FROM threat_intel").fetchone()[0]
        by_sid = c.execute(
            "SELECT COUNT(*) FROM threat_intel WHERE sig_id IS NOT NULL"
        ).fetchone()[0]
        by_cat = c.execute(
            "SELECT COUNT(*) FROM threat_intel "
            "WHERE sig_id IS NULL AND category IS NOT NULL"
        ).fetchone()[0]
        return {"total": total, "by_sid": by_sid, "by_category": by_cat}

    # ── .htf Import / Export ─────────────────────────────────────────────────

    HTF_HEADER = (
        "# ─────────────────────────────────────────────\n"
        "# Heimdall Threat Intel Feed (.htf)\n"
        "# One [entry] block per record, closed by ---\n"
        "# Either sig_id OR category must be non-empty\n"
        "# tags / refs = comma-separated\n"
        "# Lines starting with # are comments\n"
        "# ─────────────────────────────────────────────\n"
    )

    def export_htf(self) -> str:
        """Serialise all threat intel entries to .htf text format."""
        entries = self.get_all()
        lines   = [self.HTF_HEADER]
        for e in entries:
            lines.append("[entry]")
            lines.append(f"sig_id: {e.get('sig_id') or ''}")
            lines.append(f"sig_msg: {e.get('sig_msg') or ''}")
            lines.append(f"category: {e.get('category') or ''}")
            # Multi-line explanation: first line inline, continuations indented
            explanation = (e.get("explanation") or "").replace("\r\n", "\n").replace("\r", "\n")
            exp_lines = explanation.split("\n")
            lines.append(f"explanation: {exp_lines[0]}")
            for cont in exp_lines[1:]:
                lines.append(f"  {cont}")
            tags_str = ", ".join(e.get("tags") or [])
            refs_str = ", ".join(e.get("refs") or [])
            lines.append(f"tags: {tags_str}")
            lines.append(f"refs: {refs_str}")
            lines.append("---")
            lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _parse_htf(text: str) -> tuple[list[dict], list[str]]:
        """
        Parse .htf text into a list of entry dicts and a list of warning strings.
        Tolerates blank lines, comments, and multi-line explanations (indented).
        """
        entries  = []
        warnings = []
        current  = None
        last_key = None

        for raw_line in text.splitlines():
            line = raw_line.rstrip()

            # Comment or blank outside a block
            if line.startswith("#"):
                continue
            if line.strip() == "" and current is None:
                continue

            # Block open
            if line.strip() == "[entry]":
                current  = {"sig_id": None, "sig_msg": "", "category": "",
                            "explanation": "", "tags": [], "refs": []}
                last_key = None
                continue

            # Block close
            if line.strip() == "---":
                if current is not None:
                    entries.append(current)
                current  = None
                last_key = None
                continue

            if current is None:
                continue

            # Indented continuation line (multi-line explanation)
            if raw_line.startswith("  ") or raw_line.startswith("\t"):
                if last_key == "explanation":
                    current["explanation"] += "\n" + line.strip()
                continue

            # Key: value line
            if ":" in line:
                key, _, val = line.partition(":")
                key = key.strip().lower()
                val = val.strip()

                if key == "sig_id":
                    try:
                        current["sig_id"] = int(val) if val else None
                    except ValueError:
                        warnings.append(f"Invalid sig_id '{val}' — skipped")
                        current["sig_id"] = None
                elif key == "sig_msg":
                    current["sig_msg"] = val
                elif key == "category":
                    current["category"] = val
                elif key == "explanation":
                    current["explanation"] = val
                    last_key = "explanation"
                    continue
                elif key == "tags":
                    current["tags"] = [t.strip() for t in val.split(",") if t.strip()]
                elif key == "refs":
                    current["refs"] = [r.strip() for r in val.split(",") if r.strip()]
                last_key = key

        # Validate all entries
        valid    = []
        for i, e in enumerate(entries, start=1):
            if not e.get("sig_id") and not e.get("category", "").strip():
                warnings.append(f"Entry {i}: skipped — both sig_id and category are empty")
                continue
            if not e.get("explanation", "").strip():
                warnings.append(f"Entry {i} (sig_id={e.get('sig_id') or e.get('category')}): "
                                f"skipped — explanation is required")
                continue
            valid.append(e)

        return valid, warnings

    def import_htf(self, text: str, imported_by: str = "import") -> dict:
        """
        Parse .htf text, dedup against existing entries, create new ones.
        Returns {imported, skipped, errors, warnings}.
        """
        entries, parse_warnings = self._parse_htf(text)

        # Build dedup sets from existing entries (single connection)
        _c = self._conn()
        existing_sids = {
            row[0] for row in
            _c.execute(
                "SELECT sig_id FROM threat_intel WHERE sig_id IS NOT NULL"
            ).fetchall()
        }
        existing_cats = {
            (row[0] or "").lower() for row in
            _c.execute(
                "SELECT category FROM threat_intel WHERE sig_id IS NULL AND category IS NOT NULL"
            ).fetchall()
        }

        imported = skipped = 0
        errors   = []

        for e in entries:
            try:
                sid = e.get("sig_id")
                cat = (e.get("category") or "").strip()

                # Skip exact duplicates
                if sid and sid in existing_sids:
                    skipped += 1
                    continue
                if not sid and cat and cat.lower() in existing_cats:
                    skipped += 1
                    continue

                self.create(
                    sig_id      = sid,
                    sig_msg     = e.get("sig_msg") or "",
                    category    = cat or None,
                    explanation = e["explanation"],
                    tags        = e.get("tags") or [],
                    refs        = e.get("refs") or [],
                    created_by  = imported_by,
                )
                if sid:
                    existing_sids.add(sid)
                if cat:
                    existing_cats.add(cat.lower())
                imported += 1
            except Exception as exc:
                errors.append(f"Entry (sig_id={e.get('sig_id')}): {exc}")

        log.info("HTF import: %d imported, %d skipped, %d errors",
                 imported, skipped, len(errors))
        return {
            "imported": imported,
            "skipped":  skipped,
            "errors":   errors,
            "warnings": parse_warnings,
        }


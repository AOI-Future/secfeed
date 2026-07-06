"""Security Intelligence Feed Fetcher and Cache.

Aggregates data from authoritative security sources into a local SQLite cache.
Designed for the standalone secfeed MCP server.
"""

import asyncio
import hashlib
import json
import logging
import os
import sqlite3
from datetime import datetime, timedelta, timezone

import feedparser
import httpx

from taxonomy import classify_th

logger = logging.getLogger("secfeed")

DB_PATH = os.environ.get("SECFEED_DB_PATH", "/data/secfeed.db")

# === Feed Configuration ===

RSS_FEEDS = {
    "hackernews": "https://feeds.feedburner.com/TheHackersNews",
    "bleepingcomputer": "https://www.bleepingcomputer.com/feed/",
    "krebs": "https://krebsonsecurity.com/feed/",
    "therecord": "https://therecord.media/feed",
    "sans_isc": "https://isc.sans.edu/rssfeed.xml",
    "cisa_advisories": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "arxiv_cs_cr": "https://rss.arxiv.org/rss/cs.CR",
    # Agent-security focused sources (LLM/agent threat coverage for TH-01..TH-10)
    "simonwillison": "https://simonwillison.net/atom/everything/",
    "embracethered": "https://embracethered.com/blog/index.xml",
}

# Fetch intervals (seconds)
INTERVALS = {
    "cisa_kev": 21600,         # 6h
    "nvd_cve": 7200,           # 2h
    "epss": 7200,              # 2h (enrichment pass)
    "github_advisories": 3600, # 1h
    "github_poc": 3600,        # 1h
    "threatfox": 3600,         # 1h
    "rss": 3600,               # 1h (all RSS feeds)
}


class SecurityDB:
    """SQLite cache for security intelligence data."""

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self):
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                title TEXT,
                description TEXT,
                severity TEXT,
                cvss_score REAL,
                epss_score REAL,
                epss_percentile REAL,
                affected_packages TEXT DEFAULT '[]',
                references_json TEXT DEFAULT '[]',
                published_at TEXT,
                updated_at TEXT,
                fetched_at TEXT,
                has_poc INTEGER DEFAULT 0,
                in_cisa_kev INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS security_news (
                id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                title TEXT,
                summary TEXT,
                url TEXT,
                author TEXT,
                published_at TEXT,
                fetched_at TEXT,
                categories TEXT DEFAULT '[]'
            );

            CREATE TABLE IF NOT EXISTS threat_intel (
                id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                type TEXT,
                title TEXT,
                description TEXT,
                indicators TEXT DEFAULT '{}',
                tags TEXT DEFAULT '[]',
                published_at TEXT,
                fetched_at TEXT
            );

            CREATE TABLE IF NOT EXISTS feed_status (
                source TEXT PRIMARY KEY,
                last_fetch TEXT,
                last_success TEXT,
                items_count INTEGER DEFAULT 0,
                error TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity);
            CREATE INDEX IF NOT EXISTS idx_vuln_published ON vulnerabilities(published_at);
            CREATE INDEX IF NOT EXISTS idx_vuln_epss ON vulnerabilities(epss_score);
            CREATE INDEX IF NOT EXISTS idx_vuln_kev ON vulnerabilities(in_cisa_kev);
            CREATE INDEX IF NOT EXISTS idx_news_published ON security_news(published_at);
            CREATE INDEX IF NOT EXISTS idx_news_source ON security_news(source);
            CREATE INDEX IF NOT EXISTS idx_threat_published ON threat_intel(published_at);

            CREATE VIRTUAL TABLE IF NOT EXISTS search_fts USING fts5(
                item_id, item_type, source, title, content,
                tokenize='porter unicode61'
            );
        """)
        conn.commit()
        # Migration: agent-threat classification column (JSON array of TH ids,
        # NULL = not yet classified, '[]' = classified as not agent-relevant)
        for table in ("vulnerabilities", "security_news", "threat_intel"):
            try:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN th_classes TEXT")
                conn.commit()
            except sqlite3.OperationalError:
                pass  # column already exists
        conn.close()

    def upsert_vulnerability(self, vuln: dict):
        conn = self._get_conn()
        now = datetime.now(timezone.utc).isoformat()
        th_classes = json.dumps(classify_th(f"{vuln.get('title') or ''} {vuln.get('description') or ''}"))
        conn.execute("""
            INSERT INTO vulnerabilities
                (id, source, title, description, severity, cvss_score,
                 epss_score, epss_percentile, affected_packages, references_json,
                 published_at, updated_at, fetched_at, has_poc, in_cisa_kev, th_classes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                title=COALESCE(excluded.title, title),
                description=COALESCE(excluded.description, description),
                severity=COALESCE(excluded.severity, severity),
                cvss_score=COALESCE(excluded.cvss_score, cvss_score),
                epss_score=COALESCE(excluded.epss_score, epss_score),
                epss_percentile=COALESCE(excluded.epss_percentile, epss_percentile),
                affected_packages=CASE WHEN excluded.affected_packages != '[]'
                    THEN excluded.affected_packages ELSE affected_packages END,
                references_json=CASE WHEN excluded.references_json != '[]'
                    THEN excluded.references_json ELSE references_json END,
                updated_at=excluded.updated_at,
                fetched_at=excluded.fetched_at,
                has_poc=MAX(has_poc, excluded.has_poc),
                in_cisa_kev=MAX(in_cisa_kev, excluded.in_cisa_kev),
                th_classes=CASE WHEN excluded.th_classes != '[]'
                    THEN excluded.th_classes ELSE COALESCE(th_classes, excluded.th_classes) END
        """, (
            vuln.get("id"), vuln.get("source"), vuln.get("title"),
            vuln.get("description"), vuln.get("severity"),
            vuln.get("cvss_score"), vuln.get("epss_score"),
            vuln.get("epss_percentile"),
            json.dumps(vuln.get("affected_packages", [])),
            json.dumps(vuln.get("references", [])),
            vuln.get("published_at"), vuln.get("updated_at", now),
            now, vuln.get("has_poc", 0), vuln.get("in_cisa_kev", 0),
            th_classes,
        ))
        # Update FTS index
        conn.execute("DELETE FROM search_fts WHERE item_id = ?", (vuln["id"],))
        conn.execute(
            "INSERT INTO search_fts (item_id, item_type, source, title, content) VALUES (?, 'vulnerability', ?, ?, ?)",
            (vuln["id"], vuln.get("source", ""), vuln.get("title", ""), vuln.get("description", "")),
        )
        conn.commit()
        conn.close()

    def upsert_news(self, news: dict):
        conn = self._get_conn()
        now = datetime.now(timezone.utc).isoformat()
        th_classes = json.dumps(classify_th(f"{news.get('title') or ''} {news.get('summary') or ''}"))
        conn.execute("""
            INSERT INTO security_news
                (id, source, title, summary, url, author, published_at, fetched_at, categories, th_classes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                title=excluded.title, summary=excluded.summary, fetched_at=excluded.fetched_at,
                th_classes=excluded.th_classes
        """, (
            news["id"], news["source"], news.get("title"),
            news.get("summary"), news.get("url"), news.get("author"),
            news.get("published_at"), now,
            json.dumps(news.get("categories", [])),
            th_classes,
        ))
        conn.execute("DELETE FROM search_fts WHERE item_id = ?", (news["id"],))
        conn.execute(
            "INSERT INTO search_fts (item_id, item_type, source, title, content) VALUES (?, 'news', ?, ?, ?)",
            (news["id"], news["source"], news.get("title", ""), news.get("summary", "")),
        )
        conn.commit()
        conn.close()

    def upsert_threat(self, threat: dict):
        conn = self._get_conn()
        now = datetime.now(timezone.utc).isoformat()
        th_classes = json.dumps(classify_th(f"{threat.get('title') or ''} {threat.get('description') or ''}"))
        conn.execute("""
            INSERT INTO threat_intel
                (id, source, type, title, description, indicators, tags, published_at, fetched_at, th_classes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                title=excluded.title, description=excluded.description,
                indicators=excluded.indicators, fetched_at=excluded.fetched_at,
                th_classes=excluded.th_classes
        """, (
            threat["id"], threat["source"], threat.get("type"),
            threat.get("title"), threat.get("description"),
            json.dumps(threat.get("indicators", {})),
            json.dumps(threat.get("tags", [])),
            threat.get("published_at"), now,
            th_classes,
        ))
        conn.execute("DELETE FROM search_fts WHERE item_id = ?", (threat["id"],))
        conn.execute(
            "INSERT INTO search_fts (item_id, item_type, source, title, content) VALUES (?, 'threat', ?, ?, ?)",
            (threat["id"], threat["source"], threat.get("title", ""), threat.get("description", "")),
        )
        conn.commit()
        conn.close()

    def update_feed_status(self, source: str, success: bool, count: int = 0, error: str = None):
        conn = self._get_conn()
        now = datetime.now(timezone.utc).isoformat()
        conn.execute("""
            INSERT INTO feed_status (source, last_fetch, last_success, items_count, error)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(source) DO UPDATE SET
                last_fetch=excluded.last_fetch,
                last_success=CASE WHEN ? THEN excluded.last_fetch ELSE last_success END,
                items_count=CASE WHEN ? THEN excluded.items_count ELSE items_count END,
                error=excluded.error
        """, (source, now, now if success else None, count, error, success, success))
        conn.commit()
        conn.close()

    def backfill_th_classes(self, batch_size: int = 2000) -> int:
        """Classify rows ingested before the th_classes column existed.

        Idempotent: only touches rows where th_classes IS NULL. Safe to run at
        every startup.
        """
        specs = [
            ("vulnerabilities", "description"),
            ("security_news", "summary"),
            ("threat_intel", "description"),
        ]
        total = 0
        conn = self._get_conn()
        for table, body_col in specs:
            while True:
                rows = conn.execute(
                    f"SELECT id, title, {body_col} AS body FROM {table} "
                    "WHERE th_classes IS NULL LIMIT ?",
                    (batch_size,),
                ).fetchall()
                if not rows:
                    break
                updates = [
                    (json.dumps(classify_th(f"{r['title'] or ''} {r['body'] or ''}")), r["id"])
                    for r in rows
                ]
                conn.executemany(
                    f"UPDATE {table} SET th_classes = ? WHERE id = ?", updates
                )
                conn.commit()
                total += len(rows)
        conn.close()
        if total:
            logger.info(f"th_classes backfill: {total} rows classified")
        return total

    # === Query Methods ===

    def get_cves(self, severity: str = "all", days: int = 7, limit: int = 20) -> list[dict]:
        conn = self._get_conn()
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        query = "SELECT * FROM vulnerabilities WHERE published_at >= ?"
        params: list = [cutoff]
        if severity != "all":
            query += " AND severity = ?"
            params.append(severity.upper())
        query += " ORDER BY COALESCE(epss_score, 0) DESC, published_at DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_kev(self, days: int = 30, limit: int = 20) -> list[dict]:
        conn = self._get_conn()
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        rows = conn.execute("""
            SELECT * FROM vulnerabilities
            WHERE in_cisa_kev = 1 AND published_at >= ?
            ORDER BY published_at DESC LIMIT ?
        """, (cutoff, limit)).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_news(self, source: str = "all", days: int = 3, limit: int = 20) -> list[dict]:
        conn = self._get_conn()
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        query = "SELECT * FROM security_news WHERE published_at >= ?"
        params: list = [cutoff]
        if source != "all":
            query += " AND source = ?"
            params.append(source)
        query += " ORDER BY published_at DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    @staticmethod
    def _sanitize_fts_query(query: str) -> str:
        """Sanitize user query for FTS5 MATCH syntax.

        Wraps each token in double quotes to treat special chars
        (hyphens in CVE-2024-xxxx, dots, etc.) as literals.
        """
        tokens = query.split()
        if not tokens:
            return '""'
        return " ".join(f'"{t}"' for t in tokens)

    def search(self, query: str, limit: int = 20) -> list[dict]:
        conn = self._get_conn()
        safe_query = self._sanitize_fts_query(query)
        try:
            rows = conn.execute("""
                SELECT s.item_id, s.item_type, s.source, s.title,
                       snippet(search_fts, 4, '>>>', '<<<', '...', 40) as snippet
                FROM search_fts s
                WHERE search_fts MATCH ?
                ORDER BY rank
                LIMIT ?
            """, (safe_query, limit)).fetchall()
        except Exception:
            # Fallback: try LIKE search if FTS still fails
            like_pat = f"%{query}%"
            rows = conn.execute("""
                SELECT item_id, item_type, source, title, '' as snippet
                FROM search_fts
                WHERE title LIKE ? OR content LIKE ?
                LIMIT ?
            """, (like_pat, like_pat, limit)).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_cve_detail(self, cve_id: str) -> dict | None:
        """Get full detail for a single CVE from local cache."""
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM vulnerabilities WHERE id = ?", (cve_id,)).fetchone()
        if not row:
            conn.close()
            return None
        result = dict(row)
        # Parse JSON fields
        for field in ("affected_packages", "references_json"):
            if result.get(field):
                try:
                    result[field] = json.loads(result[field])
                except (json.JSONDecodeError, TypeError):
                    pass
        # Get related news/threat intel
        safe_id = self._sanitize_fts_query(cve_id)
        try:
            related = conn.execute("""
                SELECT item_id, item_type, source, title
                FROM search_fts WHERE search_fts MATCH ? AND item_id != ?
                ORDER BY rank LIMIT 10
            """, (safe_id, cve_id)).fetchall()
            result["related_items"] = [dict(r) for r in related]
        except Exception:
            result["related_items"] = []
        conn.close()
        return result

    def get_summary(self) -> dict:
        conn = self._get_conn()
        now = datetime.now(timezone.utc)
        day_ago = (now - timedelta(days=1)).isoformat()
        week_ago = (now - timedelta(days=7)).isoformat()

        critical_cves = conn.execute(
            "SELECT COUNT(*) FROM vulnerabilities WHERE severity IN ('CRITICAL','HIGH') AND published_at >= ?",
            (day_ago,),
        ).fetchone()[0]

        new_kev = conn.execute(
            "SELECT COUNT(*) FROM vulnerabilities WHERE in_cisa_kev = 1 AND fetched_at >= ?",
            (day_ago,),
        ).fetchone()[0]

        high_epss = conn.execute("""
            SELECT id, title, severity, cvss_score, epss_score, has_poc, in_cisa_kev
            FROM vulnerabilities
            WHERE epss_score >= 0.7 AND published_at >= ?
            ORDER BY epss_score DESC LIMIT 5
        """, (week_ago,)).fetchall()

        recent_pocs = conn.execute("""
            SELECT id, title, severity, cvss_score, epss_score
            FROM vulnerabilities
            WHERE has_poc = 1 AND fetched_at >= ?
            ORDER BY published_at DESC LIMIT 5
        """, (day_ago,)).fetchall()

        news_count = conn.execute(
            "SELECT COUNT(*) FROM security_news WHERE published_at >= ?", (day_ago,)
        ).fetchone()[0]

        top_news = conn.execute("""
            SELECT source, title, url FROM security_news
            WHERE published_at >= ?
            ORDER BY published_at DESC LIMIT 5
        """, (day_ago,)).fetchall()

        threat_count = conn.execute(
            "SELECT COUNT(*) FROM threat_intel WHERE published_at >= ?", (day_ago,)
        ).fetchone()[0]

        recent_research = conn.execute("""
            SELECT title, description FROM threat_intel
            WHERE source = 'arxiv_cs_cr' AND published_at >= ?
            ORDER BY published_at DESC LIMIT 3
        """, (week_ago,)).fetchall()

        feed_status = conn.execute(
            "SELECT source, last_success, items_count, error FROM feed_status"
        ).fetchall()

        conn.close()

        return {
            "period": "24h",
            "generated_at": now.isoformat(),
            "critical_high_cves_24h": critical_cves,
            "new_cisa_kev_24h": new_kev,
            "high_epss_vulns": [dict(r) for r in high_epss],
            "recent_pocs": [dict(r) for r in recent_pocs],
            "news_articles_24h": news_count,
            "top_news": [dict(r) for r in top_news],
            "threat_indicators_24h": threat_count,
            "recent_ai_security_research": [dict(r) for r in recent_research],
            "feed_health": [dict(r) for r in feed_status],
        }

    # === Agent-Threat Query Methods (agent-security-manual taxonomy) ===

    def get_agent_items(self, threat_class: str = "all", days: int = 7,
                        limit: int = 20) -> list[dict]:
        """Items classified under one or more TH-XX agent threat classes.

        threat_class: "all" or a specific TH id (e.g. "TH-01").
        """
        conn = self._get_conn()
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        th_filter = ""
        extra_params: list = []
        if threat_class != "all":
            # th_classes is a JSON array like ["TH-01","TH-04"]
            th_filter = " AND th_classes LIKE ?"
            extra_params.append(f'%"{threat_class.upper()}"%')

        specs = [
            ("vulnerabilities", "vulnerability", "description",
             "'https://nvd.nist.gov/vuln/detail/' || id"),
            ("security_news", "news", "summary", "url"),
            ("threat_intel", "threat_intel", "description", "NULL"),
        ]
        items: list[dict] = []
        for table, item_type, body_col, url_expr in specs:
            rows = conn.execute(f"""
                SELECT id, source, title,
                       substr({body_col}, 1, 500) AS summary,
                       {url_expr} AS url,
                       published_at, th_classes,
                       '{item_type}' AS item_type
                FROM {table}
                WHERE th_classes IS NOT NULL AND th_classes != '[]'
                  AND published_at >= ?{th_filter}
            """, [cutoff, *extra_params]).fetchall()
            items.extend(dict(r) for r in rows)
        conn.close()

        for item in items:
            try:
                item["th_classes"] = json.loads(item["th_classes"])
            except (json.JSONDecodeError, TypeError):
                item["th_classes"] = []
        items.sort(key=lambda i: i["published_at"] or "", reverse=True)
        return items[:limit]

    def get_agent_digest(self, days: int = 7) -> dict:
        """Aggregate agent-threat activity: per-TH counts + most recent items."""
        conn = self._get_conn()
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        counts: dict[str, int] = {}
        total = 0
        for table in ("vulnerabilities", "security_news", "threat_intel"):
            rows = conn.execute(f"""
                SELECT th_classes FROM {table}
                WHERE th_classes IS NOT NULL AND th_classes != '[]'
                  AND published_at >= ?
            """, (cutoff,)).fetchall()
            for r in rows:
                total += 1
                try:
                    for th in json.loads(r["th_classes"]):
                        counts[th] = counts.get(th, 0) + 1
                except (json.JSONDecodeError, TypeError):
                    pass
        conn.close()
        return {
            "period_days": days,
            "total_agent_relevant_items": total,
            "counts_by_threat": dict(sorted(counts.items())),
        }


class FeedFetcher:
    """Async fetcher for all security intelligence sources."""

    def __init__(self, db: SecurityDB):
        self.db = db
        self.client = httpx.AsyncClient(
            timeout=30.0,
            headers={"User-Agent": "PurpleSecFeed/1.0 (Security Intelligence Aggregator)"},
            follow_redirects=True,
        )
        self._nvd_api_key = os.environ.get("NVD_API_KEY")
        self._gh_token = os.environ.get("GITHUB_TOKEN")

    async def close(self):
        await self.client.aclose()

    # === On-demand CVE Detail Lookup ===

    async def fetch_cve_detail(self, cve_id: str) -> dict | None:
        """Fetch full detail for a specific CVE from NVD + EPSS (on-demand)."""
        # 1. NVD CVE 2.0 lookup
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        headers = {}
        if self._nvd_api_key:
            headers["apiKey"] = self._nvd_api_key

        try:
            resp = await self.client.get(
                url, params={"cveId": cve_id}, headers=headers, timeout=30.0
            )
            resp.raise_for_status()
            data = resp.json()
            items = data.get("vulnerabilities", [])
            if not items:
                return None

            cve = items[0].get("cve", {})

            # CVSS extraction
            metrics = cve.get("metrics", {})
            cvss_score = None
            severity = None
            cvss_vector = None
            for ver in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if ver in metrics and metrics[ver]:
                    cvss_data = metrics[ver][0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                    severity = cvss_data.get("baseSeverity", "").upper()
                    cvss_vector = cvss_data.get("vectorString")
                    break

            # English description
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break

            # References
            refs = [
                {"url": r.get("url", ""), "source": r.get("source", ""), "tags": r.get("tags", [])}
                for r in cve.get("references", [])
            ]

            # Affected configurations (CPE)
            affected = []
            for config in cve.get("configurations", []):
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        if match.get("vulnerable"):
                            affected.append({
                                "cpe": match.get("criteria", ""),
                                "version_start": match.get("versionStartIncluding", ""),
                                "version_end": match.get("versionEndExcluding")
                                    or match.get("versionEndIncluding", ""),
                            })

            # Weaknesses (CWE)
            weaknesses = []
            for w in cve.get("weaknesses", []):
                for d in w.get("description", []):
                    if d.get("lang") == "en":
                        weaknesses.append(d.get("value", ""))

            vuln_data = {
                "id": cve_id,
                "source": "nvd",
                "title": cve_id,
                "description": desc[:2000],
                "severity": severity,
                "cvss_score": cvss_score,
                "published_at": cve.get("published", ""),
                "references": [r["url"] for r in refs],
            }
            self.db.upsert_vulnerability(vuln_data)

        except Exception as e:
            logger.error(f"NVD lookup for {cve_id} failed: {e}")
            return None

        # 2. EPSS enrichment
        try:
            epss_resp = await self.client.get(
                "https://api.first.org/data/v1/epss", params={"cve": cve_id}
            )
            epss_resp.raise_for_status()
            epss_data = epss_resp.json().get("data", [])
            epss_score = None
            epss_percentile = None
            if epss_data:
                epss_score = float(epss_data[0].get("epss", 0))
                epss_percentile = float(epss_data[0].get("percentile", 0))
                conn = self.db._get_conn()
                conn.execute(
                    "UPDATE vulnerabilities SET epss_score = ?, epss_percentile = ? WHERE id = ?",
                    (epss_score, epss_percentile, cve_id),
                )
                conn.commit()
                conn.close()
        except Exception as e:
            logger.warning(f"EPSS lookup for {cve_id} failed: {e}")
            epss_score = None
            epss_percentile = None

        return {
            "id": cve_id,
            "description": desc,
            "severity": severity,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "epss_score": epss_score,
            "epss_percentile": epss_percentile,
            "weaknesses": weaknesses,
            "affected_configurations": affected,
            "references": refs,
            "published": cve.get("published", ""),
            "last_modified": cve.get("lastModified", ""),
        }

    # === CISA Known Exploited Vulnerabilities ===

    async def fetch_cisa_kev(self):
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        try:
            resp = await self.client.get(url)
            resp.raise_for_status()
            data = resp.json()
            count = 0
            for vuln in data.get("vulnerabilities", []):
                self.db.upsert_vulnerability({
                    "id": vuln.get("cveID", ""),
                    "source": "cisa_kev",
                    "title": f"{vuln.get('vendorProject', '')} {vuln.get('product', '')}: "
                             f"{vuln.get('vulnerabilityName', '')}",
                    "description": vuln.get("shortDescription", ""),
                    "severity": "CRITICAL",
                    "published_at": vuln.get("dateAdded", ""),
                    "in_cisa_kev": 1,
                    "references": [vuln.get("notes", "")],
                })
                count += 1
            self.db.update_feed_status("cisa_kev", True, count)
            logger.info(f"CISA KEV: {count} vulnerabilities indexed")
        except Exception as e:
            self.db.update_feed_status("cisa_kev", False, error=str(e))
            logger.error(f"CISA KEV fetch failed: {e}")

    # === NVD CVE API 2.0 ===

    async def fetch_nvd_cve(self):
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=7)
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": 200,
        }
        headers = {}
        if self._nvd_api_key:
            headers["apiKey"] = self._nvd_api_key

        try:
            resp = await self.client.get(url, params=params, headers=headers, timeout=60.0)
            resp.raise_for_status()
            data = resp.json()
            count = 0
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")

                # Extract CVSS
                metrics = cve.get("metrics", {})
                cvss_score = None
                severity = None
                for ver in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if ver in metrics and metrics[ver]:
                        cvss_data = metrics[ver][0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore")
                        severity = cvss_data.get("baseSeverity", "").upper()
                        break

                # English description
                desc = ""
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value", "")
                        break

                refs = [r.get("url", "") for r in cve.get("references", [])]

                self.db.upsert_vulnerability({
                    "id": cve_id,
                    "source": "nvd",
                    "title": cve_id,
                    "description": desc[:2000],
                    "severity": severity,
                    "cvss_score": cvss_score,
                    "published_at": cve.get("published", ""),
                    "references": refs,
                })
                count += 1

            self.db.update_feed_status("nvd_cve", True, count)
            logger.info(f"NVD CVE: {count} CVEs indexed")
        except Exception as e:
            self.db.update_feed_status("nvd_cve", False, error=str(e))
            logger.error(f"NVD CVE fetch failed: {e}")

    # === EPSS Enrichment ===

    async def fetch_epss(self):
        conn = self.db._get_conn()
        cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        rows = conn.execute("""
            SELECT id FROM vulnerabilities
            WHERE epss_score IS NULL AND published_at >= ? AND id LIKE 'CVE-%'
            LIMIT 100
        """, (cutoff,)).fetchall()
        conn.close()

        if not rows:
            self.db.update_feed_status("epss", True, 0)
            return

        cve_ids = [r["id"] for r in rows]
        url = "https://api.first.org/data/v1/epss"

        try:
            count = 0
            for i in range(0, len(cve_ids), 30):
                batch = cve_ids[i:i + 30]
                resp = await self.client.get(url, params={"cve": ",".join(batch)})
                resp.raise_for_status()
                data = resp.json()

                conn = self.db._get_conn()
                for item in data.get("data", []):
                    conn.execute(
                        "UPDATE vulnerabilities SET epss_score = ?, epss_percentile = ? WHERE id = ?",
                        (float(item.get("epss", 0)), float(item.get("percentile", 0)), item.get("cve", "")),
                    )
                    count += 1
                conn.commit()
                conn.close()
                await asyncio.sleep(1)

            self.db.update_feed_status("epss", True, count)
            logger.info(f"EPSS: {count} CVEs enriched")
        except Exception as e:
            self.db.update_feed_status("epss", False, error=str(e))
            logger.error(f"EPSS enrichment failed: {e}")

    # === GitHub Security Advisories ===

    async def fetch_github_advisories(self):
        url = "https://api.github.com/advisories"
        params = {"per_page": 50, "sort": "published", "direction": "desc", "type": "reviewed"}
        headers = {"Accept": "application/vnd.github+json"}
        if self._gh_token:
            headers["Authorization"] = f"Bearer {self._gh_token}"

        try:
            resp = await self.client.get(url, params=params, headers=headers)
            resp.raise_for_status()
            count = 0
            for adv in resp.json():
                ghsa_id = adv.get("ghsa_id", "")
                cve_id = adv.get("cve_id") or ghsa_id

                packages = []
                for v in adv.get("vulnerabilities", []):
                    pkg = v.get("package", {})
                    packages.append({
                        "ecosystem": pkg.get("ecosystem", ""),
                        "name": pkg.get("name", ""),
                        "vulnerable_range": v.get("vulnerable_version_range", ""),
                        "patched": v.get("patched_versions", ""),
                    })

                severity = (adv.get("severity") or "").upper()
                cvss = adv.get("cvss", {})

                self.db.upsert_vulnerability({
                    "id": cve_id,
                    "source": "github_advisory",
                    "title": adv.get("summary", ""),
                    "description": (adv.get("description") or "")[:2000],
                    "severity": severity,
                    "cvss_score": cvss.get("score") if cvss else None,
                    "affected_packages": packages,
                    "published_at": adv.get("published_at", ""),
                    "references": [adv.get("html_url", "")],
                })
                count += 1

            self.db.update_feed_status("github_advisories", True, count)
            logger.info(f"GitHub Advisories: {count} indexed")
        except Exception as e:
            self.db.update_feed_status("github_advisories", False, error=str(e))
            logger.error(f"GitHub Advisories fetch failed: {e}")

    # === GitHub PoC Tracking ===

    async def fetch_github_poc(self):
        conn = self.db._get_conn()
        cutoff = (datetime.now(timezone.utc) - timedelta(days=14)).isoformat()
        cves = conn.execute("""
            SELECT id FROM vulnerabilities
            WHERE severity IN ('CRITICAL', 'HIGH')
              AND published_at >= ? AND has_poc = 0 AND id LIKE 'CVE-%'
            ORDER BY COALESCE(epss_score, 0) DESC, published_at DESC LIMIT 15
        """, (cutoff,)).fetchall()
        conn.close()

        if not cves:
            self.db.update_feed_status("github_poc", True, 0)
            return

        headers = {"Accept": "application/vnd.github+json"}
        if self._gh_token:
            headers["Authorization"] = f"Bearer {self._gh_token}"

        count = 0
        try:
            for row in cves:
                cve_id = row["id"]
                resp = await self.client.get(
                    "https://api.github.com/search/repositories",
                    params={"q": f"{cve_id} poc exploit", "sort": "updated", "per_page": 3},
                    headers=headers,
                )
                if resp.status_code == 403:
                    logger.warning("GitHub rate limited, stopping PoC search")
                    break
                resp.raise_for_status()

                if resp.json().get("total_count", 0) > 0:
                    conn = self.db._get_conn()
                    conn.execute("UPDATE vulnerabilities SET has_poc = 1 WHERE id = ?", (cve_id,))
                    conn.commit()
                    conn.close()
                    count += 1
                    logger.info(f"PoC found: {cve_id}")

                await asyncio.sleep(6)  # GitHub search: 10 req/min

            self.db.update_feed_status("github_poc", True, count)
            logger.info(f"GitHub PoC: {count} CVEs with PoC confirmed")
        except Exception as e:
            self.db.update_feed_status("github_poc", False, error=str(e))
            logger.error(f"GitHub PoC search failed: {e}")

    # === Abuse.ch ThreatFox ===

    async def fetch_threatfox(self):
        url = "https://threatfox-api.abuse.ch/api/v1/"
        try:
            resp = await self.client.post(
                url,
                json={"query": "get_iocs", "days": 1},
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code != 200:
                logger.warning(f"ThreatFox returned {resp.status_code}, skipping")
                self.db.update_feed_status("threatfox", False, error=f"HTTP {resp.status_code}")
                return
            data = resp.json()

            count = 0
            if data.get("query_status") == "ok":
                for ioc in (data.get("data") or [])[:100]:
                    ioc_id = str(ioc.get("id", ""))
                    self.db.upsert_threat({
                        "id": f"threatfox-{ioc_id}",
                        "source": "threatfox",
                        "type": "ioc",
                        "title": f"{ioc.get('ioc_type', '')}: {ioc.get('ioc', '')}",
                        "description": (
                            f"Malware: {ioc.get('malware_printable', 'Unknown')}. "
                            f"Threat: {ioc.get('threat_type_desc', '')}. "
                            f"Confidence: {ioc.get('confidence_level', '')}%"
                        ),
                        "indicators": {
                            "type": ioc.get("ioc_type", ""),
                            "value": ioc.get("ioc", ""),
                            "malware": ioc.get("malware_printable", ""),
                            "threat_type": ioc.get("threat_type", ""),
                        },
                        "tags": ioc.get("tags") or [],
                        "published_at": ioc.get("first_seen_utc", ""),
                    })
                    count += 1

            self.db.update_feed_status("threatfox", True, count)
            logger.info(f"ThreatFox: {count} IoCs indexed")
        except Exception as e:
            self.db.update_feed_status("threatfox", False, error=str(e))
            logger.error(f"ThreatFox fetch failed: {e}")

    # === RSS Feeds (all sources) ===

    async def fetch_rss_feeds(self):
        total = 0
        for source, url in RSS_FEEDS.items():
            try:
                resp = await self.client.get(url)
                resp.raise_for_status()
                feed = feedparser.parse(resp.text)
                count = 0

                for entry in feed.entries[:30]:
                    raw_id = entry.get("link", "") or entry.get("id", "")
                    entry_id = hashlib.sha256(raw_id.encode()).hexdigest()[:16]

                    pub_date = ""
                    for attr in ("published_parsed", "updated_parsed"):
                        parsed = getattr(entry, attr, None)
                        if parsed:
                            pub_date = datetime(*parsed[:6], tzinfo=timezone.utc).isoformat()
                            break

                    summary = entry.get("summary", "")[:1000]
                    categories = [t.get("term", "") for t in entry.get("tags", [])]

                    if source == "arxiv_cs_cr":
                        self.db.upsert_threat({
                            "id": f"arxiv-{entry_id}",
                            "source": "arxiv_cs_cr",
                            "type": "research",
                            "title": entry.get("title", "").replace("\n", " ").strip(),
                            "description": summary,
                            "tags": categories,
                            "published_at": pub_date,
                        })
                    elif source == "cisa_advisories":
                        self.db.upsert_threat({
                            "id": f"cisa-adv-{entry_id}",
                            "source": "cisa_advisories",
                            "type": "advisory",
                            "title": entry.get("title", ""),
                            "description": summary,
                            "tags": categories,
                            "published_at": pub_date,
                        })
                    else:
                        self.db.upsert_news({
                            "id": f"{source}-{entry_id}",
                            "source": source,
                            "title": entry.get("title", ""),
                            "summary": summary,
                            "url": entry.get("link", ""),
                            "author": entry.get("author", ""),
                            "published_at": pub_date,
                            "categories": categories,
                        })
                    count += 1

                self.db.update_feed_status(source, True, count)
                total += count
                logger.info(f"RSS {source}: {count} items")
            except Exception as e:
                self.db.update_feed_status(source, False, error=str(e))
                logger.error(f"RSS {source} failed: {e}")

        return total


async def run_fetch_loop(fetcher: FeedFetcher):
    """Run all feed fetchers with staggered intervals."""

    async def loop(name: str, fetch_fn, interval: int, initial_delay: int = 0):
        if initial_delay:
            await asyncio.sleep(initial_delay)
        while True:
            try:
                logger.info(f"[{name}] fetching...")
                await fetch_fn()
            except Exception as e:
                logger.error(f"[{name}] unhandled error: {e}")
            await asyncio.sleep(interval)

    # Stagger initial fetches to avoid burst
    tasks = [
        asyncio.create_task(loop("cisa_kev", fetcher.fetch_cisa_kev, INTERVALS["cisa_kev"], 0)),
        asyncio.create_task(loop("nvd_cve", fetcher.fetch_nvd_cve, INTERVALS["nvd_cve"], 5)),
        asyncio.create_task(loop("epss", fetcher.fetch_epss, INTERVALS["epss"], 30)),
        asyncio.create_task(loop("github_advisories", fetcher.fetch_github_advisories, INTERVALS["github_advisories"], 10)),
        asyncio.create_task(loop("github_poc", fetcher.fetch_github_poc, INTERVALS["github_poc"], 60)),
        asyncio.create_task(loop("threatfox", fetcher.fetch_threatfox, INTERVALS["threatfox"], 15)),
        asyncio.create_task(loop("rss", fetcher.fetch_rss_feeds, INTERVALS["rss"], 20)),
    ]

    await asyncio.gather(*tasks)

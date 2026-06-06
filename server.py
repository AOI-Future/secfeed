"""SecFeed — Security Intelligence MCP Server.

Provides curated security intelligence from authoritative sources:
- CISA KEV (Known Exploited Vulnerabilities)
- NVD CVE API 2.0 (NIST)
- EPSS (Exploit Prediction Scoring)
- GitHub Security Advisories (supply chain)
- GitHub PoC tracking
- Abuse.ch ThreatFox (IoCs)
- Security news (The Hacker News, BleepingComputer, Krebs, The Record, SANS ISC)
- CISA Cybersecurity Advisories
- arXiv cs.CR (AI/ML security research)
"""

import asyncio
import json
import logging
import sys
import threading

from fastmcp import FastMCP

from fetcher import FeedFetcher, SecurityDB, run_fetch_loop

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("secfeed")

# Global instances
db = SecurityDB()
fetcher = FeedFetcher(db)

# MCP Server
mcp = FastMCP("secfeed")


def _fmt(data, indent=2) -> str:
    return json.dumps(data, indent=indent, ensure_ascii=False, default=str)


# === MCP Tools ===


@mcp.tool()
async def get_latest_cves(severity: str = "all", days: int = 7, limit: int = 20) -> str:
    """Get recent CVEs enriched with EPSS exploit probability scores.

    Args:
        severity: Filter by severity level: "CRITICAL", "HIGH", "MEDIUM", "LOW", or "all"
        days: How many days back to search (default: 7)
        limit: Maximum results to return (default: 20)

    Returns:
        JSON array of CVEs sorted by EPSS score (highest exploit probability first).
        Each entry includes: id, severity, cvss_score, epss_score, has_poc, in_cisa_kev,
        affected_packages, and description.
    """
    results = db.get_cves(severity, days, limit)
    if not results:
        return '{"message": "No CVEs found for the given criteria.", "results": []}'
    return _fmt({"count": len(results), "results": results})


@mcp.tool()
async def get_cisa_kev(days: int = 30, limit: int = 20) -> str:
    """Get CISA Known Exploited Vulnerabilities — confirmed actively exploited in the wild.

    These are the highest-priority vulnerabilities: the US government has confirmed
    active exploitation. Every entry here demands immediate action.

    Args:
        days: How many days back to search (default: 30)
        limit: Maximum results to return (default: 20)

    Returns:
        JSON array of KEV entries with CVE details and EPSS enrichment.
    """
    results = db.get_kev(days, limit)
    if not results:
        return '{"message": "No new CISA KEV entries in the given period.", "results": []}'
    return _fmt({"count": len(results), "results": results})


@mcp.tool()
async def get_security_news(source: str = "all", days: int = 3, limit: int = 20) -> str:
    """Get aggregated security news from trusted sources.

    Sources: hackernews (The Hacker News), bleepingcomputer, krebs (Krebs on Security),
    therecord (The Record by Recorded Future), sans_isc (SANS Internet Storm Center).

    Args:
        source: Filter by source name, or "all" for everything
        days: How many days back to search (default: 3)
        limit: Maximum results to return (default: 20)

    Returns:
        JSON array of news articles with title, summary, url, and source.
    """
    results = db.get_news(source, days, limit)
    if not results:
        return '{"message": "No security news found for the given criteria.", "results": []}'
    return _fmt({"count": len(results), "results": results})


@mcp.tool()
async def search_security(query: str, limit: int = 20) -> str:
    """Full-text search across all security intelligence data.

    Searches vulnerabilities (CVEs, advisories), security news, threat intelligence
    (IoCs, CISA advisories), and AI/ML security research (arXiv cs.CR).

    Args:
        query: Search query (supports AND, OR, NOT operators)
        limit: Maximum results to return (default: 20)

    Returns:
        JSON array of matching items with type, source, title, and context snippet.
    """
    results = db.search(query, limit)
    if not results:
        return '{"message": "No results found.", "results": []}'
    return _fmt({"count": len(results), "results": results})


@mcp.tool()
async def get_cve_detail(cve_id: str) -> str:
    """Get comprehensive detail for a specific CVE from authoritative sources.

    Looks up a CVE by ID (e.g., "CVE-2024-3400") and returns enriched data from
    NVD (NIST), EPSS, CISA KEV status, and PoC tracking. If the CVE is not in
    the local cache, fetches it on-demand from NVD API 2.0.

    Args:
        cve_id: The CVE identifier (e.g., "CVE-2024-3400")

    Returns:
        JSON object with: description, severity, CVSS score/vector, EPSS score,
        CWE weaknesses, affected configurations (CPE), references (with tags),
        CISA KEV status, PoC status, and related items from the intelligence DB.
    """
    cve_id = cve_id.strip().upper()

    # Check local cache first
    cached = db.get_cve_detail(cve_id)

    # On-demand fetch from NVD + EPSS
    fresh = await fetcher.fetch_cve_detail(cve_id)

    if not fresh and not cached:
        return _fmt({"error": f"CVE {cve_id} not found in NVD or local cache."})

    # Merge: fresh NVD data + local enrichments (KEV, PoC, related items)
    if fresh and cached:
        fresh["in_cisa_kev"] = bool(cached.get("in_cisa_kev"))
        fresh["has_poc"] = bool(cached.get("has_poc"))
        fresh["affected_packages"] = cached.get("affected_packages", [])
        fresh["related_items"] = cached.get("related_items", [])
    elif cached and not fresh:
        # NVD fetch failed, use cached data
        fresh = cached
        fresh["_note"] = "Served from local cache (NVD API unreachable)"
    else:
        # New CVE, re-read from DB to get related items
        updated = db.get_cve_detail(cve_id)
        if updated:
            fresh["related_items"] = updated.get("related_items", [])
            fresh["in_cisa_kev"] = bool(updated.get("in_cisa_kev"))
            fresh["has_poc"] = bool(updated.get("has_poc"))

    return _fmt(fresh)


@mcp.tool()
async def get_threat_summary() -> str:
    """Get a high-level threat landscape summary for the last 24 hours.

    Returns an intelligence briefing including:
    - Critical/High CVE count (24h)
    - New CISA KEV additions (24h)
    - Top 5 highest-EPSS vulnerabilities (7d, actively exploitable)
    - CVEs with confirmed PoC exploits (24h)
    - Top security news headlines (24h)
    - Active threat indicators count (24h)
    - Recent AI/ML security research (7d)
    - Feed health status (all sources)

    Use this at the start of each patrol cycle for situational awareness.
    """
    summary = db.get_summary()
    return _fmt(summary)


# === Background Feed Fetcher ===


def _start_fetch_thread():
    """Run the feed fetch loop in a background daemon thread."""
    def target():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(run_fetch_loop(fetcher))
        except Exception as e:
            logger.error(f"Fetch loop crashed: {e}")

    t = threading.Thread(target=target, daemon=True, name="secfeed-fetcher")
    t.start()
    logger.info("Background feed fetcher started")
    return t


# === Entry Point ===

if __name__ == "__main__":
    _start_fetch_thread()

    if "--stdio" in sys.argv:
        logger.info("Starting secfeed (stdio mode)")
        mcp.run(transport="stdio")
    else:
        logger.info("Starting secfeed (SSE mode on 0.0.0.0:8888)")
        mcp.run(transport="sse", host="0.0.0.0", port=8888)

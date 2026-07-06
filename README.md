# secfeed

Security Intelligence MCP server — aggregates authoritative vulnerability, news,
and threat-intel feeds into a local SQLite database and serves them to AI agents
via [MCP](https://modelcontextprotocol.io/) tools.

Every ingested item is auto-classified against the
[agent-security-manual](https://github.com/AOI-Future/agent-security-manual)
threat taxonomy (**TH-01..TH-10**), so agents can pull an AI-agent-security
focused feed and trace each threat to its mitigating controls (CT), requirements
(REQ), and manual chapters.

## Data sources

| Category | Sources |
|---|---|
| Vulnerabilities | CISA KEV, NVD CVE API 2.0, EPSS, GitHub Security Advisories, GitHub PoC search |
| Threat intel | Abuse.ch ThreatFox, CISA Cybersecurity Advisories, arXiv cs.CR |
| News | The Hacker News, BleepingComputer, Krebs on Security, The Record, SANS ISC |
| Agent security | Simon Willison's blog, Embrace The Red |

## MCP tools

| Tool | Purpose |
|---|---|
| `get_latest_cves` | Recent CVEs sorted by EPSS exploit probability |
| `get_cisa_kev` | Known Exploited Vulnerabilities (confirmed in-the-wild) |
| `get_security_news` | Aggregated security news |
| `search_security` | FTS5 full-text search across all data |
| `get_cve_detail` | On-demand NVD + EPSS lookup for one CVE |
| `get_threat_summary` | 24h threat landscape briefing + feed health |
| `get_agent_threat_feed` | Items tagged with agent threat classes TH-01..TH-10 |
| `lookup_taxonomy` | Resolve TH/CT ids to controls, REQs, and manual chapters |
| `get_agent_security_digest` | Per-threat-class activity digest for posture review |

## Agent threat taxonomy

Classification is a deterministic two-tier keyword classifier (`taxonomy.py`):
strong agent-specific patterns always tag; generic security terms tag only when
AI/agent context is present in the same text. No LLM calls — results are
reproducible and auditable.

| ID | Threat class |
|---|---|
| TH-01 | Prompt injection (direct / indirect) |
| TH-02 | Tool abuse / privilege escalation |
| TH-03 | RAG / knowledge-base poisoning |
| TH-04 | Memory / context contamination |
| TH-05 | Agent identity / authority abuse |
| TH-06 | Delegation / multi-agent abuse |
| TH-07 | Supply-chain / MCP / plugin compromise |
| TH-08 | Data exfiltration / secret exposure |
| TH-09 | Audit / evaluation evasion |
| TH-10 | Model / service abuse |

## Deployment

```bash
docker compose up -d --build
docker logs --tail 80 secfeed
```

- Streamable HTTP: `http://<host>:8888/mcp` (put a reverse proxy with auth in front for public exposure)
- stdio mode: `python3 server.py --stdio`
- Data volume: `secfeed-data` mounted at `/data` (SQLite + FTS5)

### Environment variables

| Variable | Purpose |
|---|---|
| `NVD_API_KEY` | Optional — higher NVD API rate limits |
| `GITHUB_TOKEN` | Optional — higher GitHub API rate limits |
| `SECFEED_DB_PATH` | DB path override (default `/data/secfeed.db`) |

Secrets are injected via the compose `environment` block from the host
environment — never commit them.

## Development

```bash
python3 -m venv venv && venv/bin/pip install -r requirements.txt
SECFEED_DB_PATH=/tmp/secfeed-dev.db venv/bin/python3 server.py --stdio
```

## License

MIT

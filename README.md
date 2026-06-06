# secfeed

Standalone Security Intelligence MCP server.

## Runtime

- Host path: `/home/shugo/services/secfeed`
- Container: `secfeed`
- Tailscale bind: `100.94.245.115:8889 -> 8888`
- MCP SSE endpoint: `http://100.94.245.115:8889/sse`
- Docker network: external `ai_network`
- Network aliases: `secfeed`, `purple-secfeed` (legacy compatibility)
- Data volume: `secfeed-data`

## Data sources

CISA KEV, NVD CVE API 2.0, EPSS, GitHub Security Advisories, GitHub PoC search, Abuse.ch ThreatFox, security RSS feeds, CISA advisories, and arXiv cs.CR.

## Operations

```bash
cd /home/shugo/services/secfeed
docker compose up -d --build
docker logs --tail 80 secfeed
curl -I http://100.94.245.115:8889/sse
```

The old `agent-purple_secfeed-data` Docker volume is no longer mounted. Keep it temporarily as rollback backup until the standalone volume has run safely for a while.

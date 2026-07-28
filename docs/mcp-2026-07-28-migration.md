# MCP 2026-07-28 migration gate

## Current decision

Secfeed remains on the existing Streamable HTTP implementation while retaining the canonical, authenticated endpoint:

- public client URL: `https://mcp.aoifuture.com/secfeed/mcp`
- public gateway: nginx plus per-request Bearer `auth_request`
- backend: FastMCP Streamable HTTP on the private Docker network

`requirements.txt` intentionally constrains FastMCP to `<4.0.0`. This prevents an unrelated image rebuild from silently crossing the protocol boundary before an end-to-end migration has been proven.

## Why this is needed

MCP 2026-07-28 removes the `initialize`/`initialized` exchange and `Mcp-Session-Id`; requests are self-describing and use `MCP-Protocol-Version`, `Mcp-Method`, and, for named calls, `Mcp-Name`. It adds `server/discover`, MRTR, cache hints, and authorization changes. The MCP announcement identifies FastMCP 4.0 as the matching implementation line.

The current server contains no sampling, elicitation, roots, or session-coupled application state. Therefore the migration is transport/runtime work; no Secfeed tool schema or SQLite data migration is expected.

## Promotion gate for FastMCP 4

Do not change the upper bound or deploy until all of the following pass in an isolated environment, then in the authenticated production canary:

1. Build the exact FastMCP 4 release selected for deployment; record its immutable version and artifact digest.
2. Send `server/discover` and `tools/list` with `MCP-Protocol-Version: 2026-07-28` and `Mcp-Method`; both succeed without `Mcp-Session-Id`.
3. Call representative read-only tools (`get_threat_summary`, `search_security`) with the required routing headers, and verify responses have no legacy session dependency.
4. Verify the gateway forwards `MCP-Protocol-Version`, `Mcp-Method`, and `Mcp-Name`, while unauthenticated and invalid-token requests still return `401`.
5. Re-run discovery with the Hermes client and verify all nine Secfeed tools; verify feed health and data volume survive the container replacement.
6. Capture an exact deployment receipt (image digest, timestamp, client discovery result) and keep rollback available by restoring the previous image digest.

## Scope exclusions

This gate does not introduce OAuth, Dynamic Client Registration, CIMD, MRTR, Tasks, or new public routes. Secfeed uses static Bearer authentication and read-only tools, so those features are not needed to preserve the current security boundary.

## Sources

- MCP announcement: <https://blog.modelcontextprotocol.io/posts/2026-07-28/>
- Secfeed deployment contract: `README.md`, `docker-compose.yml`

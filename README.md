# Telegram Assistant Bridge

MCP status prototype, local-only by default. No Telegram SDK, credentials, personal data, authentication, subscriptions or background events are implemented.

## Run locally

Requires Node.js 24. Run `npm ci --ignore-scripts`, `npm test`, then `npm start`.
The endpoint is `http://127.0.0.1:3000/mcp`. It exposes exactly one read-only tool, `status`, returning service name, prototype stage and `telegramConnected: false`. It never examines the host, environment, files or other applications.

The official MCP SDK implements Streamable HTTP. This is not a custom JSON status endpoint. The integration test uses the official MCP client to initialize, discover and call the tool; it checks invalid arguments, unknown tools, browser origins and untrusted Host headers. The local server has no authentication: do not expose it to external networks. Origin/Host checks prevent accidental browser access; they are not authentication.

## Container template — not deployed

`compose.yaml` is a review template with no published ports. It requires `BRIDGE_IMAGE` as an explicit image reference; before deployment pin it to a reviewed sha256 digest. The Dockerfile default base tag is for local evaluation only; replace NODE_BASE with a reviewed digest for release. Build away from a production host. Container build/runtime have not been verified unless explicitly recorded separately.

One Compose project, private internal network, reserved named volume, non-root user, read-only root, no capabilities, no Docker socket or host mounts. No external networking is configured. The reserved volume is currently unused; no application data is written. It is not a disk quota. Preliminary limits are 0.25 CPU, 256 MiB RAM without container swap, 64 PIDs, 16 MiB tmpfs and 10 MiB rotated logs. Validate these against measured host capacity. Container isolation does not isolate host resources or protect against a compromised host/root user.

Do not connect this service to another project's networks or volumes. Do not run global prune or down -v. An independent deployment and rollback plan is required.

## Next decisions

1. Complete read-only host capacity, ports, container and HTTPS checks before deployment.
2. Choose a dedicated DNS name and certificate, review the existing HTTPS proxy route and streaming/timeouts. No external port or proxy change is provided here.
3. Require OAuth before exposing any private data, Telegram, events or write tools. The separately approved public static status-only trial is the only no-auth exception. No new identity, token or permanent access is created by this prototype.
4. Test status through protected HTTPS, then connect a personal plugin. A public GitHub repository does not make the plugin public.
5. Implement and validate one synthetic event separately. No MCP Events capability is advertised now. Check SDK support, subscription lifecycle, callback validation and signed delivery before claiming event support. Telegram integration and real credentials come later.

## Sources

- https://developers.openai.com/plugins/build/mcp-server
- https://developers.openai.com/plugins/quickstart
- https://developers.openai.com/plugins/build/mcp-events
- https://github.com/modelcontextprotocol/typescript-sdk/tree/main

The current SDK stable line is v2 with split server/client/node packages; the short OpenAI example still names the v1 package. This prototype uses exact v2 package versions and a lockfile. It does not claim MCP Events compatibility.

## Prepared public status-only trial

The selected hostname is `telegram-bridge.mu56.ru`. See `deploy/APPROVAL.md` for the proposed DNS, dedicated HTTPS vhost, limits, maximum 15-minute trial and rollback. These files are preparation only: no DNS, certificates or server deployment were changed.

`deploy/compose.status.yaml` adds an explicitly enabled public-status Host policy and loopback port 18085. Use it only with the base Compose file and a reviewed, tested image digest after approval. The base Compose file alone still publishes no ports. All Origin headers remain rejected. The only public data is the fixed status response. Authentication is intentionally absent in this narrowly scoped trial; no private data, new tools or events may be added without separate OAuth and release review.

### CI transport limitation

The CI runner accepted port publication on an internal-only Docker network but created no host port mapping. The process remained running without OOM. The image smoke test therefore uses an ephemeral official Node client container sharing only the tested service's network namespace, with the same CPU/RAM/security restrictions and a read-only mount of this public checkout. No network isolation is removed and no host networking/socket is used. This proves MCP operation inside the constrained image, not the proposed host loopback publication. The internal-network plus loopback deployment path remains unverified and must be resolved separately before deploying. Do not silently remove internal isolation to make host publication work.

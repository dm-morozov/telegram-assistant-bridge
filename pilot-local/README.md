# Synthetic protected MCP pilot

This is a synthetic-only resource server, separate from the public status prototype. It has no Telegram network adapter, credentials, real messages or sending tool. The official MCP SDK implements transport; jose validates RS256 RFC9068 access tokens against an explicitly pinned issuer, resource and owner.

Tools: list_new_messages, create_local_draft and get_local_draft. Drafts are bounded in-memory review-only values. Every call requires owner/scopes; source edits/deletions and consent/owner revocation invalidate access and dependent drafts. Background TTL cleanup operates independently of reads.

Run npm ci at the root and npm ci --prefix pilot-local, then npm test on Node24. Tests use ephemeral synthetic keys/tokens and temporary loopback listeners only. No real authorization server is implemented.

## Isolated container entry

The separate deploy/Dockerfile requires an official Node image digest through NODE_BASE. Dockerfile-specific .dockerignore and explicit COPY exclude private config, test keys and local reports. deploy/compose.synthetic.yaml has one internal bridge, no published ports/egress network/socket/neighbor mounts, nonroot/read-only, no capabilities, .25CPU/256MiB/64PIDs and own reserved volume.

Container startup requires explicit owner.local.json and a fresh public-JWKS snapshot. Missing/unverified owner, missing/stale/malformed keys or unknown signing kid fail closed. There is no fixture or remote-key fallback in this entry point. The snapshot directory must be mounted read-only as a directory so host atomic replacement remains visible. Host refresh uses exact pinned HTTPS URL, no redirects/credentials, bounded response and TTL; deploy/refresh_jwks.py uses only installed Python3 standard library (the Node helper is optional). No host software installation is required. deploy/trial_stop.py disables only exact own routes, then stops the exact own container even if nginx test/reload fails; it checks project/image/container identity. Never bake owner config into git/image, or place access tokens/passwords in env/files/logs.

The container closes its runtime after15minutes; an independently tested host route/container/helper cleanup deadline is also required BEFORE public exposure. render-routes.mjs requires inspected own container/image IDs, own Compose project/service, one internal nat bridge and no published ports before rendering loopback Nginx. Re-inspect immediately before reload; nginx -t is mandatory. Container isolation is not host resource isolation and an internal nat bridge does not universally block host services.

The manually dispatched synthetic workflow builds from resolved official image digests and runs official MCP-client host-IP/Nginx transport, auth/Host/Origin negatives, resource and snapshot-rotation/staleness checks. Only the image archive and sanitized evidence are retained for3days. A CI PASS does not prove real ChatGPT OAuth login or deployment. Those require a separately authorized bounded trial with a ready human login/consent and verified cleanup.

References: [MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization), [OpenAI plugin auth](https://developers.openai.com/plugins/build/auth), [jose](https://github.com/panva/jose), [Docker gateway modes](https://docs.docker.com/engine/network/port-publishing/#gateway-modes).
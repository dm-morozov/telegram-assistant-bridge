# Public status-only trial — approval plan

Prepared locally only. No DNS, server configuration, certificate, credentials or plugin changes have been made. Selected hostname: `telegram-bridge.mu56.ru`.

## Public surface and hard boundary

The public `/mcp` endpoint exposes only the static `status` tool. MCP uses POST for protocol calls; it is not an application write tool. No Telegram, history, files, environment, command execution, webhooks, event subscription or authentication is implemented. Public users may learn the service name, prototype stage and that Telegram is disconnected. Anyone can call this public tool; the personal plugin listing is not an access control.

All future private data, Telegram integration, events or write tools are blocked pending a separately reviewed OAuth implementation and new deployment approval. Freeze the exact tested image digest for this trial. No automatic updates, builds or release hooks are part of the trial.

Local default remains loopback-only. Explicit `--public-status` allows the selected public Host; browser Origin headers are rejected even for the same origin. Nginx checks Host and SNI, sets the fixed upstream Host, limits body size/rate/concurrency, and exposes exactly `/mcp`. No CORS wildcard is provided. These are request controls, not user authentication.

## Proposed change set — requires explicit approval

1. DNS: create only A record `telegram-bridge` in the `mu56.ru` zone pointing to the separately confirmed VPS IPv4. Use TTL 300 if supported. Do not change apex/www/MX/TXT/NS or add AAAA/CNAME. Record the exact prior state before writing. Public Google and Cloudflare DoH returned NXDOMAIN during preparation; authoritative NS are Beget. Local project records show prior DNS changes were made by the owner; an automated DNS management connection is not established.
2. Preflight: recheck host capacity, all existing service health, the candidate loopback port 18085 and absence of duplicate vhosts, project paths and certificate names. Do not reuse existing objects on collision. This is a new read-only server operation requiring authorization.
3. Build off-server and review the pinned image digest. Container build/runtime has not been tested because local Docker API access was denied. Do not deploy an untested image.
4. Create only the new project directory, image/container, project network and reserved volume. Use `compose.yaml` with `deploy/compose.status.yaml`. RAM 256 MiB, memory+swap 256 MiB, CPU 0.25, PID 64, tmpfs 16 MiB, log rotation 5 MiB x2, restart=no. The internal network has no outbound internet. No neighbor networks, mounts, sockets or data. Bind only loopback 18085; add no firewall rules or external application port.
5. Install only `deploy/status-http.conf` as a new dedicated vhost. Run `nginx -t`; only if it succeeds reload the shared Nginx service. This is a shared-service change. Confirm public authoritative DNS before ACME.
6. Issue a separate certificate with existing Certbot/webroot flow: `certbot certonly --webroot -w /var/lib/letsencrypt -d telegram-bridge.mu56.ru --cert-name telegram-bridge.mu56.ru`. Reuse the existing approved ACME account; stop if account creation, new terms or unrelated modifications are required. Certificate issuance publishes the hostname through Certificate Transparency. Do not use Certbot's automatic nginx editing mode.
7. Replace only the newly added vhost with `deploy/status-https.conf`, run `nginx -t`, then reload shared Nginx. The existing renewal flow must be verified for this new certificate; no global renewal settings are changed silently.
8. Run a maximum 15-minute trial: TLS validation, official MCP initialization/discovery/status, negative Host/Origin, unknown tool/arguments, route and rate-limit checks. Observe new-container RAM/CPU and host available RAM/swap as well as existing service health. Stop early on any neighbor regression, host available RAM below 512 MiB or new-container RAM above 220 MiB. Swap occupancy alone does not measure active swapping; compare rates. No load or stress test. Use an explicitly approved transient auto-stop timer for only this Compose project, or keep an operator present and stop at the deadline; do not leave it running.
9. Creating/installing a personal plugin is a separate explicit action. No private data is introduced by this trial. End with the new project stopped and its HTTPS route disabled unless continued availability is separately approved.

## Rollback without data deletion

Disable only the new vhost symlink; run `nginx -t`, then reload Nginx. Stop only the new Compose project, without `down -v` or prune. Restore/remove only the exact newly created DNS A record based on the recorded prior state; allow for positive and negative DNS caches. Keep the new project files, image, reserved volume and certificate for review. Remove only the trial's own transient timer if one was approved. Do not revoke or delete certificates/ACME accounts or touch other certificate lineages as part of automatic rollback.

## Risks and validation limits

The shared Nginx reload, CPU, memory, disk, Docker daemon and kernel remain common with other projects. Resource controls and request limits reduce but cannot eliminate impact or public abuse. A named volume is not a disk quota. TLS/Certbot failures, name collisions, DNS caching and the maintenance window can interrupt the trial. HTTPS templates were prepared by inspection; real `nginx -t` and end-to-end TLS tests remain mandatory after authorization. Compose was parser-checked only. No server changes are authorized by the existence of these files.

Protocol evidence: the installed SDK default reported support up to 2025-11-25. The public-host HTTP test uses that version; this does not establish 2026-07-28 or MCP Events support.

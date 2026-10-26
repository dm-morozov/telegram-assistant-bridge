#!/usr/bin/env bash
set -euo pipefail
trap 'docker logs bridge-status-ci || true; docker logs bridge-nginx-ci || true; docker stop bridge-nginx-ci bridge-status-ci >/dev/null 2>&1 || true; docker rm bridge-nginx-ci bridge-status-ci >/dev/null 2>&1 || true; docker network rm bridge-status-ci >/dev/null 2>&1 || true' EXIT
mkdir -p image-artifact ci-tmp
docker version --format '{{.Server.Version}}' > image-artifact/docker-version.txt
docker network create --internal bridge-status-ci
docker run -d --name bridge-status-ci --network bridge-status-ci --user 1000:1000 --read-only --cap-drop ALL --security-opt no-new-privileges --cpus .25 --memory 256m --memory-swap 256m --pids-limit 64 --tmpfs /tmp:rw,noexec,nosuid,size=16m,uid=1000,gid=1000 telegram-assistant-bridge:status node src/main.mjs --container --public-status
ip=$(docker inspect --format '{{(index .NetworkSettings.Networks "bridge-status-ci").IPAddress}}' bridge-status-ci)
[[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
docker network inspect --format 'driver={{.Driver}} internal={{.Internal}} options={{json .Options}} ipam={{json .IPAM.Config}}' bridge-status-ci > image-artifact/network-details.txt
docker inspect --format 'network-count={{len .NetworkSettings.Networks}} published-ports={{json .NetworkSettings.Ports}} container-ip={{(index .NetworkSettings.Networks "bridge-status-ci").IPAddress}}' bridge-status-ci >> image-artifact/network-details.txt
ready=false
for attempt in $(seq 1 20); do
  if curl -s --noproxy '*' --connect-timeout 1 -o /dev/null --connect-to "telegram-bridge.mu56.ru:80:$ip:3000" http://telegram-bridge.mu56.ru/mcp; then ready=true; break; fi
  sleep 1
done
[[ "$ready" == true ]]
docker stats --no-stream --format '{{json .}}' bridge-status-ci > image-artifact/stats-idle.json
timeout 40s node scripts/smoke.mjs http://telegram-bridge.mu56.ru/mcp "$ip" 3000 > image-artifact/host-direct-smoke.txt &
smoke_pid=$!
for sample in 1 2 3; do
  docker stats --no-stream --format '{{json .}}' bridge-status-ci >> image-artifact/stats-during-calls.jsonl
done
wait "$smoke_pid"
# Emulate host Nginx without privileged mode, capabilities, socket or other-project mounts.
docker pull nginx:stable
nginx_base=$(docker image inspect --format '{{index .RepoDigests 0}}' nginx:stable)
printf '%s\n' "$nginx_base" > image-artifact/nginx-image.txt
cat > ci-tmp/nginx.conf <<'NGINX'
pid /tmp/nginx.pid;
error_log /dev/stderr warn;
events { worker_connections 128; }
http {
  access_log off;
  client_body_temp_path /tmp/client;
  proxy_temp_path /tmp/proxy;
  fastcgi_temp_path /tmp/fastcgi;
  uwsgi_temp_path /tmp/uwsgi;
  scgi_temp_path /tmp/scgi;
  server {
    listen 127.0.0.1:18085;
    server_name telegram-bridge.mu56.ru;
    if ($host != telegram-bridge.mu56.ru) { return 421; }
    location = /mcp {
      proxy_pass http://TARGET_IP:3000;
      proxy_set_header Host telegram-bridge.mu56.ru;
      proxy_set_header Origin $http_origin;
      proxy_http_version 1.1;
      proxy_set_header Connection "";
      proxy_buffering off;
      proxy_request_buffering off;
    }
    location / { return 404; }
  }
}
NGINX
sed -i "s/TARGET_IP/$ip/g" ci-tmp/nginx.conf
docker run --rm --network host --user 1000:1000 --read-only --cap-drop ALL --security-opt no-new-privileges --cpus .1 --memory 64m --memory-swap 64m --pids-limit 32 --tmpfs /tmp:rw,noexec,nosuid,size=16m --mount type=bind,src="$GITHUB_WORKSPACE/ci-tmp/nginx.conf",dst=/ci/nginx.conf,readonly --entrypoint nginx "$nginx_base" -t -c /ci/nginx.conf
docker run -d --name bridge-nginx-ci --network host --user 1000:1000 --read-only --cap-drop ALL --security-opt no-new-privileges --cpus .1 --memory 64m --memory-swap 64m --pids-limit 32 --tmpfs /tmp:rw,noexec,nosuid,size=16m --mount type=bind,src="$GITHUB_WORKSPACE/ci-tmp/nginx.conf",dst=/ci/nginx.conf,readonly --entrypoint nginx "$nginx_base" -c /ci/nginx.conf -g 'daemon off;'
for attempt in $(seq 1 20); do
  if curl -s -o /dev/null -H 'Host: telegram-bridge.mu56.ru' http://127.0.0.1:18085/mcp; then break; fi
  sleep 1
done
timeout 40s node scripts/smoke.mjs http://telegram-bridge.mu56.ru/mcp 127.0.0.1 18085 > image-artifact/nginx-loopback-smoke.txt
docker inspect --format '{{json .State}}' bridge-status-ci > image-artifact/container-state.json
docker inspect --format 'user={{.Config.User}} memory={{.HostConfig.Memory}} memoryswap={{.HostConfig.MemorySwap}} nanocpus={{.HostConfig.NanoCpus}} pids={{.HostConfig.PidsLimit}} readonly={{.HostConfig.ReadonlyRootfs}} capdrop={{json .HostConfig.CapDrop}} security={{json .HostConfig.SecurityOpt}}' bridge-status-ci > image-artifact/container-limits.txt
docker stop bridge-nginx-ci bridge-status-ci
docker save telegram-assistant-bridge:status | gzip > image-artifact/status-image.tar.gz
sha256sum image-artifact/status-image.tar.gz > image-artifact/archive-sha256.txt
cat image-artifact/source-sha.txt image-artifact/image-id.txt image-artifact/archive-sha256.txt image-artifact/host-direct-smoke.txt image-artifact/nginx-loopback-smoke.txt image-artifact/docker-version.txt image-artifact/network-details.txt image-artifact/stats-idle.json image-artifact/stats-during-calls.jsonl image-artifact/container-state.json image-artifact/container-limits.txt

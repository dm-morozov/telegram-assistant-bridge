import { isIP } from 'node:net';
export function renderSyntheticRoutes({container,expectedContainerId,expectedImageId,resource}) {
 const u=new URL(resource);
 if(u.protocol!=='https:'||u.username||u.password||u.search||u.hash||u.port||!/^\/[A-Za-z0-9/_-]+$/.test(u.pathname)||u.pathname.endsWith('/')||!/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])$/.test(u.hostname)||u.hostname.includes('..')||isIP(u.hostname)||u.hostname==='localhost')throw new Error('Invalid canonical resource');
 if(!/^[a-f0-9]{64}$/.test(expectedContainerId??'')||!/^sha256:[a-f0-9]{64}$/.test(expectedImageId??'')||container?.containerId!==expectedContainerId||container.imageId!==expectedImageId||container.project!=='telegram-assistant-bridge-synthetic'||container.service!=='bridge'||container.running!==true||container.networkCount!==1||container.publishedPortCount!==0||container.internal!==true||container.driver!=='bridge'||!['nat',undefined,''].includes(container.gatewayMode)||isIP(container.ip)!==4||!/^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/.test(container.ip))throw new Error('Verified own internal container identity required');
 const host=u.hostname,path=u.pathname,metadata='/.well-known/oauth-protected-resource'+path;
 const upstream=`        proxy_http_version 1.1;
        proxy_set_header Host ${host};
        proxy_set_header Connection "";
        proxy_set_header X-Forwarded-Host "";
        proxy_set_header X-Forwarded-Proto "";
        proxy_set_header X-Forwarded-For "";
        proxy_set_header Cookie "";
        proxy_set_header Origin $http_origin;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_connect_timeout 3s;
        proxy_send_timeout 10s;
        proxy_read_timeout 15s;`;
 const routes=destination=>[path,metadata].map(p=>`    location = ${p} {
        proxy_pass http://${destination};
${upstream}
    }`).join('\n');
 const controls=`    if ($host != ${host}) { return 421; }
    if ($http_origin != "") { return 403; }
    access_log off;
    error_log /dev/null crit;
    client_max_body_size 16k;
    client_body_timeout 5s;`;
 return {
 loopback:`server {
    listen 127.0.0.1:18085;
    server_name ${host};
${controls}
${routes(container.ip+':3000')}
    location / { return 404; }
}\n`,
 https:`limit_req_zone $binary_remote_addr zone=telegram_bridge_synthetic_rate:1m rate=2r/s;
limit_conn_zone $server_name zone=telegram_bridge_synthetic_connections:1m;
server {
    listen 443 ssl;
    server_name ${host};
    ssl_certificate /etc/letsencrypt/live/${host}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${host}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    if ($ssl_server_name != ${host}) { return 421; }
${controls}
    add_header X-Robots-Tag "noindex, nofollow" always;
    add_header X-Content-Type-Options nosniff always;
    limit_req_status 429;
    limit_conn_status 429;
    limit_req zone=telegram_bridge_synthetic_rate burst=10 nodelay;
    limit_conn telegram_bridge_synthetic_connections 16;
${routes('127.0.0.1:18085')}
    location / { return 404; }
}\n`
 };
}

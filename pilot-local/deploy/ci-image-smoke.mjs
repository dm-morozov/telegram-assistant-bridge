import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {mkdtemp,mkdir,writeFile,readFile,rename,chmod,readdir,unlink,rmdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';import {join,resolve} from 'node:path';
import {generateKeyPair,exportJWK,SignJWT} from 'jose';
import {Client,StreamableHTTPClientTransport} from '@modelcontextprotocol/client';
import {connectFetch} from '../../scripts/connect-fetch.mjs';
import {renderSyntheticRoutes} from './render-routes.mjs';
const root=process.cwd(),artifact=join(root,'synthetic-artifact'),compose=resolve('pilot-local/deploy/compose.synthetic.yaml');
const docker=(...args)=>execFileSync('docker',args,{encoding:'utf8',timeout:120000,maxBuffer:1048576,stdio:['ignore','pipe','pipe']}).trim();
const inspect=id=>JSON.parse(docker('inspect',id))[0];
const directory=await mkdtemp(join(tmpdir(),'bridge-synthetic-ci-'));await chmod(directory,0o755);
const jwksDirectory=join(directory,'jwks');await mkdir(jwksDirectory,{mode:0o755});const ownerFile=join(directory,'owner.local.json'),snapshotFile=join(jwksDirectory,'jwks.snapshot.json');
const oauth={issuer:'https://issuer.invalid/',audience:'https://resource.invalid/private-mcp',jwksUri:'https://issuer.invalid/.well-known/jwks.json',ownerSubject:'synthetic-owner'};
const imageId=(await readFile(join(artifact,'image-id.txt'),'utf8')).trim(),nginxImage=(await readFile(join(artifact,'nginx-base.txt'),'utf8')).trim();
assert.match(imageId,/^sha256:[a-f0-9]{64}$/);assert.match(nginxImage,/^nginx@sha256:[a-f0-9]{64}$/);
let containerId,nginxId;const stats=[];let clients=[];
const env={...process.env,BRIDGE_SYNTHETIC_IMAGE:imageId,BRIDGE_SYNTHETIC_OWNER_FILE:ownerFile,BRIDGE_SYNTHETIC_JWKS_DIR:jwksDirectory};
const composeRun=(...args)=>execFileSync('docker',['compose','-f',compose,...args],{env,encoding:'utf8',timeout:120000,maxBuffer:1048576,stdio:['ignore','pipe','pipe']}).trim();
const pause=ms=>new Promise(r=>setTimeout(r,ms));
const pair=await generateKeyPair('RS256'),second=await generateKeyPair('RS256');
async function snapshot(keyPair,kid,age=0){const key={...await exportJWK(keyPair.publicKey),kid,alg:'RS256',use:'sig'};const value={schemaVersion:1,issuer:oauth.issuer,uri:oauth.jwksUri,fetchedAt:Date.now()-age,jwks:{keys:[key]}};const temp=join(jwksDirectory,'next.json');await writeFile(temp,JSON.stringify(value),{mode:0o644});await rename(temp,snapshotFile);}
async function token(keyPair=pair,kid='first',patch={}){const now=Math.floor(Date.now()/1000);return new SignJWT({iss:oauth.issuer,aud:oauth.audience,sub:oauth.ownerSubject,iat:now,exp:now+300,scope:'messages:read drafts:create',...patch}).setProtectedHeader({alg:'RS256',typ:'at+jwt',kid}).sign(keyPair.privateKey);}
async function status(fetcher,headers={},method='GET',path=oauth.audience){return fetcher(path,{method,headers,...(method==='POST'?{body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/list'})}:{})});}
async function session(fetcher,bearer){const client=new Client({name:'synthetic-image-ci',version:'0.0.0'});clients.push(client);await client.connect(new StreamableHTTPClientTransport(new URL(oauth.audience),{fetch:fetcher,requestInit:{headers:{Authorization:'Bearer '+bearer}}}));return client;}
async function operations(fetcher){const client=await session(fetcher,await token());assert.equal((await client.listTools()).tools.length,3);const messages=JSON.parse((await client.callTool({name:'list_new_messages',arguments:{chatId:'synthetic-demo'}})).content[0].text);assert.equal(messages.length,1);const draft=JSON.parse((await client.callTool({name:'create_local_draft',arguments:{chatId:'synthetic-demo',messageId:'msg-demo',text:'Synthetic review only'}})).content[0].text);assert.equal(draft.sent,false);const read=await client.callTool({name:'get_local_draft',arguments:{chatId:'synthetic-demo',draftId:draft.id}});assert.notEqual(read.isError,true);await client.close();clients=clients.filter(x=>x!==client);}
async function removeFiles(path){for(const entry of await readdir(path,{withFileTypes:true})){const file=join(path,entry.name);if(entry.isDirectory())await removeFiles(file);else await unlink(file);}await rmdir(path);}
try{
 await writeFile(ownerFile,JSON.stringify({schemaVersion:1,oauth,ownerEmailVerified:true,verificationObservedAtUtc:new Date().toISOString(),connectionName:'Username-Password-Authentication'}),{mode:0o644});await snapshot(pair,'first');
 const parsed=JSON.parse(composeRun('config','--format','json'));const service=parsed.services.bridge;assert.equal(service.ports,undefined);assert.equal(service.read_only,true);assert.equal(service.user,'1000:1000');assert.equal(Object.keys(service.networks).length,1);assert.equal(parsed.networks.synthetic_private.internal,true);
 composeRun('up','-d','--no-build');containerId=composeRun('ps','-q','bridge');assert.match(containerId,/^[a-f0-9]{64}$/);
 const own=inspect(containerId),networks=Object.entries(own.NetworkSettings.Networks);assert.equal(networks.length,1);const [networkName,network]=networks[0];const actualNetwork=JSON.parse(docker('network','inspect',networkName))[0];
 const actual={containerId,imageId:own.Image,project:own.Config.Labels['com.docker.compose.project'],service:own.Config.Labels['com.docker.compose.service'],running:own.State.Running,networkCount:networks.length,publishedPortCount:Object.values(own.NetworkSettings.Ports??{}).filter(Boolean).length,internal:actualNetwork.Internal,driver:actualNetwork.Driver,gatewayMode:actualNetwork.Options?.['com.docker.network.bridge.gateway_mode_ipv4'],ip:network.IPAddress};
 const routes=renderSyntheticRoutes({container:actual,expectedContainerId:containerId,expectedImageId:imageId,resource:oauth.audience});
 assert.equal(own.Config.User,'1000:1000');assert.equal(own.HostConfig.ReadonlyRootfs,true);assert.equal(own.HostConfig.Memory,268435456);assert.equal(own.HostConfig.MemorySwap,268435456);assert.equal(own.HostConfig.NanoCpus,250000000);assert.equal(own.HostConfig.PidsLimit,64);assert.deepEqual(own.HostConfig.CapDrop,['ALL']);assert.ok(own.HostConfig.SecurityOpt.includes('no-new-privileges:true')||own.HostConfig.SecurityOpt.includes('no-new-privileges'));assert.equal(own.Mounts.some(x=>/docker.sock/.test(x.Source)),false);
 const direct=connectFetch(actual.ip,3000);let ready=false;for(let i=0;i<30;i++){try{if((await status(direct)).status===401){ready=true;break;}}catch{}await pause(300);}assert.ok(ready,'container readiness');
 const challenge=await status(direct);assert.match(challenge.headers.get('www-authenticate'),/resource_metadata/);const prm=await status(direct,{},'GET','https://resource.invalid/.well-known/oauth-protected-resource/private-mcp');assert.equal((await prm.json()).resource,oauth.audience);
 await operations(direct);
 for(const patch of [{sub:'other-owner'},{iss:'https://other.invalid/'},{aud:'https://other.invalid/private-mcp'},{exp:Math.floor(Date.now()/1000)-1},{scope:'drafts:create'}]){assert.equal((await status(direct,{Authorization:'Bearer '+await token(pair,'first',patch),'Content-Type':'application/json'},'POST')).status,401);}
 assert.equal((await status(direct,{Origin:'https://other.invalid'})).status,403);assert.equal((await status(connectFetch(actual.ip,3000),{},'GET','https://wrong.invalid/private-mcp')).status,403);
 const limited=await session(direct,await token(pair,'first',{scope:'messages:read'}));await assert.rejects(limited.callTool({name:'create_local_draft',arguments:{chatId:'synthetic-demo',messageId:'msg-demo',text:'synthetic'}}));await limited.close();clients=clients.filter(x=>x!==limited);
 const nginxConfig=join(directory,'nginx.conf');await writeFile(nginxConfig,`pid /tmp/nginx.pid;\nerror_log /dev/null crit;\nevents { worker_connections 128; }\nhttp { access_log off; client_body_temp_path /tmp/client; proxy_temp_path /tmp/proxy; fastcgi_temp_path /tmp/fastcgi; uwsgi_temp_path /tmp/uwsgi; scgi_temp_path /tmp/scgi;\n${routes.loopback}\n}\n`,{mode:0o644});
 const nginxArgs=['--network','host','--user','1000:1000','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--cpus','.1','--memory','64m','--memory-swap','64m','--pids-limit','32','--tmpfs','/tmp:rw,noexec,nosuid,size=16m','--mount',`type=bind,src=${nginxConfig},dst=/ci/nginx.conf,readonly`,'--entrypoint','nginx',nginxImage];docker('run','--rm',...nginxArgs,'-t','-c','/ci/nginx.conf');nginxId=docker('run','-d',...nginxArgs,'-c','/ci/nginx.conf','-g','daemon off;');
 const proxy=connectFetch('127.0.0.1',18085);for(let i=0;i<20;i++){try{if((await status(proxy)).status===401)break;}catch{}await pause(200);}await operations(proxy);assert.equal((await status(proxy,{Origin:'https://bad.invalid'})).status,403);assert.equal((await status(proxy,{},'GET','https://wrong.invalid/private-mcp')).status,421);
 // Directory mount observes atomic replacement; warm key caches do not bypass TTL or rotation.
 await snapshot(second,'second');assert.equal((await status(direct,{Authorization:'Bearer '+await token(),'Content-Type':'application/json'},'POST')).status,401);const rotated=await session(direct,await token(second,'second'));await rotated.listTools();await snapshot(second,'second',120001);await assert.rejects(rotated.listTools());await rotated.close();clients=clients.filter(x=>x!==rotated);await snapshot(pair,'first');
 for(let i=0;i<3;i++){const sample=JSON.parse(docker('stats','--no-stream','--format','{{json .}}',containerId));stats.push({cpu:sample.CPUPerc,memory:sample.MemUsage,pids:sample.PIDs});const used=sample.MemUsage.split('/')[0].trim();const memoryMiB=parseFloat(used)*(used.endsWith('GiB')?1024:used.endsWith('KiB')?1/1024:1);assert.ok(memoryMiB<220,'own memory threshold');await operations(direct);}
 const logs=docker('logs',containerId);assert.equal(logs.trim(),'Synthetic private MCP ready; maximum runtime 15 minutes');assert.equal(docker('logs',nginxId).trim(),'');
 await writeFile(join(artifact,'report.json'),JSON.stringify({result:'PASS',routes:['host-internal-IP','host-loopback-Nginx'],protocol:'official MCP client',negativeAuth:true,hostOrigin:true,publicMetadata:true,directorySnapshotRotation:true,warmCacheStaleDenied:true,limits:{cpu:0.25,memoryMiB:256,pids:64,readOnly:true,nonroot:true,noCapabilities:true},network:{internal:actual.internal,driver:actual.driver,gatewayMode:actual.gatewayMode??'nat-default',options:actualNetwork.Options,networkCount:1,publishedPorts:0},stats,notes:['HTTPS certificate and actual ChatGPT OAuth not exercised by CI','Host bridge services are not universally isolated']},null,2));
 console.log('PASS: constrained protected image, host internal IP, loopback Nginx, official MCP read/draft, negatives and snapshot rotation/staleness; no tokens logged');
}finally{
 for(const client of clients)await client.close().catch(()=>{});
 if(nginxId){try{docker('stop','--time','2',nginxId);}catch{}try{docker('rm',nginxId);}catch{}}
 try{composeRun('down','--timeout','3');}catch{}
 // Only this fresh CI project's reserved empty volume; no global prune or neighboring objects.
 try{docker('volume','rm','telegram-assistant-bridge-synthetic_synthetic_state');}catch{}
 await removeFiles(directory);
}
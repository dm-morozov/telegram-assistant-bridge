import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp,writeFile,readFile,readdir,unlink,rmdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer,request } from 'node:http';
import { once } from 'node:events';
import { generateKeyPair,exportJWK,SignJWT } from 'jose';
import { Client,StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { createResourceVerifier } from './verifier.mjs';
import { validateJwksSnapshot,readJwksSnapshot,refreshJwksSnapshot } from './jwks-snapshot.mjs';
import { createSnapshotIngressPilot } from './http-pilot.mjs';
import { createConfiguredIngressPilot } from './owner-config.mjs';
import { runContainer } from './container-main.mjs';
const oauth={issuer:'https://issuer.invalid/',audience:'https://resource.invalid/private-mcp',jwksUri:'https://issuer.invalid/.well-known/jwks.json',ownerSubject:'synthetic-owner'};
const publicKey=async(pair,kid)=>({...await exportJWK(pair.publicKey),kid,alg:'RS256',use:'sig'});
const documentFor=jwks=>({schemaVersion:1,issuer:oauth.issuer,uri:oauth.jwksUri,fetchedAt:Date.now(),jwks});
async function tokenFor(pair,kid,patch={}){const now=Math.floor(Date.now()/1000);return new SignJWT({iss:oauth.issuer,aud:oauth.audience,sub:oauth.ownerSubject,iat:now,exp:now+300,scope:'messages:read drafts:create',...patch}).setProtectedHeader({alg:'RS256',typ:'at+jwt',kid}).sign(pair.privateKey);}
async function cleanup(directory){for(const name of await readdir(directory))await unlink(join(directory,name));await rmdir(directory);}

test('snapshot resolver verifies real signatures and fails closed for malformed/stale/rotated keys without any network fallback',async t=>{
 const directory=await mkdtemp(join(tmpdir(),'bridge-jwks-test-')),file=join(directory,'jwks.snapshot.json');
 const first=await generateKeyPair('RS256',{extractable:false}),second=await generateKeyPair('RS256',{extractable:false});
 const a=await publicKey(first,'first'),b=await publicKey(second,'second');const valid=documentFor({keys:[a]});
 let network=0;t.mock.method(globalThis,'fetch',()=>{network++;throw new Error('Forbidden network fallback');});
 try{
  await writeFile(file,JSON.stringify(valid));const verifier=createResourceVerifier(oauth,{jwksSnapshotPath:file});
  await verifier.verifyAccessToken(await tokenFor(first,'first'));
  await assert.rejects(verifier.verifyAccessToken(await tokenFor(second,'second')));
  const negative=[{...valid,fetchedAt:Date.now()-120001},{...valid,fetchedAt:Date.now()+60000},{...valid,issuer:'https://other.invalid/'},{...valid,uri:'https://issuer.invalid/other'},{...valid,extra:true},{...valid,jwks:{keys:[]}},{...valid,jwks:{keys:[a,a]}},{...valid,jwks:{keys:[{...a,d:'synthetic-private-key-material'}]}},{...valid,jwks:{keys:[{...a,kty:'oct'}]}},{...valid,jwks:{keys:[{...a,alg:'HS256'}]}},{...valid,jwks:{keys:[{...a,n:'AQAB'}]}},{...valid,jwks:{keys:[{...a,key_ops:['sign']}]}},{...valid,jwks:{keys:[{...a,jku:'https://other.invalid/'}]}}];
  for(const value of negative){await writeFile(file,JSON.stringify(value));await assert.rejects(verifier.verifyAccessToken(await tokenFor(first,'first')),/^Error: Access denied$/);}
  await writeFile(file,'{malformed');await assert.rejects(verifier.verifyAccessToken(await tokenFor(first,'first')));
  await writeFile(file,'x'.repeat(65537));await assert.rejects(verifier.verifyAccessToken(await tokenFor(first,'first')));
  await unlink(file);await assert.rejects(verifier.verifyAccessToken(await tokenFor(first,'first')));
  await writeFile(file,JSON.stringify(documentFor({keys:[b]})));await verifier.verifyAccessToken(await tokenFor(second,'second'));await assert.rejects(verifier.verifyAccessToken(await tokenFor(first,'first')));
  await assert.rejects(verifier.verifyAccessToken(await tokenFor(second,'second',{sub:'other'})));
  assert.equal(network,0);assert.throws(()=>createResourceVerifier(oauth,{jwksSnapshotPath:'relative.json'}));assert.throws(()=>validateJwksSnapshot(valid,{...oauth,jwksUri:'https://issuer.invalid/other'}));
 }finally{t.mock.restoreAll();await cleanup(directory);}
});

test('snapshot refresh pins exact HTTPS URL, rejects redirects/oversize/private fields and preserves last good file on failure',async t=>{
 const directory=await mkdtemp(join(tmpdir(),'bridge-jwks-fetch-')),file=join(directory,'jwks.snapshot.json');
 const pair=await generateKeyPair('RS256',{extractable:false});const key=await publicKey(pair,'fixture');
 let mode='ok',requests=0,redirected=0;
 const fixture=createServer((req,res)=>{
  requests++;assert.equal(req.headers.authorization,undefined);assert.equal(req.headers.cookie,undefined);assert.equal(req.method,'GET');
  if(req.url==='/unexpected'){redirected++;res.writeHead(200).end('{}');return;}
  if(mode==='redirect'){res.writeHead(302,{Location:'/unexpected'}).end();return;}
  if(mode==='outage'){res.writeHead(503).end();return;}
  res.writeHead(200,{'content-type':mode==='wrong-type'?'text/plain':'application/json'});
  if(mode==='oversize'){res.end('x'.repeat(65537));return;}
  if(mode==='malformed'){res.end('{invalid');return;}
  if(mode==='private'){res.end(JSON.stringify({keys:[{...key,d:'not-real-private-material'}]}));return;}
  res.end(JSON.stringify({keys:[key]}));
 });fixture.listen(0,'127.0.0.1');await once(fixture,'listening');
 const nativeFetch=globalThis.fetch;
 t.mock.method(globalThis,'fetch',(url,options)=>{assert.equal(String(url),oauth.jwksUri);assert.equal(options.redirect,'error');assert.equal(options.credentials,'omit');assert.deepEqual(Object.keys(options.headers),['Accept']);return nativeFetch('http://127.0.0.1:'+fixture.address().port+'/jwks',options);});
 try{
  await refreshJwksSnapshot({...oauth,snapshotPath:file});const original=await readFile(file,'utf8');await readJwksSnapshot(file,oauth);
  for(const failure of ['redirect','outage','oversize','malformed','private','wrong-type']){mode=failure;await assert.rejects(refreshJwksSnapshot({...oauth,snapshotPath:file}),/^Error: JWKS snapshot refresh failed$/);assert.equal(await readFile(file,'utf8'),original);}
  assert.equal(redirected,0);assert.equal(requests,7);assert.deepEqual(await readdir(directory),['jwks.snapshot.json']);
  await assert.rejects(refreshJwksSnapshot({...oauth,jwksUri:'https://issuer.invalid/other',snapshotPath:file}));
 }finally{t.mock.restoreAll();fixture.closeAllConnections();await new Promise(resolve=>fixture.close(resolve));await cleanup(directory);}
});

test('canonical ingress works through official MCP client, requires snapshot and verified owner; defaults to loopback in tests',async t=>{
 const directory=await mkdtemp(join(tmpdir(),'bridge-ingress-')),file=join(directory,'jwks.snapshot.json'),configPath=join(directory,'owner.local.json');
 const pair=await generateKeyPair('RS256',{extractable:false});const key=await publicKey(pair,'ingress');
 const owner={schemaVersion:1,oauth,ownerEmailVerified:true,verificationObservedAtUtc:'2026-01-01T00:00:00Z',connectionName:'Username-Password-Authentication'};
 const outputs=[];for(const method of ['log','info','warn','error','debug'])t.mock.method(console,method,(...args)=>outputs.push(args.join(' ')));
 t.mock.method(globalThis,'fetch',()=>{throw new Error('Snapshot ingress must not use network fetch');});
 let runtime,client;
 try{
  await writeFile(configPath,JSON.stringify(owner));await assert.rejects(createConfiguredIngressPilot({ownerConfigPath:configPath,jwksSnapshotPath:file}));
  assert.throws(()=>createSnapshotIngressPilot({oauth}));assert.throws(()=>createSnapshotIngressPilot({oauth,jwksSnapshotPath:file,listenHost:'untrusted-host'}));
  await assert.rejects(runContainer([]));
  await writeFile(file,JSON.stringify(documentFor({keys:[key]})));const now=Date.now();
  runtime=await createConfiguredIngressPilot({ownerConfigPath:configPath,jwksSnapshotPath:file,chats:[{id:'synthetic-demo',activatedAt:now-1000,consentUntil:now+60000,participantsConsented:true}]});
  runtime.ingestSynthetic({source:'synthetic',type:'new',chatId:'synthetic-demo',id:'msg-demo',direction:'incoming',receivedAt:now-500,text:'synthetic ingress message'});
  const endpoint=await runtime.start();
  // Official transport's supplied fetch still uses real loopback HTTP. Global fetch stays forbidden for JWKS.
  const nativeHttpFetch=async(url,options={})=>{
   return new Promise((resolve,reject)=>{
    const q=request(url,{method:options.method??'GET',headers:{...Object.fromEntries(new Headers(options.headers??{})),Host:new URL(oauth.audience).host}},r=>{const chunks=[];r.on('data',x=>chunks.push(x));r.on('end',()=>resolve(new Response([204,304].includes(r.statusCode)?null:Buffer.concat(chunks),{status:r.statusCode,headers:r.headers})));});
    q.on('error',reject);q.end(options.body);
   });
  };
  client=new Client({name:'synthetic-ingress-client',version:'0.0.0'});
  const token=await tokenFor(pair,'ingress');
  await client.connect(new StreamableHTTPClientTransport(endpoint,{fetch:nativeHttpFetch,requestInit:{headers:{Authorization:'Bearer '+token}}}));
  const tools=await client.listTools();assert.equal(tools.tools.length,3);
  for(const tool of tools.tools){const scopes=tool._meta.securitySchemes[0].scopes;assert.ok(scopes.includes('messages:read'));if(tool.name!=='list_new_messages')assert.ok(scopes.includes('drafts:create'));}
  const messages=await client.callTool({name:'list_new_messages',arguments:{chatId:'synthetic-demo'}});assert.equal(JSON.parse(messages.content[0].text).length,1);
  const drafted=await client.callTool({name:'create_local_draft',arguments:{chatId:'synthetic-demo',messageId:'msg-demo',text:'synthetic review reply'}});assert.equal(JSON.parse(drafted.content[0].text).sent,false);
  const anonymous=await nativeHttpFetch(endpoint);assert.equal(anonymous.status,401);
  const metadata=await nativeHttpFetch(new URL(runtime.metadataPath,endpoint));assert.equal(metadata.status,200);assert.equal((await metadata.json()).resource,oauth.audience);
  const forbidden=await nativeHttpFetch(endpoint,{headers:{Origin:'https://untrusted.invalid'}});assert.equal(forbidden.status,403);
  const wrongHost=await new Promise((resolve,reject)=>{const q=request(endpoint,{headers:{Host:'wrong.invalid'}},r=>{r.resume();resolve(r.statusCode);});q.on('error',reject);q.end();});assert.equal(wrongHost,403);
  await writeFile(file,JSON.stringify({...documentFor({keys:[key]}),fetchedAt:Date.now()-120001}));await assert.rejects(client.listTools());
  assert.deepEqual(outputs,[]);
 }finally{await client?.close().catch(()=>{});await runtime?.close();t.mock.restoreAll();await cleanup(directory);}
});

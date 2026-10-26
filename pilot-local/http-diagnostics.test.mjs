import test from 'node:test';import assert from 'node:assert/strict';import {EventEmitter,once} from 'node:events';
import {createServer} from 'node:http';import {mkdtemp,writeFile,unlink,rmdir} from 'node:fs/promises';import {tmpdir} from 'node:os';import {join} from 'node:path';
import {generateKeyPair,exportJWK,SignJWT} from 'jose';import {Client,StreamableHTTPClientTransport,auth,extractWWWAuthenticateParams} from '@modelcontextprotocol/client';
import {createHttpDiagnostics} from './http-diagnostics.mjs';import {createSnapshotIngressPilot,createLocalProtectedPilot} from './http-pilot.mjs';import {connectFetch} from '../scripts/connect-fetch.mjs';
const oauth={issuer:'https://issuer.invalid/',audience:'https://resource.invalid/private-mcp',jwksUri:'https://issuer.invalid/.well-known/jwks.json',ownerSubject:'synthetic-owner'};
const resourcePath='/private-mcp',metadataPath='/.well-known/oauth-protected-resource/private-mcp';
test('diagnostics allowlist never reads headers/body/address, strips query and masks unknown paths/methods',()=>{
 const records=[];let clock=10;const begin=createHttpDiagnostics({resourcePath,metadataPath,sink:r=>records.push(r),now:()=>clock});
 const secrets=['credential-sentinel','owner@example.invalid','203.0.113.5','owner-subject-sentinel','code-sentinel','state-sentinel','message-sentinel'];
 for(const url of ['/private-mcp?access_token=credential-sentinel&code=code-sentinel&state=state-sentinel',metadataPath+'?email=owner@example.invalid','/owner@example.invalid/203.0.113.5/credential-sentinel','/%70rivate-mcp/owner-subject-sentinel']){
  const req={method:'POST',url};for(const field of ['headers','body','socket'])Object.defineProperty(req,field,{get(){throw new Error('Sensitive field must not be inspected');}});
  const res=new EventEmitter();res.statusCode=401;res.writableFinished=true;const mark=begin(req,res);mark('credential-sentinel');mark('missing_credentials');clock+=3;res.emit('finish');res.emit('close');
 }
 const response=new EventEmitter();response.statusCode=200;begin({method:'message-sentinel',url:'/code-sentinel'},response);response.emit('close');
 assert.equal(records.length,5);assert.deepEqual(records.map(r=>r.path),[resourcePath,metadataPath,'[other]','[other]','[other]']);assert.equal(records[4].method,'OTHER');assert.equal(records[4].status,0);
 for(const record of records){assert.deepEqual(Object.keys(record),['method','path','status','durationMs','authRejection']);assert.ok(Object.isFrozen(record));assert.ok(Number.isInteger(record.durationMs));}
 const output=JSON.stringify(records);for(const value of secrets)assert.ok(!output.includes(value));
 const bounded=[];const cap=createHttpDiagnostics({resourcePath,metadataPath,sink:r=>bounded.push(r)});for(let i=0;i<1005;i++){const r=new EventEmitter();r.statusCode=401;cap({method:'GET',url:resourcePath},r);r.emit('finish');}assert.equal(bounded.length,1000);
 const disabled=createHttpDiagnostics({resourcePath,metadataPath});assert.doesNotThrow(()=>disabled({get method(){throw new Error();}},{})('none'));
 const throwing=createHttpDiagnostics({resourcePath,metadataPath,sink:()=>{throw new Error('credential-sentinel');}});const r=new EventEmitter();r.statusCode=200;throwing({method:'GET',url:metadataPath},r);assert.doesNotThrow(()=>r.emit('finish'));
});
test('real HTTP diagnostics classify auth denial without logging synthetic JWTs, identities, cookies, messages or drafts',async()=>{
 const directory=await mkdtemp(join(tmpdir(),'bridge-diag-')),file=join(directory,'jwks.snapshot.json'),records=[],tokens=[];const pair=await generateKeyPair('RS256');
 const key={...await exportJWK(pair.publicKey),alg:'RS256',use:'sig',kid:'diagnostics'};await writeFile(file,JSON.stringify({schemaVersion:1,issuer:oauth.issuer,uri:oauth.jwksUri,fetchedAt:Date.now(),jwks:{keys:[key]}}));
 const now=Date.now();const runtime=createSnapshotIngressPilot({oauth,jwksSnapshotPath:file,diagnosticSink:r=>records.push(r),chats:[{id:'synthetic-demo',activatedAt:now-1000,consentUntil:now+60000,participantsConsented:true}]});const endpoint=await runtime.start();const fetcher=connectFetch('127.0.0.1',endpoint.port);let client;
 const signed=async patch=>{const iat=Math.floor(Date.now()/1000);const value=await new SignJWT({iss:oauth.issuer,aud:oauth.audience,sub:oauth.ownerSubject,iat,exp:iat+300,scope:'messages:read drafts:create',...patch}).setProtectedHeader({alg:'RS256',typ:'at+jwt',kid:'diagnostics'}).sign(pair.privateKey);tokens.push(value);return value;};
 const post=async(token,body)=>fetcher(oauth.audience,{method:'POST',headers:{'Content-Type':'application/json',Authorization:token,'Cookie':'cookie-sentinel'},body:typeof body==='string'?body:JSON.stringify(body)});
 try{
  assert.equal((await fetcher(oauth.audience)).status,401);
  assert.equal((await fetcher(oauth.audience,{headers:{Authorization:'Basic credential-sentinel'}})).status,401);
  assert.equal((await post('Bearer '+await signed({sub:'owner-subject-sentinel'}),{jsonrpc:'2.0',id:1,method:'initialize'})).status,401);
  const read=await signed({scope:'messages:read'});assert.equal((await post('Bearer '+read,{jsonrpc:'2.0',id:1,method:'tools/call',params:{name:'create_local_draft',arguments:{text:'draft-sentinel'}}})).status,403);
  const full=await signed();assert.equal((await post('Bearer '+full,'{message-sentinel')).status,400);
  runtime.ingestSynthetic({source:'synthetic',chatId:'synthetic-demo',id:'msg-diag',type:'new',direction:'incoming',receivedAt:now-100,text:'message-sentinel'});
  client=new Client({name:'diagnostic-official-client',version:'0.0.0'});await client.connect(new StreamableHTTPClientTransport(new URL(oauth.audience),{fetch:fetcher,requestInit:{headers:{Authorization:'Bearer '+full}}}));
  await client.listTools();await client.callTool({name:'list_new_messages',arguments:{chatId:'synthetic-demo'}});await client.callTool({name:'create_local_draft',arguments:{chatId:'synthetic-demo',messageId:'msg-diag',text:'draft-sentinel'}});
  assert.equal((await fetcher(oauth.audience+'?code=code-sentinel&state=state-sentinel&access_token='+full)).status,404);
  await fetcher('https://resource.invalid/owner@example.invalid/203.0.113.5');
  const prm=await fetcher('https://resource.invalid'+metadataPath);assert.equal(prm.status,200);
  runtime.revokeOwner();assert.equal((await post('Bearer '+full,{jsonrpc:'2.0',id:1,method:'tools/list'})).status,401);
  await new Promise(r=>setImmediate(r));
  for(const classification of ['missing_credentials','malformed_credentials','token_rejected','insufficient_scope','none','owner_revoked'])assert.ok(records.some(r=>r.authRejection===classification),classification);
  assert.ok(records.some(r=>r.path==='[other]'&&r.status===404));assert.ok(records.some(r=>r.path===metadataPath&&r.status===200));
  const output=JSON.stringify(records);for(const value of [...tokens,oauth.ownerSubject,oauth.issuer,'owner-subject-sentinel','owner@example.invalid','203.0.113.5','cookie-sentinel','message-sentinel','draft-sentinel','code-sentinel','state-sentinel','credential-sentinel'])assert.ok(!output.includes(value));
 }finally{await client?.close().catch(()=>{});await runtime.close();await unlink(file);await rmdir(directory);}
});
test('official SDK pre-authorize discovery reaches S256 public-client redirect while initialize/list remain protected',async()=>{
 const runtime=createLocalProtectedPilot({oauth});const endpoint=await runtime.start();const nativeFetch=globalThis.fetch;let redirect,verifier;const requests=[];
 // Metadata-only fixture: deliberately no authorization/login/token server; no credentials are issued.
 const metadata={issuer:oauth.issuer,authorization_endpoint:oauth.issuer+'authorize',token_endpoint:oauth.issuer+'oauth/token',jwks_uri:oauth.jwksUri,authorization_response_iss_parameter_supported:true,subject_types_supported:['public'],id_token_signing_alg_values_supported:['RS256'],response_types_supported:['code'],grant_types_supported:['authorization_code'],token_endpoint_auth_methods_supported:['none','client_secret_post'],code_challenge_methods_supported:['S256','plain'],scopes_supported:['openid','profile','offline_access','email']};
 const fixture=createServer((req,res)=>{assert.equal(req.headers.authorization,undefined);requests.push(req.url);res.writeHead(req.url==='/.well-known/openid-configuration'?200:404,{'Content-Type':'application/json'}).end(JSON.stringify(req.url==='/.well-known/openid-configuration'?metadata:{}));});fixture.listen(0,'127.0.0.1');await once(fixture,'listening');
 const fetchFn=async(input,init)=>{const url=new URL(input instanceof Request?input.url:input);if(url.origin==='https://resource.invalid')return nativeFetch('http://127.0.0.1:'+endpoint.port+url.pathname+url.search,init);if(url.origin==='https://issuer.invalid')return nativeFetch('http://127.0.0.1:'+fixture.address().port+url.pathname,init);throw new Error('Unexpected discovery destination');};
 const callback='https://chatgpt.com/connector/oauth/synthetic-callback';const provider={redirectUrl:callback,clientMetadata:{redirect_uris:[callback],grant_types:['authorization_code'],response_types:['code'],token_endpoint_auth_method:'none'},clientInformation:()=>({client_id:'synthetic-public-client',token_endpoint_auth_method:'none',issuer:oauth.issuer}),tokens:()=>undefined,saveTokens:()=>{throw new Error('No token exchange permitted');},saveCodeVerifier:value=>{verifier=value;},codeVerifier:()=>verifier,redirectToAuthorization:url=>{redirect=url;}};
 try{
  for(const method of ['initialize','tools/list']){const response=await nativeFetch(endpoint,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method})});assert.equal(response.status,401);const challenge=extractWWWAuthenticateParams(response);assert.equal(challenge.resourceMetadataUrl.href,'https://resource.invalid'+metadataPath);assert.equal(challenge.scope,'messages:read drafts:create');}
  const outcome=await auth(provider,{serverUrl:oauth.audience,scope:'messages:read drafts:create',resourceMetadataUrl:new URL('https://resource.invalid'+metadataPath),fetchFn});assert.equal(outcome,'REDIRECT');assert.equal(redirect.origin,'https://issuer.invalid');assert.equal(redirect.pathname,'/authorize');assert.equal(redirect.searchParams.get('resource'),oauth.audience);assert.equal(redirect.searchParams.get('redirect_uri'),callback);assert.equal(redirect.searchParams.get('client_id'),'synthetic-public-client');assert.equal(redirect.searchParams.get('code_challenge_method'),'S256');assert.ok(verifier.length>=43);assert.equal(redirect.searchParams.get('client_secret'),null);assert.equal(redirect.searchParams.get('scope'),'messages:read drafts:create');assert.ok(requests.includes('/.well-known/openid-configuration'));assert.ok(!requests.includes('/oauth/token'));
 }finally{await runtime.close();fixture.closeAllConnections();await new Promise(r=>fixture.close(r));redirect=undefined;verifier=undefined;}
});
import test from 'node:test';import assert from 'node:assert/strict';
import {mkdtemp,writeFile,unlink,rmdir} from 'node:fs/promises';import {tmpdir} from 'node:os';import {join} from 'node:path';
import {generateKeyPair,exportJWK,SignJWT} from 'jose';import {Server} from '@modelcontextprotocol/server';
import {Client,StreamableHTTPClientTransport,extractWWWAuthenticateParams} from '@modelcontextprotocol/client';
import {createSnapshotIngressPilot} from './http-pilot.mjs';import {connectFetch} from '../scripts/connect-fetch.mjs';
const oauth={issuer:'https://issuer.invalid/',audience:'https://resource.invalid/private-mcp',jwksUri:'https://issuer.invalid/.well-known/jwks.json',ownerSubject:'synthetic-owner'};
const policies={list_new_messages:['messages:read'],create_local_draft:['messages:read','drafts:create'],get_local_draft:['messages:read','drafts:create']};
async function setup(ownerSubject=oauth.ownerSubject){
 const directory=await mkdtemp(join(tmpdir(),'bridge-oauth-contract-')),file=join(directory,'jwks.snapshot.json'),records=[];const pair=await generateKeyPair('RS256');
 const key={...await exportJWK(pair.publicKey),kid:'http-contract',alg:'RS256',use:'sig'};await writeFile(file,JSON.stringify({schemaVersion:1,issuer:oauth.issuer,uri:oauth.jwksUri,fetchedAt:Date.now(),jwks:{keys:[key]}}));
 const now=Date.now();const runtime=createSnapshotIngressPilot({oauth:{...oauth,ownerSubject},jwksSnapshotPath:file,diagnosticSink:r=>records.push(r),chats:[{id:'synthetic-contract',activatedAt:now-1000,consentUntil:now+60000,participantsConsented:true}]});const endpoint=await runtime.start();const routed=connectFetch('127.0.0.1',endpoint.port);const wire=[];
 const fetcher=async(...args)=>{const response=await routed(...args);if(response.headers.get('content-type')?.includes('application/json'))wire.push({status:response.status,body:await response.clone().json()});return response;};
 runtime.ingestSynthetic({source:'synthetic',chatId:'synthetic-contract',id:'msg-contract',type:'new',direction:'incoming',receivedAt:now-100,text:'synthetic message never included in descriptors'});
 const signed=async patch=>{const iat=Math.floor(Date.now()/1000);return new SignJWT({iss:oauth.issuer,aud:oauth.audience,sub:ownerSubject,iat,exp:iat+300,scope:'messages:read drafts:create',...patch}).setProtectedHeader({alg:'RS256',typ:'at+jwt',kid:'http-contract'}).sign(pair.privateKey);};
 const clients=[];const clientFor=async value=>{const client=new Client({name:'oauth-only-http-contract',version:'0.0.0'});clients.push(client);await client.connect(new StreamableHTTPClientTransport(new URL(oauth.audience),{fetch:fetcher,requestInit:{headers:{Authorization:'Bearer '+value}}}));return client;};
 const post=(body,token)=>fetcher(oauth.audience,{method:'POST',headers:{'Content-Type':'application/json',Accept:'application/json, text/event-stream',...(token?{Authorization:'Bearer '+token}:{})},body:JSON.stringify(body)});
 return{runtime,records,wire,signed,clientFor,post,async close(){for(const client of clients)await client.close().catch(()=>{});await runtime.close();await unlink(file);await rmdir(directory);}};
}
const call=(name,args={})=>({jsonrpc:'2.0',id:4,method:'tools/call',params:{name,arguments:args}});
test('OAuth-only real HTTP emits complete descriptor wire only after valid owner token and denies invalid/expired/missing scopes',async()=>{
 const f=await setup();
 try{
  const full=await f.signed();const client=await f.clientFor(full);const parsed=await client.listTools();assert.equal(parsed.tools.length,3);
  const listResponse=await f.post({jsonrpc:'2.0',id:3,method:'tools/list',params:{}},full);assert.equal(listResponse.status,200);const raw=(await listResponse.json()).result.tools;assert.deepEqual(raw.map(x=>x.name),Object.keys(policies));
  for(const tool of raw){assert.deepEqual(tool.securitySchemes,[{type:'oauth2',scopes:policies[tool.name]}]);assert.deepEqual(tool._meta.securitySchemes,tool.securitySchemes);assert.equal(tool.inputSchema.additionalProperties,false);assert.ok(!tool.securitySchemes.some(x=>x.type==='noauth'));}
  assert.equal(raw[0].inputSchema.properties.limit.maximum,20);assert.equal(raw[1].inputSchema.properties.text.maxLength,2000);assert.match(raw[0].inputSchema.properties.chatId.pattern,/synthetic/);
  const descriptors=JSON.stringify(raw);for(const secret of [oauth.ownerSubject,full,'msg-contract','synthetic message never included in descriptors'])assert.ok(!descriptors.includes(secret));
  const initial=f.runtime.diagnostics();assert.deepEqual(initial,{messages:1,drafts:0});
  for(const body of [{jsonrpc:'2.0',id:1,method:'initialize',params:{}},{jsonrpc:'2.0',id:2,method:'tools/list'},...Object.keys(policies).map(name=>call(name))]){const response=await f.post(body);assert.equal(response.status,401);const rejected=await response.json();assert.equal(rejected.tools,undefined);assert.equal(rejected.result,undefined);}
  const badTokens=['synthetic.invalid.jwt',await f.signed({sub:'other-owner'}),await f.signed({iss:'https://other.invalid/'}),await f.signed({aud:'https://other.invalid/private-mcp'}),await f.signed({iat:Math.floor(Date.now()/1000)-301,exp:Math.floor(Date.now()/1000)-1})];
  for(const token of badTokens){for(const body of [{jsonrpc:'2.0',id:5,method:'tools/list'},call('create_local_draft',{chatId:'synthetic-contract',messageId:'msg-contract',text:'must not persist'})]){const response=await f.post(body,token);assert.equal(response.status,401);assert.match(response.headers.get('WWW-Authenticate'),/invalid_token/);}}
  const read=await f.signed({scope:'messages:read'});for(const name of ['create_local_draft','get_local_draft']){const response=await f.post(call(name,{chatId:'synthetic-contract',messageId:'msg-contract',text:'must not persist'}),read);assert.equal(response.status,403);assert.equal(extractWWWAuthenticateParams(response).error,'insufficient_scope');}
  assert.deepEqual(f.runtime.diagnostics(),initial);
  const messages=await client.callTool({name:'list_new_messages',arguments:{chatId:'synthetic-contract'}});assert.equal(JSON.parse(messages.content[0].text).length,1);
  const draft=await client.callTool({name:'create_local_draft',arguments:{chatId:'synthetic-contract',messageId:'msg-contract',text:'review only'}});assert.equal(JSON.parse(draft.content[0].text).sent,false);
  const unavailable=await client.callTool({name:'list_new_messages',arguments:{chatId:'synthetic-unselected'}});assert.equal(unavailable.isError,true);assert.equal(unavailable._meta?.['mcp/www_authenticate'],undefined,'domain failures must not start an OAuth loop');
 }finally{await f.close();}
});
test('real HTTP runtime rechecks owner at dispatch and returns SDK tool-result challenge with zero content/state on revocation race',async t=>{
 const f=await setup();const original=Server.prototype.setRequestHandler;let intercepted=0;
 try{
  const full=await f.signed();const client=await f.clientFor(full);await client.listTools();
  // Test-only use of the documented handler API simulates revocation AFTER HTTP auth,
  // exactly at dispatch. No production hook/verifier bypass/anonymous path is introduced.
  t.mock.method(Server.prototype,'setRequestHandler',function(method,...args){
   if(method==='tools/call'&&args.length===1&&typeof args[0]==='function'){
    const handler=args[0];return original.call(this,method,async(...request)=>{intercepted++;f.runtime.revokeOwner();return handler(...request);});
   }
   return original.call(this,method,...args);
  });
  const result=await client.callTool({name:'create_local_draft',arguments:{chatId:'synthetic-contract',messageId:'msg-contract',text:'never create after revoke'}});assert.equal(intercepted,1);assert.equal(result.isError,true);assert.deepEqual(result.content,[{type:'text',text:'Authentication required for this protected tool.'}]);
  const challenge=result._meta['mcp/www_authenticate'][0];const parsed=extractWWWAuthenticateParams(new Response(null,{status:401,headers:{'WWW-Authenticate':challenge}}));assert.equal(parsed.resourceMetadataUrl.href,'https://resource.invalid/.well-known/oauth-protected-resource/private-mcp');assert.equal(parsed.error,'invalid_token');assert.ok(parsed.errorDescription);assert.equal(parsed.scope,'messages:read drafts:create');
  assert.ok(f.wire.some(x=>x.status===200&&x.body.result?._meta?.['mcp/www_authenticate']),'challenge must survive actual localhost HTTP wire');
  assert.deepEqual(f.runtime.diagnostics(),{messages:0,drafts:0});assert.equal((await f.post({jsonrpc:'2.0',id:8,method:'tools/list'},full)).status,401);assert.ok(f.records.some(r=>r.authRejection==='owner_revoked'));
  const output=JSON.stringify(f.records);for(const secret of [full,oauth.ownerSubject,'never create after revoke','msg-contract'])assert.ok(!output.includes(secret));
 }finally{t.mock.restoreAll();await f.close();}
});
test('same email is not authority: pinned DB owner succeeds and Google subject is denied without state or identity logging',async()=>{
 const f=await setup('auth0|synthetic-db-owner');const email='same-owner@example.invalid';
 try{
  const db=await f.signed({email,email_verified:true});const google=await f.signed({sub:'google-oauth2|synthetic-other-owner',email,email_verified:true});const list={jsonrpc:'2.0',id:10,method:'tools/list'};
  const before=f.runtime.diagnostics();const denied=await f.post(list,google);assert.equal(denied.status,401);assert.equal((await denied.json()).result,undefined);assert.deepEqual(f.runtime.diagnostics(),before);
  const allowed=await f.post(list,db);assert.equal(allowed.status,200);assert.equal((await allowed.json()).result.tools.length,3);
  assert.ok(f.records.some(r=>r.status===401&&r.authRejection==='token_rejected'));
  const diagnostics=JSON.stringify(f.records);for(const value of [db,google,email,'auth0|synthetic-db-owner','google-oauth2|synthetic-other-owner'])assert.ok(!diagnostics.includes(value));
 }finally{await f.close();}
});
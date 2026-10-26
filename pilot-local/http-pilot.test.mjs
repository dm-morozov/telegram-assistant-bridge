import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer, request } from 'node:http';
import { setTimeout as delay } from 'node:timers/promises';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { Client, StreamableHTTPClientTransport, discoverOAuthProtectedResourceMetadata, discoverAuthorizationServerMetadata } from '@modelcontextprotocol/client';
import { createLocalProtectedPilot } from './http-pilot.mjs';
import { parseSyntheticBusinessUpdate } from './telegram-fixture-parser.mjs';
const oauth={issuer:'https://issuer.invalid/',audience:'https://resource.invalid/private-mcp',jwksUri:'https://issuer.invalid/jwks',ownerSubject:'synthetic-owner'};
const result=value=>JSON.parse(value.content[0].text);

test('startup requires explicit trusted configuration before listener exists',()=>{
  for(const config of [undefined,{}, {...oauth,issuer:undefined},{...oauth,audience:undefined},{...oauth,jwksUri:undefined},{...oauth,ownerSubject:''}]) assert.throws(()=>createLocalProtectedPilot({oauth:config}));
});

test('protected localhost HTTP MCP with real signed tokens, official client, discovery and synthetic updates',async t=>{
 const pair=await generateKeyPair('RS256',{extractable:false});
 const jwk={...await exportJWK(pair.publicKey),kid:'fixture',alg:'RS256',use:'sig'};
 const asMetadata={issuer:oauth.issuer,authorization_endpoint:oauth.issuer+'authorize',token_endpoint:oauth.issuer+'token',jwks_uri:oauth.jwksUri,response_types_supported:['code'],grant_types_supported:['authorization_code'],code_challenge_methods_supported:['S256'],token_endpoint_auth_methods_supported:['none']};
 // Fixture serves public metadata/JWKS only. No login, authorization code or token issuance endpoint.
 const fixture=createServer((req,res)=>{assert.equal(req.headers.authorization,undefined); const body=req.url==='/jwks'?{keys:[jwk]}:req.url==='/.well-known/oauth-authorization-server'?asMetadata:undefined; res.writeHead(body?200:404,{'content-type':'application/json'}).end(JSON.stringify(body??{}));});
 fixture.listen(0,'127.0.0.1'); await once(fixture,'listening');
 const nativeFetch=globalThis.fetch;
 t.mock.method(globalThis,'fetch',async(url,options)=>{
   const value=String(url);
   if(value.startsWith(oauth.issuer)) {const u=new URL(value);return nativeFetch('http://127.0.0.1:'+fixture.address().port+u.pathname,options);}
   return nativeFetch(url,options);
 });
 let now=Date.now(); const initial=now;
 const chats=[{id:'synthetic-a',telegramChatId:101,activatedAt:now-2000,consentUntil:now+7200000,participantsConsented:true},{id:'synthetic-b',telegramChatId:102,activatedAt:now-2000,consentUntil:now+60000,participantsConsented:true}];
 const runtime=createLocalProtectedPilot({oauth,chats,clock:()=>now,sweepMs:10});
 const endpoint=await runtime.start(); const clients=[];
 const logs=[]; for(const method of ['log','info','warn','error','debug']) t.mock.method(console,method,(...args)=>logs.push(args.join(' ')));
 const token=async(claims={})=>{const at=Math.floor(Date.now()/1000); return new SignJWT({iss:oauth.issuer,aud:oauth.audience,sub:oauth.ownerSubject,iat:at,exp:at+300,scope:'messages:read drafts:create',...claims}).setProtectedHeader({alg:'RS256',typ:'at+jwt',kid:'fixture'}).sign(pair.privateKey);};
 const fullToken=await token();
 const clientFor=async value=>{const client=new Client({name:'synthetic-local-client',version:'0.0.0'}); clients.push(client); await client.connect(new StreamableHTTPClientTransport(endpoint,{requestInit:{headers:{Authorization:'Bearer '+value}}}));return client;};
 const post=async(body,access=fullToken,headers={})=>nativeFetch(endpoint,{method:'POST',headers:{Authorization:'Bearer '+access,'Content-Type':'application/json',Accept:'application/json, text/event-stream',...headers},body:typeof body==='string'?body:JSON.stringify(body)});
 const call=(name,args={})=>({jsonrpc:'2.0',id:1,method:'tools/call',params:{name,arguments:args}});
 const officialMessage={business_connection_id:'synthetic-connection',message_id:1,date:Math.floor(initial/1000),chat:{id:101,type:'private'},from:{id:101,is_bot:false},text:'synthetic-private-text-do-not-log'};
 const parse=(kind,value)=>parseSyntheticBusinessUpdate({synthetic:true,update:{update_id:1,[kind]:value}},{connectionId:'synthetic-connection',ownerUserId:999,chats,now});
 const ingest=events=>events.forEach(event=>event.type==='revoke'?runtime.revokeChat(event.chatId):runtime.ingestSynthetic(event));
 try {
  await t.test('401 advertises PRM and official client discovers fixed resource and issuer metadata',async()=>{
   const denied=await nativeFetch(endpoint); assert.equal(denied.status,401); assert.match(denied.headers.get('www-authenticate'),/resource_metadata="https:\/\/resource.invalid\/\.well-known\/oauth-protected-resource\/private-mcp"/);
   const prm=await discoverOAuthProtectedResourceMetadata(oauth.audience,{resourceMetadataUrl:new URL(runtime.metadataPath,endpoint)},nativeFetch);
   assert.equal(prm.resource,oauth.audience);assert.deepEqual(prm.authorization_servers,[oauth.issuer]);
   const as=await discoverAuthorizationServerMetadata(oauth.issuer,undefined,globalThis.fetch); assert.equal(as.issuer,oauth.issuer); assert.deepEqual(as.code_challenge_methods_supported,['S256']);
  });
  const client=await clientFor(fullToken);
  await t.test('official MCP initializes and exposes only read/local-draft tools',async()=>{
   assert.deepEqual((await client.listTools()).tools.map(x=>x.name).sort(),['create_local_draft','get_local_draft','list_new_messages']);
   ingest(parse('business_message',officialMessage));
   const list=result(await client.callTool({name:'list_new_messages',arguments:{chatId:'synthetic-a'}})); assert.equal(list[0].trust,'untrusted-chat-content');assert.equal(list[0].text,officialMessage.text);
   const draft=result(await client.callTool({name:'create_local_draft',arguments:{chatId:'synthetic-a',messageId:'msg-1',text:'synthetic-draft-do-not-log'}}));assert.equal(draft.sent,false);assert.equal(draft.status,'local-review-only');
   assert.equal(result(await client.callTool({name:'get_local_draft',arguments:{chatId:'synthetic-a',draftId:draft.id}})).id,draft.id);
   assert.equal((await client.callTool({name:'get_local_draft',arguments:{chatId:'synthetic-b',draftId:draft.id}})).isError,true);
  });
  await t.test('scope/owner/audience/expiry/tamper/anonymous bypasses fail; no send/commands',async()=>{
   for(const claims of [{sub:'other'},{aud:'https://other.invalid/'},{exp:Math.floor(Date.now()/1000)-1},{scope:'drafts:create'}]) assert.equal((await post(call('list_new_messages',{chatId:'synthetic-a'}),await token(claims))).status,401);
   assert.equal((await post(call('list_new_messages',{chatId:'synthetic-a'}),'synthetic-fixture')).status,401);
   const readToken=await token({scope:'messages:read'}); const reader=await clientFor(readToken);
   assert.deepEqual(result(await reader.callTool({name:'list_new_messages',arguments:{chatId:'synthetic-b'}})),[]);
   for(const name of ['create_local_draft','get_local_draft']) {const denied=await post(call(name),readToken);assert.equal(denied.status,403);assert.match(denied.headers.get('www-authenticate'),/insufficient_scope/);}
   for(const name of ['send_message','execute_command','constructor','__proto__']) {const r=await post(call(name));assert.equal(r.status,200); assert.ok((await r.json()).error);}
   assert.equal((await client.callTool({name:'list_new_messages',arguments:{chatId:'synthetic-unknown'}})).isError,true);
  });
  await t.test('Host/Origin/query-token/body/JSON guards fail closed without echo',async()=>{
   assert.equal((await post(call('list_new_messages'),fullToken,{Origin:'https://attacker.invalid'})).status,403);
   assert.equal((await post(call('list_new_messages'),fullToken,{'X-Forwarded-Host':'attacker.invalid'})).status,403);
   const deniedHost=await new Promise((resolve,reject)=>{const q=request(endpoint,{headers:{Host:'attacker.invalid'}},r=>{r.resume();resolve(r.statusCode);});q.on('error',reject);q.end();});assert.equal(deniedHost,403);
   assert.equal((await nativeFetch(new URL(endpoint.href+'?access_token='+fullToken))).status,404);
   const malformed=await post('{synthetic-sensitive-malformed');assert.equal(malformed.status,400);assert.ok(!(await malformed.text()).includes('sensitive'));
   assert.equal((await post('x'.repeat(17000))).status,413);assert.equal((await post([])).status,400);
   const unauthorized=await nativeFetch(endpoint,{headers:{Authorization:'Basic synthetic-secret'}});assert.equal(unauthorized.status,401);assert.ok(!(await unauthorized.text()).includes('synthetic-secret'));
  });
  await t.test('official edit and deletion fixtures invalidate dependent drafts',async()=>{
   const draft=result(await client.callTool({name:'create_local_draft',arguments:{chatId:'synthetic-a',messageId:'msg-1',text:'synthetic-draft-do-not-log'}}));
   ingest(parse('edited_business_message',{...officialMessage,text:'synthetic-edited'}));
   assert.equal((await client.callTool({name:'get_local_draft',arguments:{chatId:'synthetic-a',draftId:draft.id}})).isError,true);
   assert.equal(result(await client.callTool({name:'list_new_messages',arguments:{chatId:'synthetic-a'}}))[0].text,'synthetic-edited');
   ingest(parse('deleted_business_messages',{business_connection_id:'synthetic-connection',chat:{id:101,type:'private'},message_ids:[1]}));
   assert.deepEqual(result(await client.callTool({name:'list_new_messages',arguments:{chatId:'synthetic-a'}})),[]);
  });
  await t.test('background consent expiry purges without reads and denies further chat access',async()=>{
   ingest(parse('business_message',{...officialMessage,chat:{id:102,type:'private'},from:{id:102,is_bot:false}}));
   await client.callTool({name:'create_local_draft',arguments:{chatId:'synthetic-b',messageId:'msg-1',text:'temporary-consent'}});
   assert.deepEqual(runtime.diagnostics(),{messages:1,drafts:1});now=initial+60001;
   await delay(40);assert.deepEqual(runtime.diagnostics(),{messages:0,drafts:0});
   assert.equal((await client.callTool({name:'list_new_messages',arguments:{chatId:'synthetic-b'}})).isError,true);now=initial;
  });
  await t.test('background TTL purges source and draft without a read request',async()=>{
   ingest(parse('business_message',officialMessage));await client.callTool({name:'create_local_draft',arguments:{chatId:'synthetic-a',messageId:'msg-1',text:'temporary'}});
   assert.deepEqual(runtime.diagnostics(),{messages:1,drafts:1});now=initial+3600001;
   await delay(40);assert.deepEqual(runtime.diagnostics(),{messages:0,drafts:0});now=initial;
  });
  await t.test('connection/consent revocation purges immediately; owner revocation invalidates existing client',async()=>{
   ingest(parse('business_message',officialMessage));ingest(parse('business_connection',{id:'synthetic-connection',user:{id:999},is_enabled:false}));
   assert.deepEqual(runtime.diagnostics(),{messages:0,drafts:0});
   assert.equal((await client.callTool({name:'list_new_messages',arguments:{chatId:'synthetic-a'}})).isError,true);
   runtime.revokeOwner();assert.equal((await post(call('list_new_messages'))).status,401);assert.equal(runtime.ingestSynthetic({source:'synthetic'}),false);
  });
  assert.deepEqual(logs,[],'runtime must not log token/message/draft content');
 } finally {for(const c of clients) await c.close().catch(()=>{});await runtime.close();fixture.closeAllConnections();await new Promise(resolve=>fixture.close(resolve));t.mock.restoreAll(); assert.deepEqual(runtime.diagnostics(),{messages:0,drafts:0}); await assert.rejects(nativeFetch(endpoint));}
});

test('pure parser excludes non-synthetic, history, outgoing, media, unknown chat/connection and ambiguous updates',()=>{
 const now=Date.now(),chats=[{id:'synthetic-a',telegramChatId:101,activatedAt:now-2000,consentUntil:now+1000,participantsConsented:true}];
 const config={connectionId:'synthetic-connection',ownerUserId:999,chats,now};
 const message={business_connection_id:config.connectionId,message_id:1,date:Math.floor(now/1000),chat:{id:101,type:'private'},from:{id:101,is_bot:false},text:'synthetic'};
 const envelope=patch=>({synthetic:true,update:{update_id:1,business_message:{...message,...patch}}});
 assert.throws(()=>parseSyntheticBusinessUpdate({update:{}},config));
 assert.equal(parseSyntheticBusinessUpdate(envelope({}),config).length,1);
 for(const patch of [{business_connection_id:'other'},{chat:{id:102,type:'private'}},{chat:{id:101,type:'group'}},{from:{id:999,is_bot:false}},{date:1},{date:Math.floor(now/1000)+60},{text:'x'.repeat(2001)},{photo:[]},{reply_to_message:{}},{from:undefined}]) assert.deepEqual(parseSyntheticBusinessUpdate(envelope(patch),config),[]);
 const ambiguous=envelope({});ambiguous.update.edited_business_message=message;assert.deepEqual(parseSyntheticBusinessUpdate(ambiguous,config),[]);
 assert.deepEqual(parseSyntheticBusinessUpdate(envelope({}),{...config,chats:[{...chats[0],participantsConsented:false}]}),[]);
});

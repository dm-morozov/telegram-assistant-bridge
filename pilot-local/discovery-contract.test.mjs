import test from 'node:test';import assert from 'node:assert/strict';
import {Server,InMemoryTransport} from '@modelcontextprotocol/server';import {Client,extractWWWAuthenticateParams} from '@modelcontextprotocol/client';
import {createLocalProtectedPilot} from './http-pilot.mjs';
// Wire-contract fixture ONLY. It is not imported by the runtime, has no HTTP listener/data/credentials,
// and denies ALL tool executions. It does not change any deployed or local-runtime discovery policy.
const policies={list_new_messages:['messages:read'],create_local_draft:['messages:read','drafts:create'],get_local_draft:['messages:read','drafts:create']};
const resource='https://resource.invalid/private-mcp',prm='https://resource.invalid/.well-known/oauth-protected-resource/private-mcp';
const descriptor=name=>({name,description:'Synthetic static contract fixture. Execution requires OAuth.',inputSchema:{type:'object',properties:{},additionalProperties:false},securitySchemes:[{type:'oauth2',scopes:policies[name]}],_meta:{securitySchemes:[{type:'oauth2',scopes:policies[name]}]},annotations:{readOnlyHint:name!=='create_local_draft',destructiveHint:false,openWorldHint:false}});
test('supported low-level SDK preserves top-level securitySchemes and tool-result OAuth challenge on the wire',async()=>{
 const server=new Server({name:'synthetic-static-contract',version:'0.0.0'},{capabilities:{tools:{listChanged:false}}});const client=new Client({name:'contract-official-client',version:'0.0.0'});
 server.setRequestHandler('tools/list',async()=>({tools:Object.keys(policies).map(descriptor)}));
 server.setRequestHandler('tools/call',async request=>{
  assert.ok(Object.hasOwn(policies,request.params.name));
  // An unconditional deny is intentional: this fixture has no authority source or executor.
  const scopes=policies[request.params.name].join(' ');
  return {isError:true,content:[{type:'text',text:'Authentication required.'}],_meta:{'mcp/www_authenticate':[`Bearer resource_metadata="${prm}", error="invalid_token", error_description="Sign in to use this protected tool", scope="${scopes}"`]}};
 });
 const [clientTransport,serverTransport]=InMemoryTransport.createLinkedPair();let wireTools;const send=serverTransport.send.bind(serverTransport);serverTransport.send=async(message,...args)=>{if(message.result?.tools)wireTools=structuredClone(message.result.tools);return send(message,...args);};
 try{
  await server.connect(serverTransport);await client.connect(clientTransport);const listed=await client.listTools();assert.equal(listed.tools.length,3);
  assert.deepEqual(listed.tools.map(x=>x.name),Object.keys(policies));
  assert.equal(wireTools.length,3);for(const tool of wireTools){assert.deepEqual(tool.securitySchemes,[{type:'oauth2',scopes:policies[tool.name]}]);assert.deepEqual(tool._meta.securitySchemes,tool.securitySchemes);assert.ok(!tool.securitySchemes.some(x=>x.type==='noauth'));}for(const tool of listed.tools){assert.deepEqual(tool._meta.securitySchemes,[{type:'oauth2',scopes:policies[tool.name]}]);}
  const publicMetadata=JSON.stringify(listed);for(const secret of ['owner-subject','owner@example.invalid','message-sentinel','draft-sentinel','credential-sentinel'])assert.ok(!publicMetadata.includes(secret));
  for(const name of Object.keys(policies)){
   const result=await client.callTool({name,arguments:{}});assert.equal(result.isError,true);const challenge=result._meta['mcp/www_authenticate'][0];const parsed=extractWWWAuthenticateParams(new Response(null,{status:401,headers:{'WWW-Authenticate':challenge}}));assert.equal(parsed.resourceMetadataUrl.href,prm);assert.equal(parsed.error,'invalid_token');assert.ok(parsed.errorDescription);assert.equal(parsed.scope,policies[name].join(' '));
  }
  // Fixture proves metadata serialization only; it deliberately has no executor or authority source.
 }finally{await client.close();await server.close();}
});
test('existing HTTP runtime still requires credentials for initialize and tools/list; contract fixture is not an auth fallback',async()=>{
 const runtime=createLocalProtectedPilot({oauth:{issuer:'https://issuer.invalid/',audience:resource,jwksUri:'https://issuer.invalid/.well-known/jwks.json',ownerSubject:'synthetic-owner'}});const url=await runtime.start();
 try{for(const method of ['initialize','tools/list',...Object.keys(policies)]){const body=Object.hasOwn(policies,method)?{jsonrpc:'2.0',id:1,method:'tools/call',params:{name:method,arguments:{}}}:{jsonrpc:'2.0',id:1,method};const response=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});assert.equal(response.status,401);assert.ok(response.headers.get('WWW-Authenticate'));}}
 finally{await runtime.close();}
});
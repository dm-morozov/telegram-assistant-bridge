import { createServer } from 'node:http';
import { once } from 'node:events';
import { McpServer } from '@modelcontextprotocol/server';
import { NodeStreamableHTTPServerTransport } from '@modelcontextprotocol/node';
import * as z from 'zod/v4';
import { createResourceVerifier } from './verifier.mjs';
import { SyntheticPilot } from './pilot.mjs';

// Synthetic resource server only. No authorization/token endpoints or real-data adapter.
function createProtectedPilot({ oauth, chats = [], clock = Date.now, sweepMs = 1000, jwksSnapshotPath, canonicalIngress = false, listenHost = "127.0.0.1" } = {}) {
  if (!["127.0.0.1","0.0.0.0"].includes(listenHost) || (canonicalIngress && jwksSnapshotPath === undefined)) throw new Error("Explicit snapshot-only ingress configuration required");
  const verifier = createResourceVerifier(oauth, {jwksSnapshotPath});
  if (!Number.isInteger(sweepMs) || sweepMs < 10 || sweepMs > 1000) throw new Error('Invalid cleanup interval');
  const resource = new URL(oauth.audience);
  if (!/^\/[a-zA-Z0-9/_-]+$/.test(resource.pathname) || resource.pathname.endsWith('/')) throw new Error('Explicit resource path required');
  const metadataPath = '/.well-known/oauth-protected-resource' + resource.pathname;
  const metadataUrl = resource.origin + metadataPath;
  const metadata = { resource: oauth.audience, authorization_servers: [oauth.issuer], scopes_supported: ['messages:read','drafts:create'], bearer_methods_supported: ['header'] };
  let revoked = false;
  const pilot = new SyntheticPilot({ issuer:oauth.issuer, audience:oauth.audience, owner:oauth.ownerSubject, chats, clock,
    verifyAccessToken: async token => { if (revoked) throw new Error('Access denied'); return verifier.verifyAccessToken(token); } });
  const sweep = setInterval(() => pilot.collectGarbage(), sweepMs); sweep.unref();
  const json = (res,status,value) => res.writeHead(status,{'content-type':'application/json','cache-control':'no-store'}).end(JSON.stringify(value));
  const challenge = (res,status,error) => { res.setHeader('WWW-Authenticate', 'Bearer resource_metadata="'+metadataUrl+'", scope="messages:read drafts:create"'+(error?', error="'+error+'"':'')); json(res,status,{error:status===401?'unauthorized':'insufficient_scope'}); };
  const http = createServer(async (req,res) => {
    res.setHeader('Cache-Control','no-store');
    const expectedHost = canonicalIngress ? resource.host : '127.0.0.1:'+http.address()?.port;
    if (req.headers.host !== expectedHost || req.headers.origin || req.headers['x-forwarded-host'] || req.headers['x-forwarded-proto']) { json(res,403,{error:'forbidden'}); return; }
    if (req.url === metadataPath && req.method === 'GET') { json(res,200,metadata); return; }
    if (req.url !== resource.pathname) { json(res,404,{error:'not_found'}); return; }
    let principal;
    try { if (revoked) throw new Error(); principal = await verifier.verifyBearerHeader(req.headers.authorization); }
    catch { challenge(res,401,req.headers.authorization?'invalid_token':undefined); return; }
    if (req.method !== 'POST') { res.setHeader('Allow','POST'); json(res,405,{error:'method_not_allowed'}); return; }
    let body;
    try {
      if (!/^application\/json(?:;|$)/i.test(req.headers['content-type'] ?? '')) { json(res,415,{error:'unsupported_media_type'}); return; }
      if (Number(req.headers['content-length'] ?? 0)>16384) { json(res,413,{error:'body_too_large'}); return; }
      let size=0; const chunks=[];
      for await (const chunk of req) { size+=chunk.length; if(size>16384) {json(res,413,{error:'body_too_large'});return;} chunks.push(chunk); }
      body=JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (!body || Array.isArray(body) || body.jsonrpc!=='2.0') throw new Error();
    } catch { if (!res.headersSent) json(res,400,{error:'invalid_request'}); return; }
    if (revoked || principal.expiresAt <= Date.now()) { challenge(res,401,'invalid_token');return; }
    const toolScopes = { list_new_messages:['messages:read'], create_local_draft:['messages:read','drafts:create'], get_local_draft:['messages:read','drafts:create'] };
    const needed = body.method==='tools/call' && Object.hasOwn(toolScopes,body.params?.name ?? '') ? toolScopes[body.params.name] : undefined;
    if (needed?.some(scope=>!principal.scopes.includes(scope))) { challenge(res,403,'insufficient_scope');return; }
    const server = new McpServer({name:'telegram-bridge-synthetic-private',version:'0.0.0'});
    const token = req.headers.authorization.slice(7);
    const guarded = fn => async args => {
      try { if(revoked) throw new Error(); const value=await fn(args); return {content:[{type:'text',text:JSON.stringify(value)}]}; }
      catch { return {isError:true,content:[{type:'text',text:'Access denied or resource unavailable'}]}; }
    };
    const chatId=z.string().regex(/^synthetic-[a-z0-9-]+$/);
    const messageId=z.string().regex(/^msg-[a-z0-9-]+$/);
    server.registerTool('list_new_messages',{description:'Read bounded synthetic untrusted messages only.',inputSchema:z.object({chatId,limit:z.number().int().min(1).max(20).optional()}).strict(),_meta:{securitySchemes:[{type:'oauth2',scopes:['messages:read']}]},annotations:{readOnlyHint:true,openWorldHint:false}},guarded(a=>pilot.listNewMessages(token,a.chatId,a.limit)));
    server.registerTool('create_local_draft',{description:'Store a synthetic review-only draft in memory. Never sends to Telegram.',inputSchema:z.object({chatId,messageId,text:z.string().min(1).max(2000)}).strict(),_meta:{securitySchemes:[{type:'oauth2',scopes:['messages:read','drafts:create']}]},annotations:{readOnlyHint:false,destructiveHint:false,openWorldHint:false}},guarded(a=>pilot.createLocalDraft(token,a.chatId,a.messageId,a.text)));
    server.registerTool('get_local_draft',{description:'Read one synthetic local draft.',inputSchema:z.object({chatId,draftId:z.string().regex(/^draft-[0-9]+$/)}).strict(),_meta:{securitySchemes:[{type:'oauth2',scopes:['messages:read','drafts:create']}]},annotations:{readOnlyHint:true,openWorldHint:false}},guarded(a=>pilot.getLocalDraft(token,a.chatId,a.draftId)));
    const transport = new NodeStreamableHTTPServerTransport({sessionIdGenerator:undefined,enableJsonResponse:true});
    res.on('close',()=>{void server.close();});
    try { await server.connect(transport); await transport.handleRequest(req,res,body); }
    catch { if(!res.headersSent) json(res,500,{error:'request_failed'}); else res.end(); await server.close(); }
  });
  http.requestTimeout=5000; http.headersTimeout=4000; http.maxConnections=16;
  return Object.freeze({
    async start(port=0) { http.listen(port,listenHost); await once(http,'listening'); return new URL('http://127.0.0.1:'+http.address().port+resource.pathname); },
    async close() { revoked=true; clearInterval(sweep); pilot.clear(); if(http.listening) {http.closeAllConnections(); await new Promise(resolve=>http.close(resolve));} },
    ingestSynthetic:event=>{if(revoked) return false; return pilot.ingestSynthetic(event);},
    revokeChat:chatId=>pilot.revokeChat(chatId),
    revokeOwner() { revoked=true; pilot.clear(); },
    diagnostics:()=>pilot.diagnostics(), metadataPath
  });
}


export function createLocalProtectedPilot(options={}) {
  return createProtectedPilot({...options,canonicalIngress:false,listenHost:'127.0.0.1'});
}
export function createSnapshotIngressPilot({listenHost='127.0.0.1',...options}={}) {
  return createProtectedPilot({...options,canonicalIngress:true,listenHost});
}

import { readFile, lstat, writeFile, rename, unlink } from 'node:fs/promises';
import { isAbsolute, dirname, join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { createLocalJWKSet } from 'jose';

const MAX_BYTES=65536, MAX_AGE=120000;
function trustedSource({issuer,jwksUri}) {
 const i=new URL(issuer), j=new URL(jwksUri);
 if([i,j].some(u=>u.protocol!=='https:'||u.username||u.password||u.hash||u.search||['localhost','127.0.0.1','[::1]'].includes(u.hostname))||i.origin!==j.origin||j.pathname!=='/.well-known/jwks.json') throw new Error('Invalid pinned JWKS source');
 return {issuer,jwksUri:j.href};
}
function publicJwks(value) {
 if(!value||Object.keys(value).join(',')!=='keys'||!Array.isArray(value.keys)||value.keys.length<1||value.keys.length>8) throw new Error();
 const seen=new Set();
 const keys=value.keys.map(k=>{
  const allowed=['kty','kid','alg','use','n','e','x5c','x5t','x5t#S256','key_ops'];
  if(!k||Object.keys(k).some(field=>!allowed.includes(field))||k.kty!=='RSA'||k.alg!=='RS256'||k.use!=='sig'||!/^[A-Za-z0-9_-]{1,128}$/.test(k.kid??'')||seen.has(k.kid)) throw new Error();
  seen.add(k.kid);
  for(const field of ['n','e']) if(typeof k[field]!=='string'||!/^[A-Za-z0-9_-]+$/.test(k[field])||Buffer.from(k[field],'base64url').toString('base64url')!==k[field]) throw new Error();
  const n=Buffer.from(k.n,'base64url'),e=Buffer.from(k.e,'base64url');
  if(n.length<256||n.length>1024||n[0]===0||(n.length-1)*8+32-Math.clz32(n[0])<2048||e.length<1||e.length>8||e[0]===0||(e.length===1&&e[0]<3)||(e[e.length-1]&1)===0) throw new Error();
  if(k.key_ops && (!Array.isArray(k.key_ops)||k.key_ops.length!==1||k.key_ops[0]!=='verify')) throw new Error();
  if(k.x5c && (!Array.isArray(k.x5c)||k.x5c.length>5||k.x5c.some(v=>typeof v!=='string'||v.length>8192||!/^[A-Za-z0-9+/=]+$/.test(v)))) throw new Error();
  for(const field of ['x5t','x5t#S256']) if(k[field]!==undefined&&(typeof k[field]!=='string'||!/^[A-Za-z0-9_-]{1,128}$/.test(k[field]))) throw new Error();
  // Certificates are public, but unnecessary for signature verification: retain only public RSA JWK fields.
  return {kty:'RSA',alg:'RS256',use:'sig',kid:k.kid,n:k.n,e:k.e};
 });
 return {keys};
}
export function validateJwksSnapshot(value, source, now=Date.now()) {
 try {
  const fixed=trustedSource(source);
  if(!value||Object.keys(value).sort().join(',')!=='fetchedAt,issuer,jwks,schemaVersion,uri'||value.schemaVersion!==1||value.issuer!==fixed.issuer||value.uri!==fixed.jwksUri||!Number.isSafeInteger(value.fetchedAt)||!Number.isFinite(now)||value.fetchedAt>now+5000||now-value.fetchedAt>MAX_AGE) throw new Error();
  return publicJwks(value.jwks);
 }catch{throw new Error('Trusted fresh public JWKS snapshot required');}
}
export async function readJwksSnapshot(snapshotPath,source,now=Date.now()) {
 try {
  if(typeof snapshotPath!=='string'||!isAbsolute(snapshotPath)) throw new Error();
  const info=await lstat(snapshotPath);
  if(!info.isFile()||info.isSymbolicLink()||info.size>MAX_BYTES) throw new Error();
  const bytes=await readFile(snapshotPath);if(bytes.length>MAX_BYTES)throw new Error();
  return validateJwksSnapshot(JSON.parse(bytes.toString('utf8')),source,now);
 }catch{throw new Error('Trusted fresh public JWKS snapshot required');}
}
export function createSnapshotKeyResolver(snapshotPath,source) {
 trustedSource(source);
 if(typeof snapshotPath!=='string'||!isAbsolute(snapshotPath)) throw new Error('Explicit JWKS snapshot path required');
 let previous, resolver;
 const resolve=async(header,token)=>{
  // Freshness is checked on EVERY token verification, even when the jose key cache is warm.
  const jwks=await readJwksSnapshot(snapshotPath,source); const current=JSON.stringify(jwks);
  if(current!==previous){resolver=createLocalJWKSet(jwks);previous=current;}
  return resolver(header,token);
 };
 resolve.reload=async()=>{previous=undefined;resolver=undefined;await readJwksSnapshot(snapshotPath,source);};
 return resolve;
}
export async function refreshJwksSnapshot({issuer,jwksUri,snapshotPath}) {
 let temporary;
 try {
  const fixed=trustedSource({issuer,jwksUri});
  if(typeof snapshotPath!=='string'||!isAbsolute(snapshotPath)) throw new Error();
  const parent=await lstat(dirname(snapshotPath));if(!parent.isDirectory()||parent.isSymbolicLink())throw new Error();
  const response=await fetch(fixed.jwksUri,{method:'GET',redirect:'error',credentials:'omit',headers:{Accept:'application/json'},signal:AbortSignal.timeout(3000)});
  if(response.status!==200||Number(response.headers.get('content-length')??0)>MAX_BYTES) throw new Error();
  if(!/^application\/(?:json|jwk-set\+json)(?:;|$)/i.test(response.headers.get('content-type')??''))throw new Error();
  const reader=response.body?.getReader();if(!reader)throw new Error();const chunks=[];let length=0;
  try{while(true){const {value,done}=await reader.read();if(done)break;length+=value.length;if(length>MAX_BYTES){await reader.cancel();throw new Error();}chunks.push(value);}}finally{reader.releaseLock();}
  const jwks=publicJwks(JSON.parse(Buffer.concat(chunks).toString('utf8')));
  const snapshot={schemaVersion:1,issuer:fixed.issuer,uri:fixed.jwksUri,fetchedAt:Date.now(),jwks};
  const encoded=JSON.stringify(snapshot);if(Buffer.byteLength(encoded)>MAX_BYTES)throw new Error();
  temporary=join(dirname(snapshotPath),'.jwks-'+randomUUID()+'.tmp');
  await writeFile(temporary,encoded,{flag:'wx',mode:0o644});await rename(temporary,snapshotPath);temporary=undefined;
 }catch{throw new Error('JWKS snapshot refresh failed');}
 finally{if(temporary)await unlink(temporary).catch(()=>{});}
}

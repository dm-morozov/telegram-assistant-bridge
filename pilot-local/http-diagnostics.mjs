const METHODS=new Set(['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS','CONNECT','TRACE']);
const REJECTIONS=new Set(['not_evaluated','none','missing_credentials','malformed_credentials','token_rejected','owner_revoked','expired_during_request','insufficient_scope','tool_denied']);
// Allowlisted schema only. Never receive headers, tokens, addresses, bodies or error objects.
export function createHttpDiagnostics({resourcePath,metadataPath,sink,now=()=>performance.now()}={}) {
 if(sink!==undefined&&typeof sink!=='function')throw new Error('Diagnostic sink must be explicit');
 if(typeof now!=='function')throw new Error('Invalid diagnostic clock');
 const paths=[resourcePath,metadataPath];
 if(paths.some(p=>typeof p!=='string'||p.length>256||!/^\/[A-Za-z0-9/_.-]+$/.test(p)))throw new Error('Invalid diagnostic routes');
 let emitted=0;
 const timestamp=()=>{try{const value=now();return Number.isFinite(value)?value:0;}catch{return 0;}};
 return (req,res)=>{
  if(!sink||emitted>=1000)return ()=>{};
  const start=timestamp();
  const method=METHODS.has(req.method)?req.method:'OTHER';
  const candidate=typeof req.url==='string'?req.url.split(/[?#]/,1)[0]:'';
  const path=paths.includes(candidate)?candidate:'[other]';
  let done=false,authRejection='not_evaluated';
  const emit=status=>{
   if(done)return;done=true;if(emitted>=1000)return;emitted++;
   const record=Object.freeze({method,path,status:Number.isInteger(status)&&status>=100&&status<=599?status:0,durationMs:Math.min(3600000,Math.max(0,Math.round(timestamp()-start))),authRejection});
   try{sink(record);}catch{/* Diagnostics cannot change authorization or expose exception text. */}
  };
  res.once('finish',()=>emit(res.statusCode));
  res.once('close',()=>emit(res.writableFinished?res.statusCode:0));
  return classification=>{if(REJECTIONS.has(classification))authRejection=classification;};
 };
}
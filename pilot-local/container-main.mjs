import { armDeadline } from './bounded-deadline.mjs';
import { parseArgs } from 'node:util';
import { pathToFileURL } from 'node:url';
import { createConfiguredIngressPilot } from './owner-config.mjs';
export async function runContainer(args) {
 const {values}=parseArgs({args,options:{container:{type:'boolean'},'owner-config':{type:'string'},'jwks-snapshot':{type:'string'}},strict:true});
 if(values.container!==true||!values['owner-config']||!values['jwks-snapshot'])throw new Error('Explicit container-only startup required');
 const now=Date.now();
 const runtime=await createConfiguredIngressPilot({ownerConfigPath:values['owner-config'],jwksSnapshotPath:values['jwks-snapshot'],listenHost:'0.0.0.0',chats:[{id:'synthetic-demo',activatedAt:now-1000,consentUntil:now+900000,participantsConsented:true}]});
 let cancelDeadline=()=>{},stopping;
 const stop=()=>stopping??=(async()=>{cancelDeadline();await runtime.close();})();
 try {
  runtime.ingestSynthetic({source:'synthetic',chatId:'synthetic-demo',id:'msg-demo',type:'new',direction:'incoming',receivedAt:now-500,text:'Synthetic demonstration message. No Telegram connection or real conversation data.'});
  await runtime.start(3000);
  cancelDeadline=armDeadline(stop);
  process.once('SIGTERM',()=>{void stop();});process.once('SIGINT',()=>{void stop();});
  // No issuer/subject/path/token/request content is logged.
  console.log('Synthetic private MCP ready; maximum runtime 15 minutes');
  return {stop};
 }catch{await stop();throw new Error('Synthetic private MCP startup failed');}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 runContainer(process.argv.slice(2)).catch(()=>{console.error('Synthetic private MCP startup refused');process.exitCode=1;});
}

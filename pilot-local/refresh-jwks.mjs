import { parseArgs } from 'node:util';
import { pathToFileURL } from 'node:url';
import { loadApprovedOwnerConfiguration } from './owner-config.mjs';
import { refreshJwksSnapshot } from './jwks-snapshot.mjs';
export async function refreshFromArguments(args) {
 const {values}=parseArgs({args,options:{'owner-config':{type:'string'},snapshot:{type:'string'}},strict:true});
 if(!values['owner-config']||!values.snapshot)throw new Error('Explicit configuration and snapshot paths required');
 const {oauth}=await loadApprovedOwnerConfiguration(values['owner-config']);
 await refreshJwksSnapshot({...oauth,snapshotPath:values.snapshot});
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 refreshFromArguments(process.argv.slice(2)).catch(()=>{console.error('JWKS refresh failed');process.exitCode=1;});
}

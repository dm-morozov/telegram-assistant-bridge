export function armDeadline(stop,{milliseconds=900000,schedule=setTimeout,cancel=clearTimeout}={}) {
 if(typeof stop!=='function'||milliseconds!==900000)throw new Error('Fixed trial deadline required');
 let active=true;const timer=schedule(()=>{if(active){active=false;void stop();}},milliseconds);timer?.unref?.();
 return ()=>{if(active){active=false;cancel(timer);}};
}
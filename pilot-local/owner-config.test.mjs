import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, unlink, rmdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadApprovedOwnerConfiguration, createConfiguredLocalPilot } from './owner-config.mjs';
const synthetic={schemaVersion:1,oauth:{issuer:'https://issuer.invalid/',audience:'https://resource.invalid/private-mcp',jwksUri:'https://issuer.invalid/jwks',ownerSubject:'synthetic-owner'},ownerEmailVerified:true,verificationObservedAtUtc:'2026-01-01T00:00:00Z',connectionName:'Username-Password-Authentication'};
test('private owner configuration fails closed without verified explicit identity and never logs it',async t=>{
 const directory=await mkdtemp(join(tmpdir(),'bridge-owner-config-'));const file=join(directory,'owner.local.json');
 const outputs=[];for(const method of ['log','info','warn','error','debug']) t.mock.method(console,method,(...args)=>outputs.push(args.join(' ')));
 try {
  await assert.rejects(createConfiguredLocalPilot(),/^Error: Approved verified-owner configuration required$/);
  await assert.rejects(loadApprovedOwnerConfiguration('owner.local.json'));
  await assert.rejects(loadApprovedOwnerConfiguration(file));
  for(const patch of [{ownerEmailVerified:false},{ownerEmailVerified:undefined},{connectionName:'other'},{verificationObservedAtUtc:'bad'},{verificationObservedAtUtc:'2999-01-01T00:00:00Z'},{oauth:{...synthetic.oauth,ownerSubject:''}},{oauth:{...synthetic.oauth,issuer:'http://issuer.invalid/'}},{oauth:{...synthetic.oauth,jwksUri:'https://other.invalid/jwks'}},{password:'synthetic-not-a-password'},{schemaVersion:2}]) {
   await writeFile(file,JSON.stringify({...synthetic,...patch}));
   await assert.rejects(createConfiguredLocalPilot({ownerConfigPath:file}),/^Error: Approved verified-owner configuration required$/);
  }
  await writeFile(file,'{malformed synthetic-private-content');await assert.rejects(loadApprovedOwnerConfiguration(file),/^Error: Approved verified-owner configuration required$/);
  await writeFile(file,'x'.repeat(8193));await assert.rejects(loadApprovedOwnerConfiguration(file));
  await writeFile(file,JSON.stringify(synthetic));const loaded=await loadApprovedOwnerConfiguration(file);assert.ok(Object.isFrozen(loaded.oauth));assert.equal(loaded.oauth.ownerSubject,'synthetic-owner');
  const pilot=await createConfiguredLocalPilot({ownerConfigPath:file});await pilot.close();assert.deepEqual(outputs,[]);
 }finally{t.mock.restoreAll();await unlink(file).catch(()=>{});await rmdir(directory);}
});

// Validation script only. The production executable does not spawn processes.
const {spawnSync} = require('node:child_process');
const assert = require('node:assert/strict');
const net = require('node:net');
const path = require('node:path');
const dir = process.argv[2] || 'build-release';
function run(name,args) {
 const r=spawnSync(path.resolve(dir,name),args,{encoding:'utf8'});
 assert.equal(r.status,0,r.stderr);
 assert.equal(r.stderr,'');
 assert(!r.stdout.startsWith('\uFEFF'));
 return JSON.parse(r.stdout);
}
const live=run('windows-dns-config-auditor.exe',['--json']);
assert.equal(live.schema_version,'1.0');
assert.equal(live.application_version,'1.0.0');
assert(Array.isArray(live.adapters));
for(const a of live.adapters) {
 assert.equal(typeof a.active,'boolean');
 assert.equal(typeof a.luid,'string');
 for(const s of a.dns_servers) if(s.valid) {
  assert.equal(net.isIP(s.address.split('%')[0]),s.family==='IPv4'?4:6);
 }
}
const fixture=run('audit_tests.exe',['--emit-json']);
assert.equal(fixture.adapters[0].friendly_name,'網路 café 🚀');
assert.equal(fixture.system.hostname,'quote"\\\n\t');
assert.equal(fixture.suffix_configuration.search_lists[0].raw_value,'a.test,b.test');
const fail=spawnSync(path.resolve(dir,'windows-dns-config-auditor.exe'),['--bad'],{encoding:'utf8'});
assert.equal(fail.status,2);assert.equal(fail.stdout,'');assert(fail.stderr.length>0);
const both=run('windows-dns-config-auditor.exe',['--all','--json']);
assert.deepEqual(both.adapters,live.adapters);
console.log('Independent JSON parsing, Unicode, numeric IPv4/IPv6, CLI stderr and schema checks passed.');

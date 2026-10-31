import test from 'node:test';
import assert from 'node:assert/strict';
import { replay } from '../src/replay.js';
import { authenticated } from '../src/server.js';
test('replay refuses foreign targets and unregistered paths',()=>{
  for(const [mode,path] of [['https://example.com','/sql'],['fixed','//example.com'],['fixed','/api/evidence'],['fixed','/sql?x=y']]) assert.throws(()=>replay(mode!,path!));
});
test('management authentication fails closed',()=>{
  assert.equal(authenticated(undefined,'secret'),false);
  assert.equal(authenticated('Bearer secreu','secret'),false);
  assert.equal(authenticated('Bearer secretx','secret'),false);
  assert.equal(authenticated('Bearer secret','secret'),true);
});

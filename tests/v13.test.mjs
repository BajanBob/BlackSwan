import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeMsg } from '../www/engine.js';
import { analyzeLogs } from '../www/artex.js';

test('conversation playbook (hook → trust → isolate → payment) is critical', () => {
  const r = analyzeMsg('Sorry, wrong number! Nice to meet you my dear. Add me on WhatsApp. I have a part-time job: earn $300 per day rating hotels, just recharge your account with USDT.');
  assert.ok(r.stages.length >= 3); assert.equal(r.lv, 4); assert.match(r.findings[0].t, /scam playbook/);
});
test('task scams are recognised', () => {
  assert.ok(analyzeMsg('Part-time job: like videos and earn daily commission, complete the tasks').rules.includes('task_scam'));
});
test('ordinary chat stays clean', () => { assert.ok(analyzeMsg('Can you send me the photos from Saturday?').prob < 0.15); });
test('port scans in ufw / iptables logs', () => {
  const L = []; for (let i = 1; i <= 30; i++) L.push(`Nov 20 10:00:${String(i).padStart(2, '0')} fw kernel: [UFW BLOCK] SRC=198.51.100.9 DST=10.0.0.2 PROTO=TCP DPT=${i === 1 ? 3389 : 1000 + i}`);
  const f = analyzeLogs(L.join('\n')).findings.find((x) => x.title === 'Port scan from 198.51.100.9');
  assert.ok(f); assert.match(f.text, /3389/);
});
test('port scans in Windows firewall logs', () => {
  const L = []; for (let i = 0; i < 20; i++) L.push(`2026-11-20 10:00:${String(i).padStart(2, '0')} DROP TCP 192.0.2.77 10.0.0.2 51000 ${2000 + i} 0 - - - - - - - RECEIVE`);
  assert.ok(analyzeLogs(L.join('\n')).findings.some((x) => x.title === 'Port scan from 192.0.2.77'));
});
test('a few ports are not a scan', () => {
  const L = []; for (const p of [80, 443, 443, 80]) L.push(`SRC=192.0.2.5 DST=10.0.0.2 DPT=${p}`);
  assert.ok(!analyzeLogs(L.join('\n')).findings.some((x) => x.title.startsWith('Port scan')));
});

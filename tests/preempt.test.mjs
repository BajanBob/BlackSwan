import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeLogs, toolFamily, mixedTools, machinePaced } from '../www/artex.js';

const T0 = Date.UTC(2026, 10, 25, 10, 0, 0);
const j = (o) => JSON.stringify(o);
const titles = (log) => analyzeLogs(log).findings.map((f) => `${f.lv}:${f.title}`).join('|');

test('ARTEX working files on hosts are critical', () => {
  assert.match(titles('2026-11-25T10:00:00Z proc create C:\\ProgramData\\artx5v\\run.exe'), /4:ARTEX working files/);
  assert.match(titles('2026-11-25T10:00:00Z file write C:\\Windows\\Temp\\artx_i42_enum.txt'), /4:ARTEX working files/);
  assert.doesNotMatch(titles('2026-11-25T10:00:00Z file write C:\\Windows\\Temp\\setup.log'), /ARTEX working files/);
});
test('callback / tunnel services and AI model calls from servers', () => {
  const t = titles([j({ time: '2026-11-25T10:00:00Z', ip: '10.0.0.5', url: 'https://webhook.site/abc' }), j({ time: '2026-11-25T10:00:01Z', ip: '10.0.0.5', host: 'api.deepseek.com' })].join('\n'));
  assert.match(t, /3:Callback or tunnel service: webhook\.site/);
  assert.match(t, /2:Server talking to an AI model service: api\.deepseek\.com/);
});
test('tool mixing from one address within a minute', () => {
  assert.equal(toolFamily('Mozilla/5.0 (Windows NT 10.0)'), null);
  assert.equal(toolFamily('Go-http-client/2.0'), 'Go');
  const uas = ['curl/8.4', 'python-requests/2.31', 'Go-http-client/1.1'];
  const log = uas.map((ua, i) => j({ time: new Date(T0 + i * 5000).toISOString(), ip: '198.51.100.20', path: '/', status: 200, user_agent: ua })).join('\n');
  assert.match(titles(log), /3:Several attack tools from 198\.51\.100\.20/);
  assert.equal(mixedTools([[0, 'curl'], [120e3, 'Go'], [240e3, 'Python']]), null);
});
test('config and source-map harvesting', () => {
  const paths = ['/static/main.js.map', '/.env', '/.git/config', '/config.json', '/actuator/env', '/index.html'];
  const log = paths.map((p, i) => j({ time: new Date(T0 + i * 1000).toISOString(), ip: '203.0.113.30', path: p, status: 404 })).join('\n');
  assert.match(titles(log), /3:Config and source harvesting from 203\.0\.113\.30/);
});
test('AWS DryRun burst', () => {
  const L = []; for (let i = 0; i < 25; i++) L.push(j({ eventTime: new Date(T0 + i * 1000).toISOString(), errorCode: 'Client.DryRunOperation', userIdentity: { arn: 'arn:aws:iam::111122223333:user/ci' } }));
  assert.match(titles(L.join('\n')), /3:Cloud permissions being mapped/);
});
test('app credential and role changes', () => {
  assert.match(titles('2026-11-25T10:00:00Z Audit: Add service principal credentials by admin@example.com'), /2:App credentials, owners or roles changed/);
  const L = []; for (let i = 0; i < 5; i++) L.push(`2026-11-25T10:0${i}:00Z Audit: Add member to role`);
  assert.match(titles(L.join('\n')), /3:App credentials, owners or roles changed/);
});
test('lateral movement fan-out', () => {
  const L = []; for (let i = 1; i <= 12; i++) L.push(`Nov 25 10:00:${String(i).padStart(2, '0')} fw kernel: SRC=10.0.0.9 DST=10.0.1.${i} PROTO=TCP DPT=${i % 2 ? 445 : 5985}`);
  assert.match(titles(L.join('\n')), /4:Lateral movement from 10\.0\.0\.9/);
  const few = []; for (let i = 1; i <= 3; i++) few.push(`SRC=10.0.0.9 DST=10.0.1.${i} PROTO=TCP DPT=445`);
  assert.doesNotMatch(titles(few.join('\n')), /Lateral movement/);
});
test('machine-paced guessing', () => {
  assert.ok(machinePaced(Array.from({ length: 30 }, (_, i) => T0 + i * 1000)));
  assert.ok(!machinePaced(Array.from({ length: 30 }, (_, i) => T0 + i * 1000 + ((i * 7919) % 13) * 700)));
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeLogs, parseLine, parseTime, rhythm, findSecrets, ARTEX_IOCS } from '../www/artex.js';

const clf = (ip, t, path = '/', status = 200, ua = 'Mozilla/5.0') => {
  const d = new Date(t); const mon = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'][d.getUTCMonth()];
  const p = (n) => String(n).padStart(2, '0');
  return `${ip} - - [${p(d.getUTCDate())}/${mon}/${d.getUTCFullYear()}:${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())} +0000] "GET ${path} HTTP/1.1" ${status} 512 "-" "${ua}"`;
};
const T0 = Date.UTC(2026, 10, 20, 10, 0, 0);

test('combined log format and time zones', () => {
  const r = parseLine(clf('203.0.113.9', T0, '/login', 401, 'curl/8'));
  assert.equal(r.ip, '203.0.113.9'); assert.equal(r.t, T0); assert.equal(r.status, 401); assert.equal(r.path, '/login'); assert.equal(r.ua, 'curl/8');
  assert.equal(parseTime('[20/Nov/2026:06:00:00 -0400]'), T0);
});
test('JSON lines', () => {
  const r = parseLine(JSON.stringify({ timestamp: '2026-11-20T10:00:00Z', remote_addr: '198.51.100.4', http_user_agent: 'norma/0.4', status: 200 }));
  assert.equal(r.ip, '198.51.100.4'); assert.equal(r.ua, 'norma/0.4'); assert.equal(r.t, T0);
});
test('user agent and known IP are critical', () => {
  const log = [clf('203.0.113.9', T0, '/', 200, 'artex-enrich/1.0'), clf('91.92.240.238', T0 + 1000)].join('\n');
  const F = analyzeLogs(log).findings;
  assert.ok(F.some((f) => f.title === 'ARTEX user agent' && f.lv === 4));
  assert.ok(F.some((f) => f.title.startsWith('Known ARTEX infrastructure')));
});
test('burst-then-think rhythm is flagged, human browsing is not', () => {
  const agent = []; let t = T0;
  for (let c = 0; c < 6; c++) { for (let k = 0; k < 5; k++) { agent.push(t); t += 900; } t += 28000; }
  assert.ok(rhythm(agent).flagged);
  const human = []; t = T0; for (let i = 0; i < 40; i++) { human.push(t); t += 3000 + ((i * 7919) % 90) * 1000; }
  assert.equal(rhythm(human).flagged, false);
  const log = agent.map((x) => clf('198.51.100.77', x, '/api/v1/users')).join('\n');
  assert.ok(analyzeLogs(log).findings.some((f) => f.title.startsWith('Agent-like request rhythm')));
});
test('password spraying', () => {
  const lines = []; for (let i = 0; i < 120; i++) lines.push(JSON.stringify({ time: new Date(T0 + i * 500).toISOString(), ip: '192.0.2.50', path: '/oauth/token', status: 401, userPrincipalName: `user${i % 40}@example.com` }));
  const F = analyzeLogs(lines.join('\n')).findings;
  assert.ok(F.some((f) => f.title === 'Password attack from 192.0.2.50' && f.lv === 4));
});
test('Entra secret guessing then success', () => {
  const lines = [];
  for (let i = 0; i < 6; i++) lines.push(`2026-11-20T10:00:0${i}Z sign-in failure ip 192.0.2.60 app app${i} AADSTS7000215`);
  lines.push('2026-11-20T10:00:09Z sign-in success ip 192.0.2.60 app app6 AADSTS0');
  const t = analyzeLogs(lines.join('\n')).findings.map((f) => f.title).join('|');
  assert.match(t, /Application secrets being guessed/); assert.match(t, /Secret guessed, then accepted/);
});
test('clean logs say so', () => {
  const F = analyzeLogs([clf('203.0.113.1', T0), clf('203.0.113.2', T0 + 5000)].join('\n')).findings;
  assert.equal(F.length, 1); assert.equal(F[0].lv, 1);
});
test('backdoored image reference', () => {
  assert.ok(analyzeLogs('image: tomicdd/artex:latest').findings.some((f) => f.lv === 4));
  assert.ok(ARTEX_IOCS.dockerImages.includes('congdonglinux/artex'));
});
test('secret finder masks values', () => {
  const s = findSecrets('const k = "AKIAABCDEFGHIJKLMNOP";\nfine line\nOPENAI=sk-proj-abcdefghijklmnopqrstuvwxyz0123456789');
  assert.equal(s.length, 2); assert.equal(s[0].kind, 'AWS access key'); assert.doesNotMatch(s[0].preview, /BCDEFGHIJKLM/);
});

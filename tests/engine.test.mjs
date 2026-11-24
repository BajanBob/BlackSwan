// Run with: npm test
import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeURL, analyzeMsg, generatePassword, poissonTail, Ewma, setUrlWeights, DEFAULT_WEIGHTS, URL_FEATURES } from '../www/engine.js';
import { analyzeCells, analyzeWifi, analyzeArp } from '../www/netwatch.js';

const p = (u) => analyzeURL(u).prob;

test('official sites score low', () => {
  for (const u of ['https://www.paypal.com/signin', 'https://accounts.google.com', 'https://groups.google.com', 'https://www.amazon.co.uk/orders', 'google.com', 'https://login.microsoftonline.com/']) assert.ok(p(u) < 0.15, u + ' ' + p(u));
});
test('phishing patterns score high', () => {
  for (const u of ['http://secure-paypa1.com.account-verify.top/login', 'https://micros0ft.com/verify', 'https://microsoft-login.pages.dev', 'http://paypal.com@198.51.100.7/login', 'https://xn--pypal-4ve.com/', 'https://faceb00k-security.help/confirm', 'https://docs.example.com/invoice.pdf.exe']) assert.ok(p(u) >= 0.4, u + ' ' + p(u));
});
test('redirect to a bad target is caught', () => {
  const r = analyzeURL('https://www.google.com/url?q=https://paypa1-login.xyz/verify');
  assert.equal(r.x.redirect, 1); assert.ok(r.prob >= 0.4, String(r.prob));
});
test('short brands do not fire on substrings', () => { assert.ok(p('https://groups.io') < 0.15); assert.ok(p('https://www.chasebank-community.org') >= 0.15); });
test('script and data links are critical', () => { assert.equal(analyzeURL('javascript:alert(1)').lv, 4); assert.equal(analyzeURL('data:text/html,<form>').lv, 4); });
test('feature vector has every feature', () => { assert.deepEqual(Object.keys(analyzeURL('https://example.com').x), URL_FEATURES); });
test('MATLAB weights load and change scores', () => {
  const before = p('https://example.top');
  assert.ok(setUrlWeights({ bias: -3, w: { ...DEFAULT_WEIGHTS.url.w, abused_tld: 5 } }));
  assert.ok(p('https://example.top') > before);
  setUrlWeights(DEFAULT_WEIGHTS.url);
  assert.equal(setUrlWeights({ nope: 1 }), false);
});
test('scam messages are caught, normal ones are not', () => {
  const bad = analyzeMsg('URGENT: your computer is infected. Install AnyDesk and pay with gift cards. Press Win + R and paste the code.');
  assert.ok(bad.prob > 0.9); assert.ok(bad.rules.includes('remote_access') && bad.rules.includes('clickfix'));
  assert.ok(analyzeMsg('See you at lunch tomorrow at 1?').prob < 0.15);
  assert.ok(analyzeMsg('Please note our new bank details for the overdue invoice. Keep this confidential.').prob >= 0.75);
});
test('passwords: length, sets, no look-alikes, entropy', () => {
  for (let i = 0; i < 200; i++) {
    const g = generatePassword(15, { upper: true, lower: true });
    assert.equal(g.password.length, 15); assert.match(g.password, /^[A-Za-z]+$/); assert.doesNotMatch(g.password, /[Il1O0o]/);
    assert.match(g.password, /[A-Z]/); assert.match(g.password, /[a-z]/);
  }
  assert.ok(generatePassword(15).bits > 80);
});
test('poisson tail', () => {
  assert.equal(poissonTail(0, 0.5), 1);
  assert.ok(Math.abs(poissonTail(1, 0.5) - (1 - Math.exp(-0.5))) < 1e-12);
  assert.ok(poissonTail(8, 0.5) < 1e-6);
});
test('ewma flags outliers only after warm-up', () => {
  const e = new Ewma(); for (const v of [-98, -97, -99, -96, -98, -97]) e.push(v);
  assert.ok(e.z(-60) > 3); assert.ok(Math.abs(e.z(-97)) < 1);
});
test('cells: tower identity change and downgrade', () => {
  let base = {};
  for (let i = 0; i < 6; i++) base = analyzeCells({ data: '4G', cells: [{ registered: true, gen: '4G', cell: 1 + (i % 3), area: 10, dbm: -97 }] }, base).base;
  const moved = analyzeCells({ data: '4G', cells: [{ registered: true, gen: '4G', cell: 2, area: 99, dbm: -97 }] }, base);
  assert.ok(moved.findings.some((f) => f.title === 'Tower identity changed'));
  const loud = analyzeCells({ data: '2G', cells: [{ registered: true, gen: '4G', cell: 777, area: 10, dbm: -50 }] }, base);
  assert.ok(loud.findings.some((f) => f.title === 'Unusually strong new tower'));
  assert.ok(loud.findings.some((f) => f.title.startsWith('Downgraded')));
});
test('wifi: evil twin, gateway change, proxy', () => {
  const w = { onWifi: true, ssid: 'Cafe', bssid: 'aa:bb:cc:00:00:01', gateway: '10.0.0.1', dns: ['10.0.0.1'], security: 2 };
  let r = analyzeWifi(w, {});
  r = analyzeWifi({ ...w, gateway: '10.0.0.66', proxy: '10.0.0.66:8080', sameName: [{ caps: '[ESS]' }, { caps: '[WPA2-PSK]' }] }, r.base);
  const t = r.findings.map((f) => f.title).join('|');
  assert.match(t, /Evil twin/); assert.match(t, /Router address changed/); assert.match(t, /proxy/);
});
test('arp spoofing of the router', () => {
  const F = analyzeArp('192.168.1.1  a4-2b-b0-11-22-33 dynamic\n192.168.1.40  a4-2b-b0-11-22-33 dynamic\n192.168.1.255 ff-ff-ff-ff-ff-ff static', '192.168.1.1');
  assert.equal(F[0].lv, 4);
  assert.equal(analyzeArp('192.168.1.1  a4-2b-b0-11-22-33\n192.168.1.2  a4-2b-b0-11-22-34')[0].lv, 1);
});

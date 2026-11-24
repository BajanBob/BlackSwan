import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeURL, setIntel, learnUrl, setUrlWeights, DEFAULT_WEIGHTS } from '../www/engine.js';
import { analyzeLogs } from '../www/artex.js';

test('live phishing feed overrides a clean-looking score', () => {
  const u = 'https://quiet-garden-store.example/account';
  const before = analyzeURL(u).prob;
  setIntel({ phishDomains: ['quiet-garden-store.example'], phishUrls: [] });
  const r = analyzeURL(u);
  assert.ok(before < 0.4); assert.ok(r.prob >= 0.97); assert.equal(r.lv, 4); assert.match(r.findings[0].t, /live phishing feeds/);
  setIntel({});
});
test('shared hosts are never blocked as a whole', () => {
  setIntel({ phishDomains: ['github.io'] });
  assert.ok(analyzeURL('https://someone.github.io/docs').prob < 0.4);
  setIntel({});
});
test('on-device learning moves the score toward the answer, then resets', () => {
  const u = 'https://example.top/promo';
  const x = analyzeURL(u).x; const p0 = analyzeURL(u).prob;
  for (let i = 0; i < 5; i++) learnUrl(x, 1);
  assert.ok(analyzeURL(u).prob > p0);
  setUrlWeights(DEFAULT_WEIGHTS.url);
  assert.ok(Math.abs(analyzeURL(u).prob - p0) < 1e-9);
});
test('feed IPs and user agents reach the log analyser', () => {
  const F = analyzeLogs('198.51.100.200 - - [20/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "evil-bot/9"', { extraIps: { '198.51.100.200': 'Botnet C2 (Test)' }, extraUAs: ['evil-bot/9'] }).findings;
  assert.ok(F.some((f) => f.title === 'Known malicious server: 198.51.100.200'));
  assert.ok(F.some((f) => f.title === 'Known attack-tool user agent'));
});

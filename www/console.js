// BlackSwan console: tabs, link / message scanners, intrusion monitor, password guard with fingerprint vault, alerts, desktop agent.
import { DEFAULT_WEIGHTS, analyzeURL, analyzeMsg, setUrlWeights, currentWeights, generatePassword, crackTime, poissonTail, URL_FEATURES } from './engine.js';
import { analyzeCells, analyzeWifi, analyzeArp } from './netwatch.js';
import { store, raise, alerts, onAlert, clearAlerts, record, exportAll } from './bus.js';
import { SCAMS } from './scams.js';
import { analyzeLogs, findSecrets, ARTEX_IOCS } from './artex.js';
import { learnUrl } from './engine.js';
import { refreshIntel, currentIntel } from './intel.js';
import { startPosture, playLevel, paint, postureOf } from './posture.js';
import { loadPlan, plan, can, config, PRICES, PLANS, startTrial, trialUsed, applyLicence, removeLicence } from './plans.js';

const $ = (s) => document.querySelector(s);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
function toast(m, ms = 3500) { const t = $('#toast'); t.textContent = m; t.hidden = false; clearTimeout(toast.t); toast.t = setTimeout(() => { t.hidden = true; }, ms); }
const CLS = ['', 'ok', 'warn', 'risk', 'risk crit'];
const LBL = ['', 'Info', 'Caution', 'Danger', 'Critical'];
const li = (lv, title, text) => `<li class="finding ${CLS[lv]}"><div><strong>${esc(title)}</strong>${text ? `<p>${esc(text)}</p>` : ''}</div></li>`;
async function copy(text, okMsg) { try { await navigator.clipboard.writeText(text); toast(okMsg || 'Copied.'); } catch { toast('Copying was blocked — select the text and copy it.'); } }

// ---------- native plugins (absent in a normal browser) ----------
let platform = 'web', Check = null, Bio = null, Notes = null;
try {
  const core = await import('./capacitor-core.js');
  platform = core.Capacitor.getPlatform();
  if (platform === 'android') Check = core.registerPlugin('GuardCheck');
  if (platform !== 'web') { Bio = core.registerPlugin('NativeBiometric'); Notes = core.registerPlugin('LocalNotifications'); }
} catch { /* browser */ }

// Weights trained in MATLAB (optional file next to index.html).
try { const r = await fetch('weights.json', { cache: 'no-store' }); if (r.ok && setUrlWeights(await r.json())) $('#model-info').textContent = 'Using phishing-model weights trained in MATLAB (weights.json).'; } catch { /* default weights */ }
const learned = store.get('learned', null);
if (learned?.w && setUrlWeights(learned.w)) $('#model-info').textContent += ` Personalised by ${learned.n} of your answers.`;
if (!$('#model-info').textContent) $('#model-info').textContent = `Using built-in weights for ${URL_FEATURES.length} link features. Train your own with matlab/bs_train_url_model.m.`;

// ---------- tabs ----------
const tabs = [...document.querySelectorAll('#tabs button')];
function show(t) {
  if (!document.getElementById('p-' + t)) t = 'phone';
  tabs.forEach((b) => (b.dataset.t === t ? b.setAttribute('aria-current', 'page') : b.removeAttribute('aria-current')));
  document.querySelectorAll('.panel').forEach((p) => { p.hidden = p.id !== 'p-' + t; });
  store.set('tab', t);
}
tabs.forEach((b) => b.addEventListener('click', () => { show(b.dataset.t); window.scrollTo(0, 0); }));
show(location.hash.slice(1) || store.get('tab', 'phone'));
window.addEventListener('hashchange', () => show(location.hash.slice(1)));

// ---------- scanners ----------
function paintResult(prefix, r) {
  $(`#${prefix}-result`).hidden = false; $(`#${prefix}-find-card`).hidden = false;
  const ring = $(`#${prefix}-ring`); ring.style.setProperty('--p', r.score); ring.style.setProperty('--c', ['', 'var(--ok)', 'var(--warn)', 'var(--risk)', 'var(--crit)'][r.lv]);
  $(`#${prefix}-score`).textContent = r.score; $(`#${prefix}-verdict`).textContent = r.verdict; $(`#${prefix}-host`).textContent = r.host;
  $(`#${prefix}-find`).innerHTML = r.findings.map((f) => li(f.lv, LBL[f.lv], f.t)).join('');
}
let lastX = null;
function scanUrl() {
  const v = $('#url').value; const r = analyzeURL(v); if (!r) return toast('Paste a link first.');
  lastX = r.x; $('#learn-info').textContent = '';
  paintResult('url', r); record('scans', { kind: 'url', host: r.host, p: +r.prob.toFixed(4), x: r.x }, 500);
  if (r.lv >= 3) raise(r.lv, `Dangerous link: ${r.host}`, `${r.verdict} · ${r.score}% phishing probability`, 'links');
}
function scanMsg() {
  const v = $('#msg').value; if (!v.trim()) return toast('Paste a message first.');
  const r = analyzeMsg(v); paintResult('msg', r); record('scans', { kind: 'msg', p: +r.prob.toFixed(4), rules: r.rules }, 500);
  if (r.lv >= 3) raise(r.lv, 'Scam message detected', `${r.verdict} · ${r.score}% · ${r.rules.join(', ')}`, 'messages');
}
$('#url-scan').addEventListener('click', scanUrl);
function learn(y) {
  if (!can('plus')) { toast('Learning from your answers is part of BlackSwan Plus.'); return show('plans'); }
  if (!lastX) return toast('Scan a link first.');
  const w = learnUrl(lastX, y); const prev = store.get('learned', { n: 0 });
  store.set('learned', { n: prev.n + 1, w: structuredClone(w) }); record('scans', { kind: 'label', y, x: lastX }, 500);
  $('#learn-info').textContent = `Thanks — BlackSwan has learned from ${prev.n + 1} answer${prev.n ? 's' : ''} on this phone.`; lastX = null;
}
$('#learn-safe').addEventListener('click', () => learn(0));
$('#learn-scam').addEventListener('click', () => learn(1));
$('#learn-reset').addEventListener('click', () => { store.del('learned'); setUrlWeights(DEFAULT_WEIGHTS.url); $('#learn-info').textContent = 'Learning reset to the built-in model.'; });
$('#url').addEventListener('keydown', (e) => { if (e.key === 'Enter') scanUrl(); });
$('#url-paste').addEventListener('click', () => { $('#url').value = 'http://secure-paypa1.com.account-verify.top/login?redirect=https%3A%2F%2Fbit.ly%2F3xY'; scanUrl(); });
$('#msg-scan').addEventListener('click', scanMsg);
$('#msg-paste').addEventListener('click', () => { $('#msg').value = 'URGENT: Your account has been locked because a virus was detected on your phone. Call our support team now and install AnyDesk so a technician can remove it. Payment is by gift card only. Verify you are human: press Win + R, paste the code and press Enter. http://micros0ft-support.help/fix'; scanMsg(); });

// ---------- intrusion monitor ----------
const EX_NET = { operator: 'Example Mobile', data: '4G', cells: [{ registered: true, gen: '4G', cell: 21345678, area: 1201, dbm: -96 }] };
const EX_WIFI = { onWifi: true, validated: true, ssid: 'Hotel Guest', bssid: 'a4:2b:b0:11:22:33', gateway: '192.168.1.1', dns: ['192.168.1.1'], security: 0, proxy: '', locationPermission: true,
  sameName: [{ bssid: 'a4:2b:b0:11:22:33', caps: '[ESS]' }, { bssid: 'f0:9f:c2:00:aa:01', caps: '[WPA2-PSK-CCMP][ESS]' }] };
async function watch() {
  const b = $('#watch-run'); b.disabled = true; b.textContent = 'Scanning…';
  const out = [];
  try {
    const [net, wifi] = Check ? await Promise.all([Check.network().catch(() => null), Check.wifi().catch(() => null)]) : [EX_NET, EX_WIFI];
    if (net && !net.noTelephony) {
      const r = analyzeCells(net, store.get('base.cells', {})); store.set('base.cells', r.base); out.push(...r.findings);
      record('cells', { operator: net.operator, data: net.data, cells: (net.cells || []).map((c) => ({ registered: c.registered, gen: c.gen, cell: c.cell, area: c.area, dbm: c.dbm })) });
    }
    if (wifi) {
      const r = analyzeWifi(wifi, store.get('base.wifi', {})); store.set('base.wifi', r.base); out.push(...r.findings);
      record('wifi', { ssid: wifi.ssid, bssid: wifi.bssid, gateway: wifi.gateway, dns: wifi.dns, rssi: wifi.rssi, security: wifi.security, proxy: wifi.proxy, sameName: (wifi.sameName || []).length });
    }
    if (!out.some((f) => f.lv >= 2)) out.push({ lv: 1, title: 'Nothing unusual', text: 'Your towers, Wi-Fi access point, router and DNS look the way they normally do.' });
    out.filter((f) => f.lv >= 3).forEach((f) => raise(f.lv, f.title, f.text, 'network'));
    $('#watch-find').innerHTML = out.sort((x, y) => y.lv - x.lv).map((f) => li(f.lv, f.title, f.text)).join('');
    $('#watch-when').textContent = `${Check ? 'Scanned' : 'Example scan (install on Android for real readings)'} · ${new Date().toLocaleString()}`;
  } catch (e) { toast(`Couldn’t scan: ${e.message || e}`); }
  finally { b.disabled = false; b.textContent = 'Scan networks now'; }
}
$('#watch-run').addEventListener('click', watch);
$('#arp-run').addEventListener('click', () => {
  const F = analyzeArp($('#arp').value, $('#gw').value.trim());
  $('#arp-find').innerHTML = F.map((f) => li(f.lv, f.title, f.text)).join('');
  F.filter((f) => f.lv >= 3).forEach((f) => raise(f.lv, f.title, f.text, 'arp'));
});
$('#arp').value = 'Interface: 192.168.1.23 --- 0x7\n  192.168.1.1           a4-2b-b0-11-22-33     dynamic\n  192.168.1.40          a4-2b-b0-11-22-33     dynamic\n  192.168.1.52          3c-22-fb-90-aa-01     dynamic';
const fpNorm = (s) => s.replace(/[^0-9a-f]/gi, '').toLowerCase();
$('#pin-save').addEventListener('click', () => {
  const h = $('#pin-host').value.trim().toLowerCase(), f = fpNorm($('#pin-fp').value);
  if (!h || f.length !== 64) { $('#pin-find').innerHTML = li(2, 'Incomplete', 'Enter a site and its full 64-character SHA-256 fingerprint.'); return; }
  const pins = store.get('pins', {}); pins[h] = f; store.set('pins', pins); $('#pin-find').innerHTML = li(1, `Pinned ${h}`, 'Compare again whenever you join a new network.');
});
$('#pin-check').addEventListener('click', () => {
  const h = $('#pin-host').value.trim().toLowerCase(), f = fpNorm($('#pin-fp').value), pins = store.get('pins', {});
  let r;
  if (!pins[h]) r = [2, 'No pin yet', `Nothing pinned for ${h || 'that site'}.`];
  else if (f.length !== 64) r = [2, 'Incomplete', 'Paste a full SHA-256 fingerprint to compare.'];
  else if (pins[h] === f) r = [1, 'Match', `The certificate for ${h} is the one you pinned — no interception on this connection.`];
  else { r = [3, `Certificate mismatch: ${h}`, 'Either the site renewed its certificate or someone is intercepting. Check the issuer; if unsure, switch to mobile data.']; raise(3, r[1], r[2], 'pinning'); }
  $('#pin-find').innerHTML = li(...r);
});

// ---------- ARTEX Shield ----------
function axShow(text, label) {
  const fi = currentIntel();
  const r = analyzeLogs(text, { extraIps: fi?.badIps || {}, extraUAs: fi?.userAgents || [] });
  $('#ax-find').innerHTML = r.findings.map((f) => li(f.lv, f.title, f.text)).join('');
  $('#ax-stats').textContent = `${label}: ${r.stats.lines.toLocaleString()} lines, ${r.stats.ips} addresses.`;
  r.findings.filter((f) => f.lv >= 3).forEach((f) => raise(f.lv, f.title, f.text, 'artex'));
  record('scans', { kind: 'artex', lines: r.stats.lines, hits: r.findings.filter((f) => f.lv >= 3).length }, 500);
}
$('#ax-run').addEventListener('click', async () => {
  const files = [...($('#ax-file').files || [])];
  if (files.length) { const parts = await Promise.all(files.map((f) => f.text())); axShow(parts.join('\n'), `${files.length} file${files.length > 1 ? 's' : ''}`); return; }
  if (!$('#ax-log').value.trim()) return toast('Paste logs or choose a file first.');
  axShow($('#ax-log').value, 'Pasted logs');
});
$('#ax-sample').addEventListener('click', () => {
  // Synthetic sample (documentation addresses): agent rhythm, Norma user agent, password spraying.
  const L = []; const fmt = (t) => new Date(t).toISOString(); let t = Date.UTC(2026, 10, 20, 10, 0, 0);
  for (let c = 0; c < 6; c++) { for (let k = 0; k < 4; k++) { L.push(JSON.stringify({ time: fmt(t), ip: '198.51.100.77', method: 'GET', path: '/api/v1/users/' + (c * 4 + k), status: 200, user_agent: 'Go-http-client/2.0' })); t += 800; } t += 27500; }
  L.push(JSON.stringify({ time: fmt(t), ip: '198.51.100.77', path: '/.git/config', status: 404, user_agent: 'norma/0.4' }));
  ['/static/main.js.map', '/.env', '/config.json', '/actuator/env'].forEach((p, i) => L.push(JSON.stringify({ time: fmt(t + 1000 + i * 300), ip: '198.51.100.77', path: p, status: 404, user_agent: ['curl/8.4', 'python-requests/2.31', 'Go-http-client/1.1', 'curl/8.4'][i] })));
  L.push(JSON.stringify({ time: fmt(t + 5000), ip: '10.0.0.5', method: 'GET', url: 'https://webhook.site/7f3c', status: 200 }));
  for (let i = 0; i < 60; i++) L.push(JSON.stringify({ time: fmt(t + i * 400), ip: '192.0.2.50', path: '/oauth/token', status: 401, userPrincipalName: `staff${i % 25}@example.com` }));
  $('#ax-log').value = L.join('\n'); $('#ax-file').value = ''; axShow($('#ax-log').value, 'Sample (synthetic)');
});
$('#sec-run').addEventListener('click', () => {
  const s = findSecrets($('#sec-in').value);
  $('#sec-find').innerHTML = s.length ? s.map((x) => li(4, `${x.kind} on line ${x.line}`, `${x.preview} — remove it, then rotate (replace) it with the provider; deleting the commit is not enough.`)).join('') : li(1, 'No secrets found', 'Nothing matched the known key and token formats.');
  if (s.length) raise(4, `${s.length} leaked secret${s.length > 1 ? 's' : ''} found`, s.map((x) => x.kind).join(', '), 'secrets');
});
$('#ax-ioc-info').textContent = `Indicators from public threat reports up to ${ARTEX_IOCS.updated}: ${Object.keys(ARTEX_IOCS.ips).length} addresses, ${ARTEX_IOCS.ja4.length} TLS fingerprints, ${ARTEX_IOCS.dockerImages.length} booby-trapped Docker images and the ARTEX console port ${ARTEX_IOCS.consolePort}. Attackers change servers often, so a match is a lead, not proof.`;
$('#ax-ioc-copy').addEventListener('click', () => copy([
  `# ARTEX indicators (BlackSwan, ${ARTEX_IOCS.updated})`, '# IP addresses', ...Object.entries(ARTEX_IOCS.ips).map(([ip, w]) => `${ip}  # ${w}`),
  '# User agents', 'artex-enrich/1.0', 'norma/0.4', 'Mozilla/5.0 (compatible; ArtEx/1.0)', 'Mozilla/5.0 (compatible; infra-hunt/1.0)', 'verify-911-probe/1.0', 'artex-pentest/1.0',
  '# JA4 TLS fingerprints', ...ARTEX_IOCS.ja4, '# Docker images (backdoored)', ...ARTEX_IOCS.dockerImages, `# SHA-256 of backdoored /app/artex`, ARTEX_IOCS.binarySha256, `# Console port`, String(ARTEX_IOCS.consolePort), '# Host artifacts', 'C:\\ProgramData\\artx5v\\  and  artx* files in temp folders', '# Callback / tunnel services to block outbound from servers', ...ARTEX_IOCS.callbacks].join('\n'), 'Indicators copied.'));

// ---------- password generator ----------
let current = '', retired = 0, rotTimer = null, nextAt = 0;
const opts = () => ({ upper: $('#o-u').checked, lower: $('#o-l').checked, digits: $('#o-d').checked, symbols: $('#o-s').checked, noLookalikes: $('#o-a').checked });
function newPw() {
  const g = generatePassword(parseInt($('#len').value, 10), opts());
  if (current) retired++;
  current = g.password; $('#pw').textContent = g.password;
  const bar = $('#pw-bar'); bar.style.width = Math.min(100, g.bits / 1.28) + '%'; bar.style.background = g.bits >= 80 ? 'var(--ok)' : g.bits >= 60 ? 'var(--warn)' : 'var(--risk)';
  $('#pw-info').textContent = `${Math.round(g.bits)} bits of entropy from ${g.pool} possible characters. Brute force at 100 billion guesses a second would take about ${crackTime(g.bits)}.`;
}
function setRot() {
  clearInterval(rotTimer); let m = +$('#rot').value;
  if (m && !can('plus')) { m = 0; $('#rot').value = '0'; toast('Automatic new passwords are part of BlackSwan Plus.'); } store.set('rot', m);
  if (!m) { $('#rot-info').textContent = retired ? `${retired} retired this session (never stored).` : 'Generated with your device’s cryptographic random generator. Never stored or sent.'; return; }
  nextAt = Date.now() + m * 60e3;
  const tick = () => { if (Date.now() >= nextAt) { newPw(); nextAt = Date.now() + m * 60e3; } const s = Math.ceil((nextAt - Date.now()) / 1000); $('#rot-info').textContent = `Next new password in ${s >= 3600 ? Math.ceil(s / 3600) + ' h' : s >= 60 ? Math.ceil(s / 60) + ' min' : s + ' s'} · ${retired} retired (never stored).`; };
  tick(); rotTimer = setInterval(tick, 1000);
}
$('#gen').addEventListener('click', newPw);
$('#pw-copy').addEventListener('click', () => copy(current, 'Password copied. Clear your clipboard after pasting it.'));
['#o-u', '#o-l', '#o-d', '#o-s', '#o-a', '#len'].forEach((id) => $(id).addEventListener('change', newPw));
$('#rot').value = String(store.get('rot', 0)); $('#rot').addEventListener('change', setRot);
newPw(); setRot();

// ---------- fingerprint (native on the phone, WebAuthn in a browser) ----------
const b64 = (b) => btoa(String.fromCharCode(...new Uint8Array(b)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const rnd = (n) => crypto.getRandomValues(new Uint8Array(n));
async function bioAvailable() {
  if (Bio) { const r = await Bio.isAvailable({ useFallback: false }).catch(() => ({ isAvailable: false })); return r.isAvailable; }
  return !!(window.PublicKeyCredential && (await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable?.().catch(() => false)));
}
/** Resolves true only after the phone’s sensor confirms the owner. */
async function fingerprint(reason = 'Confirm it’s you') {
  if (Bio) { try { await Bio.verifyIdentity({ reason, title: 'BlackSwan', subtitle: reason, description: '', useFallback: false, maxAttempts: 3 }); return true; } catch { return false; } }
  const id = store.get('webauthn', null); if (!id) return false;
  try {
    const a = await navigator.credentials.get({ publicKey: { challenge: rnd(32), allowCredentials: [{ type: 'public-key', id: unb64(id) }], userVerification: 'required', timeout: 60000 } });
    return (new Uint8Array(a.response.authenticatorData)[32] & 0x04) !== 0; // UV flag: the sensor checked the user
  } catch (e) { $('#fp-info').textContent = fpErr(e); return false; }
}
function fpErr(e) { return e?.name === 'SecurityError' || e?.name === 'NotAllowedError' ? 'This browser view blocks the fingerprint prompt. Install the BlackSwan app, or open the page from your own HTTPS address.' : `Fingerprint unavailable: ${e?.message || e}`; }
async function fpEnrol() {
  if (!(await bioAvailable())) { $('#fp-info').textContent = 'No fingerprint or face sensor is set up on this device. Add one in your phone’s security settings first.'; return; }
  if (Bio) { if (await fingerprint('Turn on fingerprint for BlackSwan')) { store.set('fp', true); gateUI('Fingerprint is on. Unlocking now needs your passphrase and your fingerprint.'); } return; }
  try {
    const c = await navigator.credentials.create({ publicKey: { challenge: rnd(32), rp: { name: 'BlackSwan' }, user: { id: rnd(16), name: 'blackswan', displayName: 'BlackSwan' },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }], authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'preferred' }, timeout: 60000, attestation: 'none' } });
    store.set('webauthn', b64(c.rawId)); store.set('fp', true); gateUI('Fingerprint is on. Unlocking now needs your passphrase and your fingerprint.');
  } catch (e) { $('#fp-info').textContent = fpErr(e); }
}
$('#fp-enrol').addEventListener('click', fpEnrol);
$('#fp-test').addEventListener('click', async () => { if (!store.get('fp', false)) return toast('Turn on fingerprint first.'); toast((await fingerprint('Test your fingerprint')) ? 'Fingerprint confirmed ✓' : 'Fingerprint not confirmed.'); });
$('#fp-off').addEventListener('click', () => { store.set('fp', false); store.del('webauthn'); gateUI('Fingerprint turned off for BlackSwan.'); });

// ---------- fingerprint vault ----------
const VAULT = 'bb.blackswan.vault.';
function renderVault() {
  const v = store.get('vault', []);
  $('#vault-list').innerHTML = v.length ? v.map((x, i) => `<li class="finding ok"><div><strong>${esc(x.label)}</strong><p>Saved ${esc(new Date(x.t).toLocaleDateString())}</p><div class="row"><button class="btn sm" data-reveal="${i}" type="button">Show</button><button class="btn sm" data-del="${i}" type="button">Delete</button></div><p class="mono" id="vault-${i}"></p></div></li>`).join('') : '<li class="muted small">Nothing saved yet.</li>';
}
$('#vault-save').addEventListener('click', async () => {
  if (!Bio) return toast('The fingerprint vault needs the BlackSwan app on Android or iPhone.');
  const label = $('#vault-label').value.trim() || 'Password'; const id = Date.now().toString(36);
  if (!(await fingerprint('Save a password behind your fingerprint'))) return toast('Fingerprint not confirmed. Nothing saved.');
  try { await Bio.setCredentials({ username: label, password: current, server: VAULT + id }); const v = store.get('vault', []); v.unshift({ id, label, t: Date.now() }); store.set('vault', v); renderVault(); toast(`Saved “${label}” in secure hardware.`); }
  catch (e) { toast(`Couldn’t save: ${e.message || e}`); }
});
$('#vault-list').addEventListener('click', async (e) => {
  const r = e.target.closest('[data-reveal]'), d = e.target.closest('[data-del]'); const v = store.get('vault', []);
  if (r) { const x = v[+r.dataset.reveal]; if (!(await fingerprint(`Show ${x.label}`))) return toast('Fingerprint not confirmed.');
    try { const c = await Bio.getCredentials({ server: VAULT + x.id }); const p = $('#vault-' + r.dataset.reveal); p.textContent = c.password; setTimeout(() => { p.textContent = ''; }, 20000); } catch (err) { toast(`Couldn’t read it: ${err.message || err}`); } }
  if (d) { const x = v[+d.dataset.del]; try { await Bio?.deleteCredentials({ server: VAULT + x.id }); } catch { /* already gone */ } v.splice(+d.dataset.del, 1); store.set('vault', v); renderVault(); }
});
async function wipeVault() { for (const x of store.get('vault', [])) { try { await Bio?.deleteCredentials({ server: VAULT + x.id }); } catch { /* fine */ } } store.set('vault', []); renderVault(); }

// ---------- anti brute-force lock ----------
const NORMAL_FAILS_PER_HOUR = 0.5; // honest typos; tune with matlab/bs_bruteforce_model.m
let gate = store.get('gate', { fails: 0, lockUntil: 0 });
async function kdf(pass, salt) { const k = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveBits']); return b64(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 310000, hash: 'SHA-256' }, k, 256)); }
const same = (a, b) => { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; };
let lockTick = null;
function gateUI(msg) {
  clearInterval(lockTick);
  const st = $('#gate-state');
  if (!gate.hash) { st.textContent = 'Not set up'; st.style.color = ''; }
  else if (gate.lockUntil > Date.now()) { st.style.color = 'var(--risk)'; const t = () => { const l = Math.ceil((gate.lockUntil - Date.now()) / 1000); if (l <= 0) { clearInterval(lockTick); gateUI(); } else { st.textContent = `Locked — wait ${l} s`; $('#lock-info').textContent = `Too many wrong tries. Wait ${l} s.`; } }; t(); lockTick = setInterval(t, 1000); }
  else { st.textContent = 'Passphrase set'; st.style.color = ''; }
  if (msg) $('#gate-info').textContent = msg;
  $('#fp-info').textContent = store.get('fp', false) ? 'Fingerprint is on: it is required after the passphrase and to open the vault.' : 'Off. Uses your phone’s own fingerprint or face sensor; BlackSwan never sees your fingerprint.';
  $('#g-applock').checked = !!gate.appLock; $('#g-wipe').checked = !!gate.wipe;
}
$('#g-use').addEventListener('click', () => { $('#g-pass').type = 'text'; $('#g-pass').value = current; });
$('#g-set').addEventListener('click', async () => {
  const p = $('#g-pass').value; if (p.length < 12) return gateUI('Use at least 12 characters — a generated 15-character password is ideal.');
  const salt = rnd(16); gate = { ...gate, salt: b64(salt), hash: await kdf(p, salt), fails: 0, lockUntil: 0 }; store.set('gate', gate);
  $('#g-pass').value = ''; $('#g-pass').type = 'password'; gateUI('Passphrase set. It is stretched with PBKDF2 (310,000 rounds) so a stolen copy is slow to crack.');
});
$('#g-applock').addEventListener('change', (e) => { if (!gate.hash) { e.target.checked = false; return toast('Set a passphrase first.'); } gate.appLock = e.target.checked; store.set('gate', gate); });
$('#g-wipe').addEventListener('change', (e) => { gate.wipe = e.target.checked; store.set('gate', gate); });
/** Checks a passphrase (and fingerprint, if on). Applies lockouts, Poisson attack test and the optional vault wipe. */
async function tryUnlock(pass) {
  if (!gate.hash) return { ok: false, msg: 'Set a passphrase first.' };
  if (gate.lockUntil > Date.now()) return { ok: false, msg: 'Still locked. Each extra failure doubles the wait.' };
  const good = same(await kdf(pass, unb64(gate.salt)), gate.hash);
  record('unlocks', { ok: good }, 2000);
  if (!good) {
    gate.fails++; let msg = `Wrong passphrase (${gate.fails} in a row).`;
    if (gate.fails >= 3) { const wait = Math.min(3600, 30 * 2 ** (gate.fails - 3)); gate.lockUntil = Date.now() + wait * 1000; msg += ` Locked for ${wait} s.`; }
    const lastHour = store.get('h.unlocks', []).filter((u) => !u.ok && Date.now() - u.t < 3600e3).length;
    const p = poissonTail(lastHour, NORMAL_FAILS_PER_HOUR);
    if (p < 0.001) raise(4, 'Brute-force attack on BlackSwan lock', `${lastHour} failures in the last hour; chance of that from normal typos is ${p.toExponential(1)}.`, 'guard');
    else if (gate.fails >= 3) raise(3, 'Repeated wrong passphrase', `${gate.fails} failures in a row.`, 'guard');
    if (gate.wipe && gate.fails >= 10) { await wipeVault(); raise(4, 'Vault erased after 10 failed unlocks', 'Self-destruct setting was on.', 'guard'); msg += ' Vault erased.'; }
    store.set('gate', gate); return { ok: false, msg };
  }
  if (store.get('fp', false) && !(await fingerprint('Unlock BlackSwan'))) { raise(3, 'Right passphrase, wrong or no fingerprint', 'Someone may know your passphrase.', 'guard'); return { ok: false, msg: 'Passphrase right, but the fingerprint wasn’t confirmed. Access denied.' }; }
  gate.fails = 0; gate.lockUntil = 0; store.set('gate', gate); return { ok: true, msg: store.get('fp', false) ? 'Unlocked with passphrase + fingerprint.' : 'Unlocked. Turn on fingerprint to add a second factor.' };
}
$('#g-try').addEventListener('click', async () => { const r = await tryUnlock($('#g-pass').value); $('#g-pass').value = ''; gateUI(r.msg); if (r.ok) { $('#gate-state').textContent = 'Unlocked ✓'; $('#gate-state').style.color = 'var(--ok)'; } });
// Lock screen when the app opens.
async function lockGo() { const r = await tryUnlock($('#lock-pass').value); $('#lock-pass').value = ''; $('#lock-info').textContent = r.msg; if (r.ok) $('#lock').hidden = true; gateUI(); }
$('#lock-go').addEventListener('click', lockGo);
$('#lock-pass').addEventListener('keydown', (e) => { if (e.key === 'Enter') lockGo(); });
if (gate.appLock && gate.hash) { $('#lock').hidden = false; $('#lock-pass').focus(); }
gateUI(); renderVault();

// ---------- scam library ----------
function renderScams() {
  const q = $('#scam-q').value.toLowerCase().trim();
  const rows = SCAMS.filter((s) => !q || s.join(' ').toLowerCase().includes(q));
  $('#scam-list').innerHTML = rows.length ? rows.map((s) => `<section class="card"><h3>${esc(s[0])}</h3><p>${esc(s[1])}</p><p><b>Red flags:</b> ${esc(s[2])}</p><p><b>Defence:</b> ${esc(s[3])}</p></section>`).join('') : '<p class="muted">No scams match that search.</p>';
}
$('#scam-q').addEventListener('input', renderScams); renderScams();

// ---------- alerts ----------
function renderAlerts() {
  const list = alerts(); const hi = list.filter((a) => a.level >= 3).length;
  $('#al-count').textContent = hi ? String(hi) : '';
  $('#al-list').innerHTML = list.length ? list.map((a) => li(a.level, `${LBL[a.level]}: ${a.title}${a.count > 1 ? ` (×${a.count})` : ''}`, `${new Date(a.t).toLocaleString()}${a.source ? ' · ' + a.source : ''}${a.detail ? ' · ' + a.detail : ''}`)).join('') : '<li class="muted small">No alerts yet. Anything dangerous BlackSwan finds is logged here.</li>';
}
onAlert(renderAlerts); renderAlerts();
$('#al-clear').addEventListener('click', clearAlerts);
$('#al-export').addEventListener('click', () => {
  if (!can('business')) { toast('Export for MATLAB and security teams is part of BlackSwan Business.'); return show('plans'); }
  const json = JSON.stringify(exportAll({ weights: currentWeights().url }), null, 1);
  const t = $('#al-json'); t.hidden = false; t.value = json;
  copy(json, 'Export copied. Save it as blackswan_export.json for MATLAB.');
});

// ---------- desktop agent ----------
let agent = '';
fetch('agent/blackswan_agent.py').then((r) => (r.ok ? r : fetch('agent/blackswan_agent.py.txt'))).then((r) => (r.ok ? r.text() : '')).then((t) => { agent = t; $('#ag-src').textContent = t || 'The agent file is in the repository at www/agent/blackswan_agent.py.'; }).catch(() => {});
$('#ag-copy').addEventListener('click', () => (agent ? copy(agent, 'Script copied. Save it as blackswan_agent.py.') : toast('Script not loaded.')));

// ---------- threat posture, sound and colour ----------
startPosture();
$('#set-sound').checked = store.get('sound', true); $('#set-flash').checked = store.get('flash', true);
$('#set-sound').addEventListener('change', (e) => store.set('sound', e.target.checked));
$('#set-flash').addEventListener('change', (e) => store.set('flash', e.target.checked));
let testTimer = null;
document.querySelectorAll('[data-test]').forEach((b) => b.addEventListener('click', () => {
  const lv = b.dataset.test; clearTimeout(testTimer);
  const s = store.get('sound', true); store.set('sound', true); playLevel(lv); store.set('sound', s);
  paint(lv, { flash: lv !== 'green' }); testTimer = setTimeout(() => paint(postureOf()), 4000);
}));

// ---------- daily global briefing ----------
const LVW = { 1: 'ok', 2: 'warn', 3: 'risk', 4: 'risk crit' };
function renderIntel(f) {
  if (!f) { $('#intel-when').textContent = 'No threat feed yet. Connect to the internet and tap “Check now”.'; return; }
  const when = new Date(f.updated);
  $('#intel-when').textContent = `Feed of ${when.toLocaleString()} (${f.from}${f.error ? `; latest check failed: ${f.error}` : ''}). ${(f.phishDomains || []).length.toLocaleString()} live phishing sites, ${Object.keys(f.badIps || {}).length.toLocaleString()} malicious servers and ${(f.watch || []).length} watched attackers are now part of every scan.`;
  $('#intel-warn').innerHTML = (f.warnings || []).length ? f.warnings.map((w) => `<li class="finding ${LVW[w.level] || 'warn'}"><div><strong>${esc(w.title)}</strong><p>${esc(w.date)}${w.actor ? ' · ' + esc(w.actor) : ''}${w.text ? ' — ' + esc(w.text) : ''}</p>${/^https:\/\//.test(w.source || '') ? `<p><a href="${esc(w.source)}" target="_blank" rel="noopener">Source</a></p>` : w.source ? `<p>${esc(w.source)}</p>` : ''}</div></li>`).join('') : li(1, 'No new global warnings', 'Nothing new in the last two weeks.');
  $('#intel-kev').innerHTML = (f.kev || []).slice(0, 15).map((v) => li(v.ransomware ? 3 : 2, `${v.vendor} ${v.product} — ${v.cve}`, `${v.name}. Added ${v.added}.${v.ransomware ? ' Used by ransomware gangs.' : ''}`)).join('') || li(1, 'No list yet', 'The software-holes list loads with the next daily feed.');
  $('#intel-actors').innerHTML = (f.actors || []).slice(0, 12).map((a) => `<li class="finding warn"><div><strong>${esc(a.name)}</strong><p>Updated ${esc(a.modified)}${a.aliases?.length ? ' · also called ' + esc(a.aliases.slice(0, 4).join(', ')) : ''}. ${esc(a.summary)}</p>${a.url ? `<p><a href="${esc(a.url)}" target="_blank" rel="noopener">MITRE profile</a></p>` : ''}</div></li>`).join('') || li(1, 'No list yet', 'Loads with the next daily feed.');
  $('#intel-src').innerHTML = (f.sources || []).map((x) => li(x.ok ? 1 : 2, `${x.name}${x.ok ? ` · ${x.count}` : ''}`, x.ok ? '' : `Unavailable on the last run: ${x.error}`)).join('');
}
async function intel(force) { const b = $('#intel-run'); b.disabled = true; b.textContent = 'Checking…'; try { renderIntel(await refreshIntel(force)); } finally { b.disabled = false; b.textContent = 'Check now'; } }
$('#intel-run').addEventListener('click', () => intel(true));
intel(false);
// Re-check whenever the app comes back to the screen (at most once every 20 hours).
document.addEventListener('visibilitychange', () => { if (!document.hidden) intel(false); });
// A daily 8 am reminder to open the briefing (phones only).
if (Notes) {
  Notes.schedule({ notifications: [{ id: 800, title: 'BlackSwan daily threat briefing', body: 'New global warnings and threat actors are checked every day. Open BlackSwan to see today’s.', schedule: { on: { hour: 8, minute: 0 }, allowWhileIdle: true } }] }).catch(() => {});
}

// ---------- safety tip of the day ----------
const DAILY_TIPS = [
  'Type your bank’s address yourself or use a bookmark — never follow a link in a message to log in.',
  'Nobody genuine will ask for the code that was just texted to you. Not your bank, not support, not a friend.',
  'If a caller asks you to install AnyDesk, TeamViewer or any “support” app, hang up.',
  'A web page telling you to press Win + R and paste something is an attack, every time.',
  'Gift cards are for gifts. Anyone demanding payment in gift cards is a scammer.',
  'Turn on automatic updates on your phone, computer and apps — most attacks use holes that are already fixed.',
  'Use a different password for every account; let BlackSwan make them and a password manager remember them.',
  'Switch to passkeys where offered: they can’t be phished because they only work on the real website.',
  'On public Wi-Fi, use mobile data or a VPN you trust for banking and email.',
  'Ask your mobile carrier for a PIN on your account to stop SIM-swap fraud.',
  'Restart your phone daily: it clears spyware that lives only in memory.',
  'Check “Devices” in your Google, Apple and Microsoft accounts and remove any you don’t recognise.',
  'A change of bank details by email is always checked by phone, on a number you already have.',
  'Never install a certificate or “profile” someone sends you — it lets them read your secure traffic.',
  'Turn off “Allow 2G” on Android: fake mobile towers force phones down to 2G.',
  'Developers: never put keys or passwords in code. If one leaked, replace it — deleting the commit is not enough.',
  'Scan QR codes with care: the link is hidden until you open it. Check it in BlackSwan first.',
  'Urgency is a red flag. Real banks and governments give you time to check.',
  'Keep your recovery phrase for crypto offline. Anyone asking for it is stealing.',
  'Lock your SIM with a PIN so a stolen SIM can’t be used to receive your codes.',
  'Before you click “Allow” for an app to access your account, check who made it.',
  'If you approved a sign-in prompt you didn’t start, change your password straight away.',
  'Business owners: rate-limit login pages — AI attack tools guess thousands of passwords a minute.',
  'Keep test and live systems on different passwords; attackers walk from one to the other.',
  'Download software only from the maker’s own site or the official app store, not from ads.',
  'Show file extensions on your computer so invoice.pdf.exe can’t hide.',
  'Back up your important files offline; ransomware can’t encrypt what it can’t reach.',
  'Use Airplane mode in sensitive meetings: it stops the phone’s radio talking to any tower.',
  'Turn on Advanced Protection (Android) or Lockdown Mode (iPhone) if you could be targeted.',
  'When in doubt, stop. Call the company on the number from its official website or your card.',
];
{ const d = Math.floor(Date.now() / 86400e3); $('#tipday').textContent = `Today’s tip: ${DAILY_TIPS[d % DAILY_TIPS.length]}`; }

// ---------- QR codes: read the hidden link from a photo, then scan it ----------
$('#qr-in').addEventListener('change', async (e) => {
  const f = e.target.files?.[0]; e.target.value = '';
  if (!f) return;
  if (!window.jsQR) return toast('QR reader not loaded.');
  try {
    const bmp = await createImageBitmap(f);
    const scale = Math.min(1, 1600 / Math.max(bmp.width, bmp.height));
    const c = document.createElement('canvas'); c.width = Math.round(bmp.width * scale); c.height = Math.round(bmp.height * scale);
    const ctx = c.getContext('2d'); ctx.drawImage(bmp, 0, 0, c.width, c.height);
    const img = ctx.getImageData(0, 0, c.width, c.height);
    const code = window.jsQR(img.data, img.width, img.height, { inversionAttempts: 'attemptBoth' });
    if (!code?.data) { $('#qr-info').textContent = 'No QR code found in that photo. Try again closer and in good light.'; return; }
    $('#qr-info').textContent = `The QR code contains: ${code.data.slice(0, 200)}`;
    if (/^(https?:|www\.)/i.test(code.data) || /^[a-z0-9-]+(\.[a-z0-9-]+)+(\/|$)/i.test(code.data)) { $('#url').value = code.data; scanUrl(); }
    else { $('#msg').value = code.data; show('msg'); scanMsg(); }
  } catch (err) { toast(`Couldn’t read the photo: ${err.message || err}`); }
});

// ---------- Share → BlackSwan (Android) ----------
async function takeShared() {
  if (!Check?.sharedText) return;
  try {
    const { text } = await Check.sharedText();
    if (!text) return;
    const t = text.trim();
    if (/^\S+$/.test(t) && /^(https?:\/\/|www\.)/i.test(t)) { show('links'); $('#url').value = t; scanUrl(); }
    else { show('msg'); $('#msg').value = t; scanMsg(); }
  } catch { /* nothing shared */ }
}
takeShared();
document.addEventListener('visibilitychange', () => { if (!document.hidden) takeShared(); });

// ---------- Real-time scam guard (Android notification access) ----------
async function guardStatus() {
  if (!Check?.scamGuardStatus) { $('#sg-state').textContent = platform === 'ios' ? 'Not available on iPhone' : 'Available in the Android app'; $('#sg-on').hidden = true; return; }
  const { enabled } = await Check.scamGuardStatus().catch(() => ({ enabled: false }));
  $('#sg-state').textContent = enabled ? 'On — watching new messages' : 'Off';
  $('#sg-state').style.color = enabled ? 'var(--ok)' : '';
  $('#sg-on').textContent = enabled ? 'Scam guard settings' : 'Turn on scam guard';
  const { items = [] } = await Check.pendingThreats().catch(() => ({}));
  const seen = store.get('sg.log', []);
  for (const it of items) {
    raise(4, `Scam message in ${it.app}`, `${(it.reasons || []).join('; ')}`, 'scam guard');
    seen.unshift({ t: it.t, app: it.app, reasons: it.reasons, urls: it.urls });
  }
  store.set('sg.log', seen.slice(0, 30));
  $('#sg-list').innerHTML = seen.length ? seen.map((x) => li(4, `${x.app} · ${new Date(x.t).toLocaleString()}`, `${(x.reasons || []).join('; ')}${x.urls?.length ? ` · links: ${x.urls.slice(0, 3).join(', ')}` : ''}`)).join('') : '<li class="muted small">No scam messages caught yet.</li>';
}
$('#sg-on').addEventListener('click', () => { Check?.openScamGuardSettings?.(); toast('Find BlackSwan in the list and allow it, then come back.'); });
guardStatus();
document.addEventListener('visibilitychange', () => { if (!document.hidden) guardStatus(); });
// Give the guard today's phishing list so it works while BlackSwan is closed.
window.addEventListener('bs-intel', () => { const f = currentIntel(); if (Check?.setBlocklist && f?.phishDomains?.length) Check.setBlocklist({ domains: f.phishDomains.slice(0, 60000) }).catch(() => {}); });

// ---------- Leaked-password check (Have I Been Pwned, k-anonymity) ----------
async function pwned(pw) {
  const h = [...new Uint8Array(await crypto.subtle.digest('SHA-1', new TextEncoder().encode(pw)))].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  const r = await fetch(`https://api.pwnedpasswords.com/range/${h.slice(0, 5)}`, { headers: { 'Add-Padding': 'true' } });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const line = (await r.text()).split('\n').find((l) => l.startsWith(h.slice(5)));
  return line ? Number(line.split(':')[1]) || 0 : 0;
}
async function pwnCheck(pw) {
  if (!pw) return toast('Type a password first.');
  $('#pwn-out').innerHTML = li(1, 'Checking…', '');
  try {
    const n = await pwned(pw);
    $('#pwn-out').innerHTML = n > 0 ? li(4, `Leaked ${n.toLocaleString()} time${n > 1 ? 's' : ''}`, 'This password is in criminals’ lists and will be tried first in any attack. Stop using it everywhere and change it now.') : li(1, 'Not found in any known breach', 'Good. Keep it unique to one account.');
    if (n > 0) raise(3, 'Leaked password in use', `Found ${n} times in breach data`, 'guard');
  } catch (e) { $('#pwn-out').innerHTML = li(2, 'Couldn’t check right now', `${e.message || e}. Check your internet connection (the web preview blocks this; the apps can check).`); }
  $('#pwn-in').value = '';
}
$('#pwn-run').addEventListener('click', () => pwnCheck($('#pwn-in').value));
$('#pwn-cur').addEventListener('click', () => pwnCheck(current));

// ---------- Scam recovery assistant ----------
const RECOVER = {
  money: ['Call your bank or card company now on the number on your card or official website — not any number the scammer gave you. Ask them to stop or recall the payment and freeze the account.', 'Write down everything: amounts, times, account numbers, names, phone numbers, website addresses. Take screenshots before the scammer deletes chats.', 'Report it to the police or your country’s cybercrime or fraud reporting service; banks often need a report number.', 'Expect “recovery” offers: anyone promising to get your money back for a fee is a second scam.', 'Change any passwords you shared, and watch your statements for the next few months.'],
  card: ['Block or freeze the card now in your banking app, or call the number on the back of the card.', 'Ask for a new card number and to cancel any pending payments you don’t recognise.', 'Check recent transactions and dispute any you didn’t make.', 'If you also typed a password, follow “I typed a password on a fake site”.'],
  password: ['From a device you trust, change that password now — and on every other account that used the same password.', 'Turn on two-step sign-in (an authenticator app or passkey, not SMS if you can avoid it).', 'Sign out all other sessions in the account’s security settings and check recovery email and phone number haven’t been changed.', 'Check the account’s mail rules or forwarding (attackers add them to keep reading your email).', 'Use BlackSwan’s leaked-password check and generator to pick a new unique password.'],
  code: ['Change the password of the account the code was for, straight away, from a device you trust.', 'Sign out all other devices and sessions in that account’s security settings.', 'If it was a bank or payment code, call your bank now on the official number and ask them to block the transaction.', 'If it was a WhatsApp or Telegram code, re-register on your phone and turn on two-step verification (a PIN).'],
  remote: ['Disconnect from the internet now (turn off Wi-Fi, unplug the cable, or switch on Airplane mode).', 'Uninstall the remote-control app they had you install (AnyDesk, TeamViewer, ScreenConnect, etc.).', 'From a different, trusted device, change your email and banking passwords and call your bank.', 'Run a full scan with a reputable security product, or have the computer checked/reinstalled by someone you trust — they may have left other software behind.', 'Run the BlackSwan desktop checker, which looks for remote-access tools still running.'],
  giftcrypto: ['Contact the gift-card company straight away with the card numbers and receipts — some can freeze unused balances.', 'For crypto, contact the exchange you sent from and report the receiving wallet address; transfers can rarely be reversed, but exchanges can flag the scammer.', 'Report to the police or your country’s fraud service with all details and screenshots.', 'Beware of “recovery agents” who contact you afterwards — they are scammers too.'],
  sim: ['From another phone, call your mobile carrier immediately: say you suspect a SIM swap or number transfer and ask them to stop it and lock your account with a PIN.', 'Change your email password first (it resets everything else), then banking and social accounts.', 'Call your bank: codes sent by text may now be going to the criminal.', 'Move important accounts from text-message codes to an authenticator app or passkey.'],
  spy: ['If you feel unsafe, think before removing anything: the person may notice. Reach out to a local support service or someone you trust first.', 'Run BlackSwan’s Phone check: it lists apps with powerful access and matches known spy apps.', 'Change your Google / Apple / Microsoft account password from a device the other person has never touched, and remove unknown devices from the account.', 'Check for unknown device administrators, accessibility services and VPN or certificate profiles, and remove them.', 'If the phone may be badly compromised, back up photos and contacts only, then factory reset and set it up as new with new passwords.'],
  sextortion: ['Stop replying and don’t pay — paying usually leads to more demands.', 'Keep evidence: screenshots of messages, usernames, payment details. Then block the person.', 'Report the account to the platform, and report to the police. If the images involve someone under 18, report to the police and to the NCMEC Take It Down service or your national hotline.', 'Tell someone you trust. You are not alone, and this is a crime against you.'],
};
$('#rc-what').addEventListener('change', (e) => { $('#rc-steps').innerHTML = (RECOVER[e.target.value] || []).map((s) => `<li>${esc(s)}</li>`).join(''); });

// ---------- editions: Free / Plus / Family / Business ----------
function applyLocks() {
  document.querySelectorAll('[data-plan]').forEach((el) => {
    const need = el.dataset.plan; const locked = !can(need);
    el.classList.toggle('locked', locked);
    el.querySelector(':scope > .lock-over')?.remove();
    if (locked) {
      const o = document.createElement('div'); o.className = 'lock-over';
      o.innerHTML = `<span class="tag">${esc(PLANS[need].name)}</span><b>${need === 'business' ? 'Part of BlackSwan Business' : 'Part of BlackSwan Plus'}</b><button class="btn sm" type="button" data-goto-plans>See plans${need === 'plus' && !trialUsed() ? ' · free trial' : ''}</button>`;
      el.append(o);
    }
  });
}
document.addEventListener('click', (e) => { if (e.target.closest('[data-goto-plans]')) { show('plans'); window.scrollTo(0, 0); } });
function renderPlans() {
  const p = plan(); const cfg = config();
  $('#plan-badge').textContent = PLANS[p.plan].name + (p.source === 'trial' ? ' trial' : p.source === 'demo' ? ' demo' : '');
  $('#plan-info').textContent = p.source === 'licence' ? `Licensed to ${p.name || 'you'}${p.devices > 1 ? ` · ${p.devices} devices` : ''}${p.expires ? ` · renews or ends ${new Date(p.expires).toLocaleDateString()}` : ''}.`
    : p.source === 'demo' ? `Demo edition: ${PLANS[p.plan].name} features are switched on until ${new Date(p.expires).toLocaleDateString()}. Enter a licence key to keep them after that.`
    : p.source === 'trial' ? `Your Plus trial ends ${new Date(p.expires).toLocaleDateString()}.`
      : p.expired ? `Your ${PLANS[p.expired.plan].name} licence ended ${new Date(p.expired.expires).toLocaleDateString()}. Renew to switch Plus features back on.` : 'You’re on BlackSwan Free. Safety features stay free forever.';
  $('#plan-trial').hidden = trialUsed() || p.plan !== 'free';
  const buy = $('#plan-buy'); buy.hidden = !(cfg.buyUrl && cfg.channel !== 'play'); if (!buy.hidden) buy.href = cfg.buyUrl;
  $('#plan-remove').hidden = p.source !== 'licence';
  $('#plan-cards').innerHTML = PRICES.map((x) => `<section class="card${x.id === p.plan ? ' current' : ''}"><h3>${esc(x.name)}</h3><p class="price">${esc(x.price)}</p><p class="per">${esc(x.per)}</p><p class="muted small">${esc(x.blurb)}</p><ul>${x.features.map((f) => `<li>${esc(f)}</li>`).join('')}</ul></section>`).join('');
}
async function refreshPlan() { await loadPlan(); applyLocks(); renderPlans(); }
$('#plan-trial').addEventListener('click', async () => { if (startTrial()) { await refreshPlan(); toast('Your 14-day Plus trial has started.'); } });
$('#plan-apply').addEventListener('click', async () => {
  const lic = await applyLicence($('#plan-key').value);
  $('#plan-msg').textContent = lic ? `Activated: ${PLANS[lic.plan].name}${lic.name ? ' for ' + lic.name : ''}.` : 'That licence key isn’t valid. Check it was copied in full.';
  if (lic) { $('#plan-key').value = ''; await refreshPlan(); }
});
$('#plan-remove').addEventListener('click', async () => { removeLicence(); await refreshPlan(); $('#plan-msg').textContent = 'Licence removed from this device.'; });
await refreshPlan();

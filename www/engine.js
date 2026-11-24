// BlackSwan detection engine. Pure functions, no DOM: used by the app, the tests and mirrored in matlab/.
// Links and messages are scored with a logistic model: p = 1 / (1 + e^-(bias + Σ wᵢ·xᵢ)).
// The default weights below can be replaced by weights trained in MATLAB (matlab/bs_train_url_model.m → www/weights.json).

export const sigmoid = (z) => 1 / (1 + Math.exp(-z));

/** URL feature order. Must match matlab/bs_url_features.m. */
export const URL_FEATURES = ['http', 'at_sign', 'ip_host', 'punycode', 'deep_subdomains', 'many_hyphens', 'abused_tld', 'odd_port', 'shortener',
  'brand_regional', 'typosquat', 'brand_impersonation', 'login_words', 'free_hosting', 'risky_download', 'double_extension', 'long_url', 'heavy_encoding', 'redirect'];

export const DEFAULT_WEIGHTS = {
  url: { bias: -3.0, w: { http: 1.0, at_sign: 3.5, ip_host: 2.5, punycode: 2.8, deep_subdomains: 1.0, many_hyphens: 0.9, abused_tld: 1.1, odd_port: 1.0, shortener: 1.6,
    brand_regional: 1.2, typosquat: 4.0, brand_impersonation: 3.5, login_words: 2.0, free_hosting: 1.0, risky_download: 2.4, double_extension: 3.5, long_url: 0.5, heavy_encoding: 0.9, redirect: 1.8 } },
  msg: { bias: -2.5, urlWeight: 3.0 },
};
let W = structuredClone(DEFAULT_WEIGHTS);
/** Load weights trained in MATLAB (same shape as DEFAULT_WEIGHTS.url). Ignores anything malformed. */
export function setUrlWeights(obj) {
  if (!obj || typeof obj.bias !== 'number' || typeof obj.w !== 'object') return false;
  const w = {};
  for (const k of URL_FEATURES) w[k] = Number.isFinite(obj.w[k]) ? obj.w[k] : DEFAULT_WEIGHTS.url.w[k];
  W.url = { bias: obj.bias, w };
  return true;
}
export const currentWeights = () => W;

// ---------- live threat feeds (www/intel/feed.json, refreshed daily) ----------
let INTEL = { domains: new Set(), urls: new Set(), updated: null };
export function setIntel(feed) {
  INTEL = { domains: new Set((feed?.phishDomains || []).map((d) => String(d).toLowerCase())), urls: new Set(feed?.phishUrls || []), updated: feed?.updated || null };
  return INTEL.domains.size + INTEL.urls.size;
}
const listed = (raw, host, rd) => INTEL.urls.has(raw) || INTEL.urls.has(raw.replace(/\/$/, '')) || INTEL.domains.has(host) || INTEL.domains.has(host.replace(/^www\./, '')) || (rd !== host && INTEL.domains.has(rd) && !SHARED_HOSTS.test(rd));
const SHARED_HOSTS = /(^|\.)(google\.com|blogspot\.com|github\.io|pages\.dev|workers\.dev|web\.app|firebaseapp\.com|netlify\.app|vercel\.app|weebly\.com|wixsite\.com|sharepoint\.com|dropbox\.com|amazonaws\.com|azurewebsites\.net|windows\.net|appspot\.com|r2\.dev)$/;

/**
 * On-device learning: one gradient step of logistic regression toward the person's own verdict (y = 1 scam, 0 safe),
 * pulled gently back toward the built-in weights so a few answers personalise the model without breaking it.
 */
export function learnUrl(x, y, lr = 0.3, pull = 0.02) {
  if (!x) return W.url;
  let z = W.url.bias; for (const k of URL_FEATURES) z += W.url.w[k] * (x[k] || 0);
  const err = sigmoid(z) - (y ? 1 : 0);
  W.url.bias -= lr * err + pull * (W.url.bias - DEFAULT_WEIGHTS.url.bias);
  for (const k of URL_FEATURES) W.url.w[k] -= lr * err * (x[k] || 0) + pull * (W.url.w[k] - DEFAULT_WEIGHTS.url.w[k]);
  return W.url;
}

// ---------- reference lists (global, not tied to any one country) ----------
const AMZ = ['amazon.com', 'amazonaws.com', 'amzn.to', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.es', 'amazon.it', 'amazon.nl', 'amazon.se', 'amazon.pl', 'amazon.com.be', 'amazon.ca', 'amazon.com.mx', 'amazon.com.br', 'amazon.in', 'amazon.co.jp', 'amazon.com.au', 'amazon.sg', 'amazon.ae', 'amazon.sa', 'amazon.eg', 'amazon.com.tr', 'amazon.co.za', 'amazon.cn'];
export const BRANDS = { paypal: ['paypal.com', 'paypal.me'], apple: ['apple.com', 'icloud.com'], icloud: ['icloud.com', 'apple.com'], microsoft: ['microsoft.com', 'live.com', 'office.com', 'microsoftonline.com', 'outlook.com', 'windows.com', 'azure.com'], office365: ['office.com', 'microsoft.com'], outlook: ['outlook.com', 'live.com', 'office.com'], google: ['google.com', 'gmail.com', 'youtube.com', 'goo.gl', 'googleusercontent.com'], gmail: ['gmail.com', 'google.com'], amazon: AMZ, facebook: ['facebook.com', 'fb.com', 'meta.com'], instagram: ['instagram.com'], whatsapp: ['whatsapp.com', 'whatsapp.net', 'wa.me'], netflix: ['netflix.com'], binance: ['binance.com'], coinbase: ['coinbase.com'], metamask: ['metamask.io'], trustwallet: ['trustwallet.com'], fedex: ['fedex.com'], linkedin: ['linkedin.com'], adobe: ['adobe.com'], dropbox: ['dropbox.com'], docusign: ['docusign.com', 'docusign.net'], yahoo: ['yahoo.com'], tiktok: ['tiktok.com'], barclays: ['barclays.co.uk', 'barclays.com'], santander: ['santander.com'], wellsfargo: ['wellsfargo.com'], citibank: ['citi.com', 'citibank.com'], alibaba: ['alibaba.com'], aliexpress: ['aliexpress.com'], telegram: ['telegram.org', 't.me'], roblox: ['roblox.com'], epicgames: ['epicgames.com'], spotify: ['spotify.com'], revolut: ['revolut.com'], mastercard: ['mastercard.com'], steampowered: ['steampowered.com'], steamcommunity: ['steamcommunity.com'], discord: ['discord.com', 'discord.gg'], shopify: ['shopify.com'], airbnb: ['airbnb.com'], booking: ['booking.com'], github: ['github.com'], openai: ['openai.com', 'chatgpt.com'], ledger: ['ledger.com'], kraken: ['kraken.com'], westernunion: ['westernunion.com'], dhl: ['dhl.com'], ups: ['ups.com'], visa: ['visa.com'], chase: ['chase.com'], hsbc: ['hsbc.com'], ebay: ['ebay.com'], wise: ['wise.com'], steam: ['steampowered.com', 'steamcommunity.com'] };
export const SHORTENERS = ['bit.ly', 'bitly.com', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'cutt.ly', 'rebrand.ly', 'shorturl.at', 'rb.gy', 'tiny.cc', 's.id', 't.ly', 'v.gd', 'lnkd.in', 'qrco.de', 'shorturl.gg', 'urlz.fr', 'surl.li', 'short.gy'];
export const FREE_HOSTS = ['pages.dev', 'workers.dev', 'web.app', 'firebaseapp.com', 'github.io', 'netlify.app', 'vercel.app', 'glitch.me', 'weebly.com', 'wixsite.com', 'blogspot.com', '000webhostapp.com', 'ngrok-free.app', 'ngrok.io', 'trycloudflare.com', 'r2.dev', 'ipfs.io', 'dweb.link', 'sites.google.com', 'webflow.io', 'framer.app', 'square.site', 'godaddysites.com', 'herokuapp.com', 'onrender.com', 'repl.co', 'duckdns.org', 'firebasestorage.googleapis.com', 'storage.googleapis.com', 'blob.core.windows.net', 's3.amazonaws.com'];
export const ABUSED_TLDS = ['zip', 'mov', 'top', 'xyz', 'click', 'link', 'rest', 'gq', 'cf', 'tk', 'ml', 'ga', 'work', 'support', 'cam', 'icu', 'buzz', 'sbs', 'cfd', 'bond', 'lol', 'quest', 'monster', 'country', 'kim', 'loan', 'win', 'bid', 'date', 'men', 'review', 'stream', 'party', 'racing', 'download', 'help', 'live', 'online', 'site', 'shop', 'info', 'cyou', 'pw'];
export const REDIRECT_KEYS = ['url', 'u', 'redirect', 'redirect_uri', 'redirect_url', 'redirecturl', 'next', 'target', 'dest', 'destination', 'return', 'returnurl', 'return_url', 'returnto', 'goto', 'continue', 'r', 'out', 'link', 'to', 'go', 'forward', 'q', 'ref', 'view', 'page', 'file', 'fwd', 'rurl', 'service'];
export const LOGIN_WORDS = ['login', 'log-in', 'signin', 'sign-in', 'verify', 'verification', 'account', 'update', 'secure', 'security', 'wallet', 'unlock', 'suspend', 'confirm', 'billing', 'password', 'recover', 'support', 'invoice', 'payment', 'refund', 'claim', 'bonus', 'airdrop', 'auth', 'webscr', 'validate', 'restore', 'helpdesk', 'reset'];
const RISKY_EXT = /\.(exe|scr|js|jse|vbs|vbe|hta|iso|img|msi|lnk|bat|cmd|ps1|jar|apk|dmg|pkg|zip|rar|7z|xll|one|svg|html?)$/i;
const SLD = ['co', 'com', 'org', 'net', 'gov', 'ac', 'edu', 'gob', 'or', 'ne', 'go', 'mil', 'nic', 'gv'];

export function regDomain(h) { const p = h.split('.'); if (p.length <= 2) return h; const sl = p[p.length - 2], tld = p[p.length - 1]; return tld.length === 2 && SLD.includes(sl) ? p.slice(-3).join('.') : p.slice(-2).join('.'); }
export function deconfuse(s) { return s.toLowerCase().replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/0/g, 'o').replace(/[1!|]/g, 'l').replace(/3/g, 'e').replace(/[4@]/g, 'a').replace(/[5$]/g, 's').replace(/7/g, 't').replace(/8/g, 'b').replace(/[-_]/g, ''); }
export function lev(a, b) { const m = a.length, n = b.length; if (Math.abs(m - n) > 2) return 9; let prev = [...Array(n + 1).keys()]; for (let i = 1; i <= m; i++) { const cur = [i]; for (let j = 1; j <= n; j++) cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)); prev = cur; } return prev[n]; }
const official = (host, list) => list.some((d) => host === d || host.endsWith('.' + d));

/** Level 1 ok · 2 caution · 3 danger · 4 critical, from a probability. */
export const levelOf = (p) => (p >= 0.75 ? 4 : p >= 0.4 ? 3 : p >= 0.15 ? 2 : 1);
export const VERDICT = ['', 'Looks safe', 'Be careful', 'Dangerous', 'Critical — do not open'];

/** Scores one link. Returns { prob, score, lv, verdict, host, x (feature vector), findings: [{lv, t}] }. */
export function analyzeURL(raw, depth = 0) {
  const x = Object.fromEntries(URL_FEATURES.map((k) => [k, 0]));
  const F = []; const note = (lv, t) => F.push({ lv, t });
  raw = String(raw || '').trim().replace(/^hxxp/i, 'http').replace(/\[\.\]/g, '.');
  if (!raw) return null;
  if (/^(javascript|vbscript):/i.test(raw)) return done(0.99, [{ lv: 4, t: 'Script link: clicking it runs code instead of opening a page.' }], '(script)', x);
  if (/^data:/i.test(raw)) return done(0.97, [{ lv: 4, t: 'data: link carries a whole page inside the link, a known way to hide fake login forms.' }], '(data)', x);
  const hadScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw);
  let u; try { u = new URL(hadScheme ? raw : 'http://' + raw); } catch { return done(0.3, [{ lv: 2, t: 'Not a valid web address. Malformed links are often used to slip past filters.' }], raw.slice(0, 60), x); }
  const host = u.hostname.toLowerCase().replace(/\.$/, ''), rd = regDomain(host), label = rd.split('.')[0], tld = host.split('.').pop();
  const rawHost = (raw.split('//')[1] || raw).split(/[/?#]/)[0];
  if (u.protocol === 'http:' && hadScheme) { x.http = 1; note(2, 'Not encrypted (http). Anyone on the same Wi-Fi can read or change this page — the opening for a man-in-the-middle attack.'); }
  if (u.username || u.password || /@/.test(rawHost)) { x.at_sign = 1; note(4, 'Contains "@" before the real address. Everything before "@" is ignored, so the visible brand name is a decoy.'); }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith('[') || /^(0x[0-9a-f]+|\d{8,10})$/i.test(rawHost)) { x.ip_host = 1; note(3, 'Uses a raw or encoded IP address instead of a name. Real companies almost never do this for logins.'); }
  if (host.includes('xn--') || /[^\x00-\x7F]/.test(rawHost)) { x.punycode = 1; note(3, 'Characters from other alphabets in the name (punycode). They can look identical to normal letters — a homograph lookalike.'); }
  const labels = host.split('.');
  if (labels.length > 4) { x.deep_subdomains = 1; note(2, `Very deep sub-domain chain (${labels.length} levels), often used to push the real domain out of view on phones.`); }
  if ((host.match(/-/g) || []).length >= 3) { x.many_hyphens = 1; note(2, 'Many hyphens in the name, typical of throwaway phishing domains.'); }
  if (ABUSED_TLDS.includes(tld)) { x.abused_tld = 1; note(2, `Ends in ".${tld}", a cheap domain ending heavily used for scams. Real sites use it too, so check carefully.`); }
  if (u.port && !['80', '443'].includes(u.port)) { x.odd_port = 1; note(2, `Uses unusual port ${u.port}.`); }
  if (SHORTENERS.includes(host)) { x.shortener = 1; note(2, 'Link shortener: the real destination is hidden. Expand it with a link-preview service before opening.'); }
  const tokens = host.split(/[.-]/).filter(Boolean), nt = tokens.map(deconfuse);
  for (const [b, off] of Object.entries(BRANDS)) {
    if (official(host, off)) continue;
    if (b.length >= 5) {
      const nl = deconfuse(label);
      if (label === b) { x.brand_regional = 1; note(2, `Uses the name "${b}" on ${rd}, which is not one of its known official domains. Confirm it is a genuine regional site before entering anything.`); break; }
      if (nl === b || lev(nl, b) === 1 || (b.length >= 8 && lev(nl, b) === 2)) { x.typosquat = 1; note(4, `Typosquat: "${label}" is a misspelling or lookalike of ${b}. Classic fake website.`); break; }
      if (nt.includes(b) || deconfuse(host.replace(/\./g, '')).includes(b)) { x.brand_impersonation = 1; note(3, `Mentions ${b}, but the real owner of this address is ${rd}. Brand impersonation.`); break; }
    } else if (tokens.includes(b) && label !== b) { x.brand_impersonation = 1; note(3, `Contains "${b}", but the real owner of this address is ${rd}. Brand impersonation.`); break; }
  }
  const path = (u.pathname + u.search).toLowerCase();
  const kw = LOGIN_WORDS.filter((k) => host.includes(k) || path.includes(k));
  if (kw.length) { x.login_words = Math.min(5, kw.length) / 5; note(kw.length > 2 ? 3 : 2, `Login or urgency words in the link: ${kw.slice(0, 6).join(', ')}.`); }
  const fh = FREE_HOSTS.find((d) => host === d || host.endsWith('.' + d));
  if (fh) { x.free_hosting = 1; note(x.brand_impersonation || x.login_words ? 3 : 1, `Hosted on ${fh}, free hosting where anyone can publish a page in minutes.`); }
  if (RISKY_EXT.test(u.pathname)) { x.risky_download = 1; note(3, `Downloads a ".${u.pathname.split('.').pop()}" file — a common way to deliver remote-control malware.`); }
  if (/\.(pdf|docx?|xlsx?|jpg|png)\.(exe|scr|js|bat|cmd|lnk|hta)$/i.test(u.pathname)) { x.double_extension = 1; note(4, 'Double file extension (e.g. invoice.pdf.exe) — malware pretending to be a document.'); }
  if (raw.length > 120) { x.long_url = 1; note(1, 'Very long link, often used to hide the real address.'); }
  if ((raw.match(/%[0-9a-f]{2}/gi) || []).length > 8) { x.heavy_encoding = 1; note(2, 'Heavily encoded characters hide what the link really says.'); }
  const nested = [];
  for (const [k, v] of u.searchParams) if (REDIRECT_KEYS.includes(k.toLowerCase()) && /^(https?:)?\/\/|^www\.|^https?%3a/i.test(v)) nested.push(v);
  let pathDec = u.pathname; try { pathDec = decodeURIComponent(u.pathname); } catch { /* keep raw */ }
  const pm = pathDec.match(/\/(https?:\/\/.+)$/i); if (pm) nested.push(pm[1]);
  let nestedP = 0;
  if (nested.length) {
    x.redirect = 1; note(3, 'Redirect: this link forwards you to another address. Attackers abuse trusted sites’ redirects to bounce you to a fake page.');
    if (depth < 3) for (const n of nested) { const r = analyzeURL(n, depth + 1); if (r) { nestedP = Math.max(nestedP, r.prob); F.push({ lv: r.lv, t: `→ Redirect target ${r.host}: ${r.verdict} (${r.score}%)` }); } }
  }
  let z = W.url.bias; for (const k of URL_FEATURES) z += W.url.w[k] * x[k];
  let p = Math.max(sigmoid(z), 0.9 * nestedP);
  if (listed(raw, host, rd)) { p = Math.max(p, 0.97); F.unshift({ lv: 4, t: 'On today’s live phishing feeds: this exact site has been reported as phishing. Do not open it.' }); }
  if (!F.length) F.push({ lv: 1, t: 'No warning signs found. Still type important addresses yourself instead of following links.' });
  return done(p, F, host, x);
}
function done(p, F, host, x) { const lv = levelOf(p); return { prob: p, score: Math.round(p * 100), lv, verdict: VERDICT[lv], host, x, findings: F.sort((a, b) => b.lv - a.lv) }; }

// ---------- messages ----------
export const MSG_RULES = [
  ['remote_access', /\b(any ?desk|team ?viewer|ultra ?viewer|rust ?desk|screen ?connect|connectwise|logmein|quick ?assist|supremo|splashtop|ammyy|remote ?utilities|netsupport|zoho assist|remotepc)\b/i, 3.5, 4, 'Asks you to install or use a remote-access tool. This is how scammers take over a computer or phone.'],
  ['clickfix', /\b(win(dows)?\s*(key)?\s*\+\s*r|press (the )?windows key|run dialog|powershell|mshta|cmd\.exe|terminal and paste|ctrl\s*\+\s*v.{0,40}enter|paste.{0,30}(run|terminal|command))/i, 4.0, 4, '“Paste and run” instructions (ClickFix). Real sites never ask you to paste commands to prove you are human.'],
  ['infected', /\b(virus|malware|trojan|spyware|hacked|infected|compromised)\b.{0,60}\b(computer|device|pc|phone|mac|system)|\b(computer|device|pc|phone|system)\b.{0,40}\b(locked|infected|hacked|blocked)/i, 2.2, 3, 'Claims your device is infected or locked — the opening line of tech-support scams.'],
  ['callback', /\b(call|contact|phone)\b.{0,40}\b(support|helpdesk|help desk|technician|toll[- ]?free|security team|fraud (team|department))/i, 1.8, 3, 'Pushes you to call a “support” number (callback phishing). Look up the real number yourself.'],
  ['gift_cards', /\b(gift ?cards?|itunes card|google play card|apple card code|steam card|amazon card|voucher code)\b/i, 3.5, 4, 'Demands gift cards. No real company, tax office or police force takes payment in gift cards.'],
  ['crypto', /\b(bitcoin|btc|usdt|tether|crypto(currency)?|ethereum|eth wallet|crypto atm|bitcoin atm|wallet address|seed phrase|recovery phrase|private key)\b/i, 2.5, 3, 'Crypto payment or wallet secrets requested. Payments can’t be reversed and a seed phrase gives total control of the funds.'],
  ['wire', /\b(wire transfer|western union|moneygram|money order|bank transfer to|send money)\b/i, 1.5, 2, 'Asks for a hard-to-reverse money transfer.'],
  ['otp', /\b(one[- ]time (pass(word|code)|code|pin)|otp|verification code|security code|6[- ]digit code|authenticat(ion|or) code)\b/i, 2.5, 3, 'Mentions a one-time code. Never share a code you receive — it lets them log in as you or approve payments.'],
  ['credentials', /\b(verify|confirm|update|validate|re-?enter|provide)\b.{0,30}\b(password|pin|account|identity|login|card|details|credentials)\b/i, 2.2, 3, 'Asks you to verify or re-enter login or card details.'],
  ['mfa_fatigue', /\b(approve|accept|confirm|tap yes)\b.{0,30}\b(sign[- ]?in|login|request|notification|prompt|push)\b/i, 2.5, 3, 'Asks you to approve a sign-in prompt you didn’t start (MFA fatigue attack).'],
  ['urgency', /\b(urgent|immediately|right now|within (24|48) hours|final (notice|warning)|act now|last chance|expires? today)\b/i, 1.2, 2, 'Pressure and urgency — designed to stop you thinking.'],
  ['account_threat', /\b(suspend(ed)?|lock(ed)?|clos(e|ed)|disabled|deactivat(e|ed)|terminated)\b.{0,25}\b(account|card|service|mailbox)\b|\baccount\b.{0,25}\b(suspend|lock|clos|disabl|deactivat|terminat)/i, 1.5, 2, 'Threatens to suspend or close your account.'],
  ['advance_fee', /\b(you('ve| have)? won|lottery|jackpot|inheritance|beneficiary|claim your (prize|reward)|unclaimed funds|compensation fund|processing fee|release fee)\b/i, 2.8, 3, 'Prize, lottery or inheritance with a fee — advance-fee fraud.'],
  ['bank_change', /\b(new|updated|change(d)? (of|to)?|different)\s+(bank|account|payment|banking)\s+(details|account|information)\b/i, 3.0, 4, 'Changed bank details for a payment — business email compromise (invoice fraud). Confirm by phone on a number you already know.'],
  ['secrecy', /\b(keep (this|it) (confidential|between us|secret)|don'?t tell (anyone|your bank)|do not (tell|inform) (anyone|the bank))/i, 2.5, 3, 'Asks you to keep it secret — scammers cut victims off from people who would warn them.'],
  ['sextortion', /\b(recorded you|your webcam|intimate (video|images)|i (have|got) access to your (device|computer|camera))\b/i, 3.0, 3, 'Sextortion threat. These are mass-mailed bluffs; don’t pay.'],
  ['delivery', /\b(package|parcel|delivery|shipment)\b.{0,50}\b(fee|failed|could not|couldn'?t|unable|held|customs|reschedule|redelivery)\b/i, 2.0, 2, 'Fake delivery problem asking for a small fee — card-stealing scam.'],
  ['authority', /\b(tax (refund|office|authority)|police|customs|court|arrest warrant|immigration|social security)\b/i, 1.5, 2, 'Claims to be a government body or police. They don’t demand payment by message or phone.'],
  ['investment', /\b(investment|guaranteed (return|profit)|double your (money|crypto)|trading platform|forex|mining pool)\b/i, 1.8, 2, 'Too-good-to-be-true investment — the hook in “pig-butchering” crypto scams.'],
  ['sim_swap', /\b(sim (swap|card)|port(ing)? (out|your number)|esim)\b/i, 1.8, 2, 'Mentions moving your phone number — SIM-swap attacks steal SMS codes.'],
  ['qr', /\b(scan (the|this) qr|qr code)\b/i, 1.2, 2, 'QR-code link — QR phishing hides the address until it’s too late.'],
  ['fake_update', /\b(browser|chrome|flash|java|driver|security)\s+(update|upgrade)\s+(required|needed|available)/i, 2.2, 3, 'Fake “update required” message — a common way to deliver malware.'],
  ['task_scam', /\b(part[- ]time (job|work)|work from home|earn \$?\d+.{0,20}(per|a) (day|task|hour)|(like|rate|review) (videos|products|hotels|apps).{0,30}(earn|pay|commission)|daily (salary|commission)|recharge your account|complete (the )?tasks)\b/i, 2.8, 3, 'Task or job scam: paid for “simple tasks”, then asked to pay in to unlock earnings. Real jobs never ask you to pay.'],
  ['platform_move', /\b(add|message|text|contact|chat with) me on (whatsapp|telegram|signal|line|wechat|viber)|(move|continue|talk) (to|on) (whatsapp|telegram|signal|line|wechat)|my (whatsapp|telegram) (is|number)\b/i, 1.6, 2, 'Asks to move the chat to another app — scammers leave platforms that can spot and ban them.'],
  ['wrong_number', /\b(sorry,? wrong (number|person)|is this [A-Z]?[a-z]+\?|did i (text|message) the wrong)\b/i, 1.0, 2, '“Wrong number” opener — a common way romance and investment scams start a conversation.'],
  ['romance', /\b(my love|my dear|sweetheart|soul ?mate|god (bless|sent) you|destiny brought|i('m| am) a (widow|widower|soldier|doctor|engineer) (on|in|at|working)|oil rig|un peacekeep)/i, 1.4, 2, 'Fast affection or a far-away “doctor, soldier or engineer” — classic romance-scam signs.'],
  ['consent', /\b(grant|allow) (access|permissions?)|consent to (the )?app|oauth\b/i, 1.2, 2, 'Asks you to grant an app access to your account (consent phishing).'],
];
const URL_IN_TEXT = /\b((?:https?|hxxps?):\/\/[^\s<>"')\]]+|www\.[^\s<>"')\]]+|[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|info|help|support|top|xyz|click|link|online|site|live|shop|io|co|me|app|zip|mov)(?:\/[^\s<>"')\]]*)?)/gi;

export function analyzeMsg(text) {
  const t = String(text || ''); const F = []; let z = W.msg.bias; const hits = [];
  for (const [id, re, w, lv, msg] of MSG_RULES) if (re.test(t)) { z += w; hits.push(id); F.push({ lv, t: msg }); }
  const urls = [...new Set(t.match(URL_IN_TEXT) || [])].slice(0, 12);
  let worst = 0;
  for (const raw of urls) { const r = analyzeURL(raw.replace(/[.,;:!?]+$/, '')); if (r) { worst = Math.max(worst, r.prob); F.push({ lv: r.lv, t: `Link ${r.host}: ${r.verdict} (${r.score}%). ${r.findings[0].t}` }); } }
  z += W.msg.urlWeight * worst;
  if (/\+?\d[\d\s().-]{8,}\d/.test(t) && /support|help|call|contact/i.test(t)) F.push({ lv: 2, t: 'Contains a phone number to call. Only use numbers from the company’s official website or your card.' });
  if (!F.length) F.push({ lv: 1, t: 'No scam patterns found. If something still feels off, contact the sender through a channel you already trust.' });
  // Conversation stages of social engineering: hook → trust → isolate → pressure → payment.
  const STAGES = { hook: ['wrong_number', 'advance_fee', 'task_scam', 'delivery', 'investment', 'infected'], trust: ['romance', 'authority', 'callback'], isolate: ['platform_move', 'secrecy', 'remote_access'], pressure: ['urgency', 'account_threat', 'sextortion', 'mfa_fatigue'], payment: ['gift_cards', 'crypto', 'wire', 'bank_change', 'otp', 'credentials', 'clickfix'] };
  const stages = Object.entries(STAGES).filter(([, ids]) => ids.some((id) => hits.includes(id))).map(([k]) => k);
  if (stages.length >= 3) { z += 1.5; F.unshift({ lv: 4, t: `This conversation follows the scam playbook: ${stages.join(' → ')}. Stop replying and don’t send anything.` }); }
  const p = sigmoid(z);
  return { ...done(p, F, `${urls.length} link${urls.length === 1 ? '' : 's'} found`, null), rules: hits, stages };
}

// ---------- statistics: running baselines and rare-event tests ----------
/** Exponentially weighted mean and variance. z() tells how unusual a new value is. */
export class Ewma {
  constructor(state = {}, alpha = 0.2) { this.alpha = alpha; this.n = state.n || 0; this.mean = state.mean || 0; this.var = state.var || 0; }
  z(v) { return this.n < 5 ? 0 : (v - this.mean) / Math.sqrt(this.var + 4); } // +4 dB² floor: radio readings jitter
  push(v) { if (!this.n) { this.mean = v; this.var = 0; } else { const d = v - this.mean; this.mean += this.alpha * d; this.var = (1 - this.alpha) * (this.var + this.alpha * d * d); } this.n++; return this; }
  toJSON() { return { n: this.n, mean: this.mean, var: this.var }; }
}
/** P(X ≥ k) for a Poisson count with mean lambda: how likely k failures are by chance. */
export function poissonTail(k, lambda) { if (k <= 0) return 1; let term = Math.exp(-lambda), cdf = term; for (let i = 1; i < k; i++) { term *= lambda / i; cdf += term; } return Math.max(0, 1 - cdf); }
/** Shannon entropy of a password drawn uniformly: length × log2(pool). */
export const entropyBits = (len, pool) => len * Math.log2(pool);

// ---------- passwords ----------
export function randInt(n, rng = (a) => crypto.getRandomValues(a)) { const lim = Math.floor(4294967296 / n) * n, a = new Uint32Array(1); do { rng(a); } while (a[0] >= lim); return a[0] % n; }
export function charSets({ upper = true, lower = true, digits = false, symbols = false, noLookalikes = true } = {}) {
  const f = (s) => (noLookalikes ? s.replace(/[Il1O0o]/g, '') : s); const S = [];
  if (upper) S.push(f('ABCDEFGHIJKLMNOPQRSTUVWXYZ')); if (lower) S.push(f('abcdefghijklmnopqrstuvwxyz'));
  if (digits) S.push(f('0123456789')); if (symbols) S.push('!#$%&*+-=?@^_~');
  return S.length ? S : [f('abcdefghijklmnopqrstuvwxyz')];
}
/** Unbiased random password with at least one character from each chosen set. */
export function generatePassword(len = 15, opts = {}) {
  len = Math.max(8, Math.min(64, len | 0 || 15));
  const S = charSets(opts), pool = S.join(''); const c = S.map((s) => s[randInt(s.length)]);
  while (c.length < len) c.push(pool[randInt(pool.length)]);
  for (let i = c.length - 1; i > 0; i--) { const j = randInt(i + 1); [c[i], c[j]] = [c[j], c[i]]; }
  return { password: c.join(''), bits: entropyBits(len, pool.length), pool: pool.length };
}
export function crackTime(bits, guessesPerSec = 1e11) {
  const sec = 2 ** bits / 2 / guessesPerSec;
  const u = [['billion years', 3.15e16], ['million years', 3.15e13], ['thousand years', 3.15e10], ['years', 3.15e7], ['days', 86400], ['hours', 3600], ['minutes', 60]];
  for (const [n, v] of u) if (sec >= v) return `${(sec / v).toLocaleString('en', { maximumFractionDigits: 0 })} ${n}`;
  return `${Math.round(sec)} seconds`;
}

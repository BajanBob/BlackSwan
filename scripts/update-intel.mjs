// BlackSwan daily threat intelligence. Run by .github/workflows/intel.yml every day (and whenever watch.json changes).
// Pulls free, public, worldwide feeds, merges them with the curated watch list (www/intel/watch.json) and writes
// www/intel/feed.json, which every BlackSwan app downloads once a day. Each source is optional: if one fails, the rest still publish.
import fs from 'node:fs';

const OUT = 'www/intel/feed.json';
const WATCH = 'www/intel/watch.json';
const DAY = 86400e3;
const now = Date.now();
const sources = [];

async function get(name, url, kind = 'json', timeoutMs = 60000) {
  try {
    const r = await fetch(url, { signal: AbortSignal.timeout(timeoutMs), headers: { 'user-agent': 'BlackSwan-intel/1.0 (+https://github.com/BajanBob/BlackSwan)' } });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const v = kind === 'json' ? await r.json() : await r.text();
    return v;
  } catch (e) { sources.push({ name, url, ok: false, error: String(e.message || e) }); return null; }
}
const ok = (name, url, count) => sources.push({ name, url, ok: true, count });
const hostOf = (u) => { try { return new URL(u).hostname.toLowerCase().replace(/^www\./, ''); } catch { return null; } };
const isIp = (s) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s);

// Hosts phishers abuse but which also serve millions of genuine pages: list full URLs for these, never the whole host.
const SHARED = /(^|\.)(google\.com|googleusercontent\.com|blogspot\.com|github\.io|githubusercontent\.com|pages\.dev|workers\.dev|web\.app|firebaseapp\.com|netlify\.app|vercel\.app|weebly\.com|wixsite\.com|sharepoint\.com|onedrive\.live\.com|dropbox\.com|amazonaws\.com|azurewebsites\.net|windows\.net|appspot\.com|glitch\.me|ipfs\.io|dweb\.link|webflow\.io|forms\.gle|docs\.google\.com|sites\.google\.com|r2\.dev|square\.site|godaddysites\.com|ngrok-free\.app|trycloudflare\.com|telegra\.ph|linktr\.ee|bit\.ly|tinyurl\.com)$/;

const phishDomains = new Set(); const phishUrls = new Set(); const badIps = {};

// 1. OpenPhish community feed (live phishing URLs, worldwide).
{
  const url = 'https://openphish.com/feed.txt';
  const t = await get('OpenPhish', url, 'text');
  if (t) { let n = 0; for (const l of t.split(/\r?\n/)) { const u = l.trim(); if (!u) continue; const h = hostOf(u); if (!h) continue; n++; if (SHARED.test(h) || isIp(h)) phishUrls.add(u); else phishDomains.add(h); } ok('OpenPhish', url, n); }
}
// 2. Phishing.Database: domains and links first seen today.
for (const [name, url] of [['Phishing.Database new domains', 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-NEW-today.txt'],
  ['Phishing.Database new links', 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-NEW-today.txt']]) {
  const t = await get(name, url, 'text');
  if (t) { let n = 0; for (const l of t.split(/\r?\n/)) { const s = l.trim(); if (!s || s.startsWith('#')) continue; n++; if (/^https?:\/\//i.test(s)) { const h = hostOf(s); if (h && (SHARED.test(h) || isIp(h))) phishUrls.add(s); else if (h) phishDomains.add(h); } else if (!SHARED.test(s.toLowerCase())) phishDomains.add(s.toLowerCase().replace(/^www\./, '')); } ok(name, url, n); }
}
// 3. abuse.ch Feodo Tracker: active botnet command-and-control servers.
{
  const url = 'https://feodotracker.abuse.ch/downloads/ipblocklist.json';
  const j = await get('Feodo Tracker C2', url);
  if (Array.isArray(j)) { let n = 0; for (const x of j) { if (x.ip_address && (x.status === 'online' || now - Date.parse(x.last_online || 0) < 30 * DAY)) { badIps[x.ip_address] = `Botnet C2 (${x.malware || 'malware'})`; n++; } } ok('Feodo Tracker C2', url, n); }
}
// 4. CISA Known Exploited Vulnerabilities: holes attackers are using right now, worldwide.
let kev = [];
{
  const url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
  const j = await get('CISA KEV', url);
  if (j?.vulnerabilities) {
    kev = j.vulnerabilities.filter((v) => now - Date.parse(v.dateAdded) <= 30 * DAY).sort((a, b) => b.dateAdded.localeCompare(a.dateAdded))
      .map((v) => ({ cve: v.cveID, vendor: v.vendorProject, product: v.product, name: v.vulnerabilityName, added: v.dateAdded, ransomware: v.knownRansomwareCampaignUse === 'Known', action: String(v.requiredAction || '').slice(0, 240) }));
    ok('CISA KEV', url, kev.length);
  }
}
// 5. MITRE ATT&CK: threat groups added or updated recently.
let actors = [];
{
  const url = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json';
  const j = await get('MITRE ATT&CK groups', url, 'json', 180000);
  if (j?.objects) {
    actors = j.objects.filter((o) => o.type === 'intrusion-set' && !o.revoked && !o.x_mitre_deprecated)
      .map((o) => ({ name: o.name, aliases: (o.aliases || []).filter((a) => a !== o.name).slice(0, 8), created: (o.created || '').slice(0, 10), modified: (o.modified || '').slice(0, 10),
        summary: String(o.description || '').replace(/\(Citation:[^)]*\)/g, '').replace(/\s+/g, ' ').trim().slice(0, 320), url: (o.external_references || []).find((r) => r.source_name === 'mitre-attack')?.url || '' }))
      .sort((a, b) => b.modified.localeCompare(a.modified)).slice(0, 25);
    ok('MITRE ATT&CK groups', url, actors.length);
  }
}


// 6a. Stalkerware and spy apps: package names and signing certificates (Echap stalkerware-indicators, CC BY 4.0).
const spyware = { packages: {}, certificates: {}, watchware: {} };
function parseIocYaml(text, into, kind) {
  let name = null, key = null, n = 0;
  for (const raw of text.split(/\r?\n/)) {
    let m;
    if ((m = raw.match(/^- name:\s*(.+)$/))) { name = m[1].trim().replace(/^['"]|['"]$/g, ''); key = null; continue; }
    if ((m = raw.match(/^ {2}([a-z_]+):\s*$/))) { key = m[1]; continue; }
    if ((m = raw.match(/^ {2}([a-z_]+):\s*\S/))) { key = null; continue; }
    if ((m = raw.match(/^ {2}- (.+)$/)) && name && key) {
      const v = m[1].trim().replace(/^['"]|['"]$/g, '');
      if (key === 'packages') { into[kind === 'watchware' ? 'watchware' : 'packages'][v] = name; n++; }
      else if (key === 'certificates' && kind !== 'watchware') { into.certificates[v.toUpperCase().replace(/[^0-9A-F]/g, '')] = name; }
    }
  }
  return n;
}
for (const [name, url, kind] of [['Stalkerware indicators (Echap)', 'https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/ioc.yaml', 'stalkerware'],
  ['Watchware indicators (Echap)', 'https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/watchware.yaml', 'watchware']]) {
  const t = await get(name, url, 'text');
  if (t) ok(name, url, parseIocYaml(t, spyware, kind));
}

// 6b. Android malware hashes from abuse.ch MalwareBazaar (needs a free Auth-Key in the ABUSE_CH_KEY secret).
const malwareHashes = {};
if (process.env.ABUSE_CH_KEY) {
  const url = 'https://mb-api.abuse.ch/api/v1/';
  try {
    const r = await fetch(url, { method: 'POST', signal: AbortSignal.timeout(60000), headers: { 'Auth-Key': process.env.ABUSE_CH_KEY, 'content-type': 'application/x-www-form-urlencoded' }, body: 'query=get_file_type&file_type=apk&limit=1000' });
    const j = await r.json();
    for (const x of j.data || []) if (x.sha256_hash) malwareHashes[x.sha256_hash.toLowerCase()] = x.signature || 'Android malware';
    ok('MalwareBazaar Android', url, Object.keys(malwareHashes).length);
  } catch (e) { sources.push({ name: 'MalwareBazaar Android', url, ok: false, error: String(e.message || e) }); }
} else sources.push({ name: 'MalwareBazaar Android', ok: false, error: 'add a free abuse.ch Auth-Key as the ABUSE_CH_KEY repository secret to enable' });

// 6. Curated watch list (updated by BlackSwan's daily research agent and by hand): new actors, AI attack tools, campaigns.
let watch = { items: [] };
try { watch = JSON.parse(fs.readFileSync(WATCH, 'utf8')); } catch (e) { sources.push({ name: 'Watch list', ok: false, error: String(e.message) }); }
const items = (watch.items || []).filter((x) => x && x.title).sort((a, b) => String(b.date).localeCompare(String(a.date)));
const userAgents = new Set();
for (const it of items) {
  for (const ip of it.iocs?.ips || []) if (isIp(ip)) badIps[ip] = `${it.actor || it.title} (${it.date})`;
  for (const d of it.iocs?.domains || []) phishDomains.add(String(d).toLowerCase());
  for (const ua of it.iocs?.userAgents || []) userAgents.add(String(ua));
  for (const pk of it.iocs?.packages || []) spyware.packages[String(pk)] = it.actor || it.title;
  for (const h of it.iocs?.sha256 || []) malwareHashes[String(h).toLowerCase()] = it.actor || it.title;
}
ok('Watch list', WATCH, items.length);

// Warnings: what a person should hear about today.
const warnings = [];
for (const it of items.filter((x) => now - Date.parse(x.date) <= 14 * DAY).slice(0, 12)) warnings.push({ level: it.level || 3, date: it.date, title: it.title, text: it.summary || '', actor: it.actor || '', source: it.source || '' });
const kev7 = kev.filter((v) => now - Date.parse(v.added) <= 7 * DAY);
if (kev7.length) warnings.push({ level: kev7.some((v) => v.ransomware) ? 3 : 2, date: kev7[0].added, title: `${kev7.length} newly exploited software hole${kev7.length > 1 ? 's' : ''} this week`, text: kev7.slice(0, 6).map((v) => `${v.vendor} ${v.product} (${v.cve})`).join('; ') + '. Update these products now.', source: 'CISA KEV' });
const actors30 = actors.filter((a) => now - Date.parse(a.modified) <= 30 * DAY);
if (actors30.length) warnings.push({ level: 2, date: actors30[0].modified, title: `${actors30.length} threat group profile${actors30.length > 1 ? 's' : ''} updated this month`, text: actors30.slice(0, 6).map((a) => a.name).join(', '), source: 'MITRE ATT&CK' });

const feed = {
  app: 'BlackSwan', format: 1, updated: new Date(now).toISOString(), sources, warnings,
  phishDomains: [...phishDomains].slice(0, 60000), phishUrls: [...phishUrls].slice(0, 8000), badIps, userAgents: [...userAgents],
  kev: kev.slice(0, 80), actors, watch: items.slice(0, 60), spyware, malwareHashes,
};
fs.mkdirSync('www/intel', { recursive: true });
fs.writeFileSync(OUT, JSON.stringify(feed));
console.log(`Wrote ${OUT}: ${feed.phishDomains.length} phishing domains, ${feed.phishUrls.length} URLs, ${Object.keys(badIps).length} bad IPs, ${kev.length} KEV, ${actors.length} actors, ${items.length} watch items, ${warnings.length} warnings, ${Object.keys(spyware.packages).length} spy-app packages, ${Object.keys(spyware.certificates).length} spy-app certificates, ${Object.keys(malwareHashes).length} malware hashes`);
for (const s of sources) console.log(`${s.ok ? 'OK  ' : 'FAIL'} ${s.name}${s.ok ? ` (${s.count})` : ` — ${s.error}`}`);

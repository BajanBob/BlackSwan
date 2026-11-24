// BlackSwan ARTEX Shield: finds traces of the ARTEX agentic attack framework (and tools built on it, such as AntiFox)
// in web, proxy, firewall and sign-in logs. Pure functions; mirrored by the desktop agent (--logs) and matlab/bs_artex_rhythm.m.
//
// Indicators come from public reporting by Microsoft Threat Intelligence, Unit 42, CrowdStrike, Censys, BadByte and
// StepSecurity (July–November 2026). Attacker infrastructure changes quickly: treat IP matches as leads, not proof.

export const ARTEX_IOCS = {
  updated: '2026-11-12',
  userAgents: [/artex-enrich\/\d/i, /\bnorma\/0\.\d/i, /compatible;\s*artex\/\d/i, /compatible;\s*infra-hunt\/\d/i, /verify-911-probe\/\d/i, /\bartex\b/i],
  ips: {
    '91.92.240.238': 'ARTEX server (Storm-3358)', '85.11.168.45': 'ARTEX server (Storm-3358)', '178.16.54.129': 'ARTEX server (Storm-3358)', '31.77.229.35': 'ARTEX server (Storm-3358)',
    '199.19.77.84': 'App sign-ins with credentials found on GitHub', '65.87.223.26': 'Recon and exploit attempts on AI workloads', '157.22.126.128': 'Recon and exploit attempts on AI workloads',
    '144.172.64.60': 'Storm-0940 infrastructure', '144.172.64.99': 'Storm-0940 infrastructure', '144.172.64.128': 'Storm-0940 infrastructure',
    '38.244.50.120': 'ARTEX server (finance attacks)', '154.64.252.77': 'ARTEX agent traffic', '183.1.65.106': 'ARTEX agent traffic', '95.169.20.166': 'ARTEX agent traffic', '203.190.1.60': 'ARTEX agent traffic',
  },
  ja4: ['t13d3013h1_1d37bd780c83_8537cf56674e', 't13d3013h2_1d37bd780c83_8537cf56674e', 't13d3014h1_1d37bd780c83_5ae85263eb3b'],
  dockerImages: ['tomicdd/artex', 'congdonglinux/artex'],
  binarySha256: 'd5070f52262effe216b840711343bff8f2787f39208d887d8dfd9c673f8d1573',
  consolePort: 8787,
  consoleTitles: [/^\s*ARTEX/i, /自主渗透测试控制台/],
  entraErrors: { AADSTS7000215: 'wrong client secret', AADSTS7000222: 'expired client secret' },
};

const MON = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };
const IPV4 = /\b((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})\b/;

/** Time in ms from Apache/Nginx "[10/Oct/2026:13:55:36 +0000]", ISO 8601, or epoch seconds/ms fields. */
export function parseTime(line) {
  let m = line.match(/\[(\d{1,2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?\s*([+-]\d{4})?\]/);
  if (m) {
    const off = m[8] ? (m[8][0] === '-' ? -1 : 1) * (Number(m[8].slice(1, 3)) * 60 + Number(m[8].slice(3))) : 0;
    return Date.UTC(+m[3], MON[m[2].toLowerCase()], +m[1], +m[4], +m[5], +m[6], m[7] ? Number(('0.' + m[7])) * 1000 : 0) - off * 60e3;
  }
  m = line.match(/(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)/);
  if (m) { const t = Date.parse(m[1].replace(' ', 'T')); if (!Number.isNaN(t)) return t; }
  m = line.match(/"(?:ts|time|timestamp|@timestamp|epoch)"\s*:\s*(\d{10}(?:\.\d+)?|\d{13})\b/);
  if (m) return m[1].length === 13 ? Number(m[1]) : Number(m[1]) * 1000;
  return null;
}

/** One log line → { t, ip, ua, status, method, path, raw } (fields may be missing). Handles combined log format, JSON lines and CSV. */
export function parseLine(line) {
  const r = { t: parseTime(line), raw: line };
  let j = null;
  if (line.trim().startsWith('{')) { try { j = JSON.parse(line); } catch { j = null; } }
  if (j) {
    const g = (...k) => { for (const x of k) { const v = x.split('.').reduce((o, p) => (o == null ? o : o[p]), j); if (v != null && v !== '') return v; } return undefined; };
    r.ip = g('ip', 'ipAddress', 'remote_addr', 'client_ip', 'clientIp', 'src_ip', 'source.ip', 'c-ip', 'callerIpAddress');
    r.ua = g('user_agent', 'userAgent', 'http_user_agent', 'ua', 'cs(User-Agent)', 'user_agent.original');
    r.status = Number(g('status', 'status_code', 'statusCode', 'sc-status', 'response.status')) || undefined;
    r.path = g('path', 'uri', 'request_uri', 'url', 'cs-uri-stem', 'url.path');
    r.method = g('method', 'request_method', 'cs-method', 'http.request.method');
    r.app = g('appId', 'appDisplayName', 'app_id', 'servicePrincipalId');
    r.account = g('userPrincipalName', 'user', 'username', 'account');
    const ec = g('errorCode', 'status.errorCode', 'resultType', 'ResultType');
    if (ec != null) r.signin = String(ec) === '0' ? 'ok' : 'fail';
    if (r.t == null) { const tv = g('createdDateTime', 'time', 'timestamp', 'TimeGenerated', '@timestamp'); if (tv) r.t = typeof tv === 'number' ? (tv > 1e12 ? tv : tv * 1000) : Date.parse(tv); }
  } else {
    const cl = line.match(/^(\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+"(\S+)\s+(\S+)[^"]*"\s+(\d{3})\s+\S+(?:\s+"[^"]*"\s+"([^"]*)")?/);
    if (cl) { r.ip = cl[1]; r.method = cl[2]; r.path = cl[3]; r.status = +cl[4]; r.ua = cl[5]; }
    else {
      const ip = line.match(IPV4); if (ip) r.ip = ip[1];
      const ua = line.match(/"((?:Mozilla|curl|python|Go-http|okhttp|artex|norma|infra-hunt|verify-911)[^"]*)"/i); if (ua) r.ua = ua[1];
      const st = line.match(/\s(\d{3})\s/); if (st) r.status = +st[1];
    }
  }
  const aad = line.match(/AADSTS\d{5,8}/g); if (aad) r.aadsts = aad;
  // Firewall logs: iptables/ufw "SRC=… DPT=…", Windows pfirewall.log "date time DROP TCP src dst sport dport", JSON dest_port.
  let fw = line.match(/SRC=(\d{1,3}(?:\.\d{1,3}){3}).*?DPT=(\d+)/);
  if (fw) { r.ip = fw[1]; r.dport = +fw[2]; }
  else if ((fw = line.match(/\b(?:DROP|ALLOW|BLOCK|DENY)\s+(?:TCP|UDP)\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\d+\s+(\d+)/i))) { r.ip = fw[1]; r.dport = +fw[2]; r.blocked = /DROP|BLOCK|DENY/i.test(line); }
  else if (j) { const dp = j.dest_port ?? j.dst_port ?? j.dport ?? j['destination.port']; if (dp != null) r.dport = +dp; }
  if (!r.signin && /\b(sign-?in|login|logon)\b/i.test(line)) { if (/\b(success|succeeded)\b/i.test(line)) r.signin = 'ok'; else if (/\b(fail|failure|failed|denied|invalid)\b/i.test(line) || r.aadsts) r.signin = 'fail'; }
  if (typeof r.ip === 'string') { const m = r.ip.match(IPV4); r.ip = m ? m[1] : r.ip; }
  return r;
}

/**
 * ARTEX request rhythm: bursts of 1–14 requests about a second apart, then 25–31 s pauses while the model "thinks".
 * Returns { cycles, pauses, share, flagged } for one source's sorted timestamps (ms).
 */
export function rhythm(times) {
  const t = [...times].sort((a, b) => a - b);
  let cycles = 0, pauses = 0, burst = 1; const longGaps = [];
  for (let i = 1; i < t.length; i++) {
    const g = (t[i] - t[i - 1]) / 1000;
    if (g <= 2.5) { burst++; continue; }
    if (g >= 5) longGaps.push(g);
    if (g >= 24 && g <= 32) { pauses++; if (burst >= 1 && burst <= 14) cycles++; }
    burst = 1;
  }
  const share = longGaps.length ? pauses / longGaps.length : 0;
  return { cycles, pauses, share, flagged: cycles >= 3 && share >= 0.6 };
}

/** Analyse pasted or uploaded logs. Returns { findings: [{lv,title,text}], stats }. */
export function analyzeLogs(text, { maxLines = 200000, extraIps = {}, extraUAs = [] } = {}) {
  const badIps = { ...extraIps, ...ARTEX_IOCS.ips }; const uaList = [...ARTEX_IOCS.userAgents, ...extraUAs.filter(Boolean).map((u) => new RegExp(u.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i'))];
  const lines = String(text || '').split(/\r?\n/).filter((l) => l.trim()).slice(0, maxLines);
  const F = []; const add = (lv, title, txt) => F.push({ lv, title, text: txt });
  const byIp = new Map(); const uaHits = new Map(); const ipHits = new Map(); const ja4Hits = new Set();
  const aad = { AADSTS7000215: 0, AADSTS7000222: 0 }; const failIps = new Map(); const okAfterFail = new Set(); const appsByIp = new Map();
  const consoleRefs = new Set();
  for (const line of lines) {
    const r = parseLine(line);
    const ip = r.ip && IPV4.test(r.ip) ? r.ip : null;
    if (ip) { if (!byIp.has(ip)) byIp.set(ip, { times: [], fails: 0, authFails: 0, accounts: new Set(), n: 0, ports: new Map() }); const s = byIp.get(ip); s.n++; if (r.dport != null) s.ports.set(r.dport, Math.min(s.ports.get(r.dport) ?? Infinity, r.t ?? 0)); if (r.t != null) s.times.push(r.t); if (r.account) s.accounts.add(String(r.account).toLowerCase()); }
    if (r.ua && uaList.some((re) => re.test(r.ua))) uaHits.set(r.ua, (uaHits.get(r.ua) || 0) + 1);
    if (ip && badIps[ip]) ipHits.set(ip, (ipHits.get(ip) || 0) + 1);
    for (const j of ARTEX_IOCS.ja4) if (line.includes(j)) ja4Hits.add(j);
    if (/\b8787\b/.test(line) && /artex|自主渗透测试控制台/i.test(line)) consoleRefs.add(line.slice(0, 160));
    if (ARTEX_IOCS.dockerImages.some((d) => line.includes(d)) || line.includes(ARTEX_IOCS.binarySha256)) consoleRefs.add(line.slice(0, 160));
    for (const c of r.aadsts || []) if (c in aad) aad[c]++;
    const authPath = r.path && /(login|signin|sign-in|auth|token|session|password|reset|oauth|wp-login|xmlrpc)/i.test(r.path);
    const failed = r.signin === 'fail' || (authPath && (r.status === 401 || r.status === 403 || r.status === 429));
    if (ip && failed) { failIps.set(ip, (failIps.get(ip) || 0) + 1); byIp.get(ip).authFails++; }
    if (ip && r.signin === 'ok' && failIps.get(ip) && (r.aadsts || aad.AADSTS7000215 + aad.AADSTS7000222 > 0)) okAfterFail.add(ip);
    if (ip && r.app) { if (!appsByIp.has(ip)) appsByIp.set(ip, new Set()); appsByIp.get(ip).add(String(r.app)); }
  }
  for (const [ua, n] of uaHits) add(4, ARTEX_IOCS.userAgents.some((re) => re.test(ua)) ? 'ARTEX user agent' : 'Known attack-tool user agent', `${n} request${n > 1 ? 's' : ''} with “${ua}”. This is the ARTEX framework or its Norma toolkit probing your service. Block it and check what those requests reached.`);
  for (const [ip, n] of ipHits) add(4, ARTEX_IOCS.ips[ip] ? `Known ARTEX infrastructure: ${ip}` : `Known malicious server: ${ip}`, `${n} line${n > 1 ? 's' : ''} from ${ip} (${badIps[ip]}). Block it at the firewall and review everything it touched.`);
  for (const j of ja4Hits) add(3, 'ARTEX TLS fingerprint', `JA4 ${j} matches ARTEX agent traffic.`);
  for (const c of consoleRefs) add(4, 'ARTEX console or backdoored image referenced', c);
  for (const [ip, s] of byIp) {
    const rh = rhythm(s.times);
    if (rh.flagged) add(3, `Agent-like request rhythm from ${ip}`, `${rh.cycles} bursts each followed by a 25–31 s pause (${Math.round(rh.share * 100)}% of its long gaps). That “burst, then think” pattern is how AI attack agents such as ARTEX behave.`);
    if (s.ports.size >= 15) {
      const ports = [...s.ports.keys()].sort((a, b) => a - b);
      const risky = ports.filter((p) => [21, 22, 23, 25, 135, 139, 445, 1433, 3306, 3389, 5432, 5555, 5900, 6379, 8080, 8443, 8787, 9200, 27017].includes(p));
      add(s.ports.size >= 100 ? 4 : 3, `Port scan from ${ip}`, `${ip} tried ${ports.length} different ports (${ports.slice(0, 8).join(', ')}${ports.length > 8 ? '…' : ''})${risky.length ? `, including ${risky.slice(0, 6).join(', ')}` : ''}. Someone is mapping your system for a way in — block this address.`);
    }
    if (s.authFails >= 20) {
      const span = s.times.length > 1 ? (Math.max(...s.times) - Math.min(...s.times)) / 60e3 : 1;
      const rate = s.authFails / Math.max(1, span);
      add(rate >= 30 || s.accounts.size >= 10 ? 4 : 3, `Password attack from ${ip}`, `${s.authFails} failed sign-ins${s.accounts.size > 1 ? ` across ${s.accounts.size} accounts` : ''}, about ${Math.round(rate)} a minute. ARTEX-driven campaigns reached thousands of attempts a minute.`);
    }
  }
  if (aad.AADSTS7000215 + aad.AADSTS7000222 >= 5) add(3, 'Application secrets being guessed', `${aad.AADSTS7000215} wrong-secret (AADSTS7000215) and ${aad.AADSTS7000222} expired-secret (AADSTS7000222) errors. ARTEX agents test leaked app secrets this way.`);
  for (const ip of okAfterFail) add(4, `Secret guessed, then accepted: ${ip}`, 'Failed app sign-ins followed by a success from the same address. Treat the application credential as stolen: rotate it now and review what it accessed.');
  for (const [ip, apps] of appsByIp) if (apps.size >= 3) add(3, `One address signing in as ${apps.size} applications`, `${ip} used ${[...apps].slice(0, 5).join(', ')}${apps.size > 5 ? '…' : ''}. That is how stolen app credentials are tried in bulk.`);
  if (!F.length) add(1, 'No ARTEX traces found', `${lines.length.toLocaleString('en')} lines from ${byIp.size} addresses checked against ${ARTEX_IOCS.userAgents.length} user-agent patterns, ${Object.keys(ARTEX_IOCS.ips).length} known addresses, TLS fingerprints, request rhythm and sign-in patterns.`);
  return { findings: F.sort((a, b) => b.lv - a.lv), stats: { lines: lines.length, ips: byIp.size } };
}

/** Secret patterns for the leaked-credentials check (same list as the desktop agent's --secrets). */
export const SECRET_PATTERNS = [
  ['AWS access key', /\b(AKIA|ASIA)[0-9A-Z]{16}\b/],
  ['GitHub token', /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b/],
  ['Anthropic API key', /\bsk-ant-[A-Za-z0-9_-]{20,}\b/],
  ['OpenAI API key', /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b/],
  ['Google API key', /\bAIza[0-9A-Za-z_-]{35}\b/],
  ['Slack token', /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/],
  ['Stripe live key', /\b(sk|rk)_live_[A-Za-z0-9]{20,}\b/],
  ['Private key', /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/],
  ['Azure storage connection string', /DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{40,}/],
  ['Android keystore password', /\b(KEYSTORE|STORE|KEY)_?PASS(WORD)?\s*[=:]\s*["']?[^\s"'$]{6,}/i],
  ['Generic secret assignment', /\b(client_?secret|api_?key|secret_?key|access_?token|auth_?token|password)\b\s*[=:]\s*["'][A-Za-z0-9_\-+/=.]{16,}["']/i],
];
export function findSecrets(text) {
  const out = []; const lines = String(text || '').split(/\n/);
  lines.forEach((l, i) => { for (const [name, re] of SECRET_PATTERNS) { const m = l.match(re); if (m) { out.push({ line: i + 1, kind: name, preview: mask(m[0]) }); break; } } });
  return out;
}
export const mask = (s) => (s.length <= 10 ? '•'.repeat(s.length) : `${s.slice(0, 4)}${'•'.repeat(Math.min(12, s.length - 8))}${s.slice(-4)}`);

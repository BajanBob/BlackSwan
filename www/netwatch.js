// BlackSwan network intrusion monitor. Pure functions: take a reading plus the saved baseline, return findings and the new baseline.
// Fake towers (IMSI catchers), evil-twin Wi-Fi, gateway / DNS hijacks and proxy injection all show up as changes from what is normal for you.
import { Ewma } from './engine.js';

const GEN_RANK = { '2G': 2, '3G': 3, '4G': 4, '5G': 5 };

/** Mobile network reading from GuardCheck.network(). */
export function analyzeCells(net, base = {}) {
  const F = []; const b = structuredClone(base); b.cells ||= {}; b.areas ||= {}; b.gens ||= {};
  const add = (lv, title, text) => F.push({ lv, title, text });
  if (!net || net.noTelephony) return { findings: F, base: b };
  const reg = (net.cells || []).filter((c) => c.registered);
  for (const c of reg) {
    if (c.cell == null || c.cell === 2147483647) continue;
    const key = `${c.gen}:${c.cell}`, known = b.cells[key];
    const areaStats = new Ewma(b.areas[c.gen] || {});
    if (!known) {
      const z = c.dbm != null ? areaStats.z(c.dbm) : 0;
      if (Object.keys(b.cells).length >= 3 && z > 3) add(3, 'Unusually strong new tower', `Your phone joined a ${c.gen} tower it has never used before (cell ${c.cell}) with a signal ${Math.round(z)} standard deviations stronger than normal. Fake towers (IMSI catchers) often sit close by and shout loudest. Watch for calls dropping or a switch to 2G.`);
      else if (Object.keys(b.cells).length >= 3) add(1, 'New tower', `Joined ${c.gen} cell ${c.cell} for the first time. Normal when you travel.`);
    } else if (known.area != null && c.area != null && known.area !== c.area) {
      add(3, 'Tower identity changed', `Cell ${c.cell} used to belong to area ${known.area}; now it reports area ${c.area}. A real tower almost never changes area — a spoofed tower copying a real ID might.`);
    }
    if (c.dbm != null) { areaStats.push(c.dbm); b.areas[c.gen] = areaStats.toJSON(); }
    b.cells[key] = { area: c.area, seen: (known?.seen || 0) + 1, last: Date.now() };
  }
  const g = GEN_RANK[net.data];
  if (g) {
    b.gens[net.data] = (b.gens[net.data] || 0) + 1;
    const total = Object.values(b.gens).reduce((a, x) => a + x, 0);
    const usual = Object.entries(b.gens).sort((x, y) => y[1] - x[1])[0][0];
    if (total >= 5 && GEN_RANK[usual] - g >= 2) add(g <= 2 ? 3 : 2, `Downgraded to ${net.data}`, `Your phone usually uses ${usual} but is on ${net.data} now. Forced downgrades are how fake towers get around modern encryption. If you are somewhere with normal coverage, turn on Airplane mode for sensitive calls and turn off “Allow 2G”.`);
  }
  if (net.roaming && !b.everRoamed) add(1, 'Roaming', 'Your phone reports it is roaming. If you haven’t travelled, that can mean a foreign or fake network.');
  if (net.roaming) b.everRoamed = true;
  return { findings: F, base: b };
}

/** Wi-Fi / link reading from GuardCheck.wifi(). */
export function analyzeWifi(w, base = {}) {
  const F = []; const b = structuredClone(base); b.nets ||= {};
  const add = (lv, title, text) => F.push({ lv, title, text });
  if (!w) return { findings: F, base: b };
  if (w.proxy) add(3, 'Traffic sent through a proxy', `This connection goes through ${w.proxy}. If you didn’t set this, someone can read and change your traffic. Remove it in the Wi-Fi network’s settings (Proxy → None).`);
  if (w.captivePortal) add(2, 'Sign-in page network', 'This network wants you to log in through a web page (captive portal). Never install certificates, profiles or apps it asks for.');
  if (w.onWifi && w.validated === false && !w.captivePortal) add(2, 'Network can’t reach the internet properly', 'Android couldn’t verify this connection. Fake hotspots often fail this check.');
  if (!w.onWifi) return { findings: F, base: b };
  const ssid = w.ssid && w.ssid !== '<unknown ssid>' ? w.ssid : null;
  if (w.security === 0) add(2, 'Open Wi-Fi (no password)', 'Anyone nearby can see unencrypted traffic and pretend to be this hotspot. Use mobile data or a VPN you trust.');
  // Evil twin: the same network name offered both with and without a password, or with different security.
  if (ssid && Array.isArray(w.sameName) && w.sameName.length > 1) {
    const kinds = new Set(w.sameName.map((x) => (/(WPA|RSN|SAE|WEP)/i.test(x.caps || '') ? 'locked' : 'open')));
    if (kinds.size > 1) add(4, `Evil twin: two “${ssid}” networks`, 'One copy of this network name has a password and another is open. Attackers create open copies of real hotspots to sit in the middle of your traffic. Disconnect and forget the open one.');
  }
  if (!ssid) { if (!w.locationPermission) add(1, 'Allow location for Wi-Fi checks', 'Android only tells apps the Wi-Fi name and access point when location is allowed and switched on. Nothing leaves your phone.'); return { findings: F, base: b }; }
  const n = b.nets[ssid];
  if (!n) { b.nets[ssid] = { bssids: w.bssid ? [w.bssid] : [], gateway: w.gateway || '', dns: w.dns || [], first: Date.now() }; add(1, `Learning “${ssid}”`, 'BlackSwan has saved this network’s normal access point, router and DNS. It will warn you if they change.'); return { findings: F, base: b }; }
  if (w.bssid && !n.bssids.includes(w.bssid)) {
    const sameVendor = n.bssids.some((x) => x.slice(0, 8) === w.bssid.slice(0, 8));
    add(sameVendor ? 1 : 3, sameVendor ? 'Another access point of the same network' : `New, unfamiliar access point for “${ssid}”`, sameVendor ? 'Same maker as before — probably a second router or mesh unit.' : `This “${ssid}” is broadcast by a device from a different maker (${w.bssid.slice(0, 8)}) than usual. That can be a new router, or an evil-twin hotspot copying the name.`);
    if (n.bssids.length < 20) n.bssids.push(w.bssid);
  }
  if (w.gateway && n.gateway && w.gateway !== n.gateway) add(3, 'Router address changed', `On “${ssid}” your router used to be ${n.gateway}, now it is ${w.gateway}. A different router answering on a familiar network is a man-in-the-middle sign.`);
  const dnsNow = (w.dns || []).slice().sort().join(','), dnsWas = (n.dns || []).slice().sort().join(',');
  if (dnsNow && dnsWas && dnsNow !== dnsWas && !w.privateDnsActive) add(2, 'DNS servers changed', `“${ssid}” now hands out DNS ${dnsNow} (was ${dnsWas}). Changed DNS can send you to fake copies of real sites. Turn on Private DNS to protect yourself.`);
  if (w.gateway) n.gateway ||= w.gateway;
  if (!n.dns?.length && w.dns?.length) n.dns = w.dns;
  b.nets[ssid] = n;
  return { findings: F, base: b };
}

/** Desktop: ARP table pasted from `arp -a`. One hardware address claiming several IPs is the ARP-spoofing signature. */
export function analyzeArp(text, gateway = '') {
  const rows = [];
  for (const l of String(text || '').split(/\n/)) {
    const ip = l.match(/(\d{1,3}(?:\.\d{1,3}){3})/), mac = l.match(/\b([0-9a-f]{1,2}(?:[:-][0-9a-f]{1,2}){5})\b/i);
    if (!ip || !mac) continue;
    const m = mac[1].toLowerCase().split(/[:-]/).map((x) => x.padStart(2, '0')).join('-');
    if (m === 'ff-ff-ff-ff-ff-ff' || m === '00-00-00-00-00-00' || m.startsWith('01-00-5e') || m.startsWith('33-33')) continue;
    rows.push([ip[1], m]);
  }
  const by = {}; for (const [i, m] of rows) (by[m] ||= new Set()).add(i);
  const F = [];
  for (const [m, ips] of Object.entries(by)) if (ips.size > 1) {
    const gw = gateway && ips.has(gateway);
    F.push({ lv: gw ? 4 : 3, title: gw ? 'Router impersonated (ARP spoofing)' : 'One device claims several addresses', text: `${m} answers for ${[...ips].join(', ')}.${gw ? ' Your router is one of them — another device is pretending to be it. Disconnect from this network.' : ' This is the signature of ARP spoofing (some repeaters do it legitimately).'}` });
  }
  if (gateway && !rows.some((r) => r[0] === gateway)) F.push({ lv: 2, title: 'Router not in the table', text: `${gateway} isn’t listed. Open any website, then run arp -a again.` });
  if (!F.length) F.push({ lv: 1, title: 'No ARP spoofing seen', text: `${rows.length} devices checked; no duplicate hardware addresses.` });
  return F;
}

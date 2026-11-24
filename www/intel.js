// BlackSwan daily threat intelligence on the device: downloads www/intel/feed.json (rebuilt every day by
// .github/workflows/intel.yml from worldwide public feeds and the curated watch list), feeds it to the scanners,
// and raises an alert for each new warning. Falls back to the copy bundled with the app when offline.
import { setIntel } from './engine.js';
import { store, raise } from './bus.js';

export const REMOTE_FEED = 'https://raw.githubusercontent.com/BajanBob/BlackSwan/main/www/intel/feed.json';
const MAX_AGE = 20 * 3600e3;
let feed = null;
export const currentIntel = () => feed;

async function fetchJson(url) {
  const r = await fetch(url, { cache: 'no-store' });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const j = await r.json();
  if (j?.app !== 'BlackSwan') throw new Error('not a BlackSwan feed');
  return j;
}
function use(j, from) {
  feed = { ...j, from };
  setIntel(j);
  try { localStorage.setItem('bs.intel', JSON.stringify(j)); } catch { /* too big for storage: keep in memory */ }
  return feed;
}
function announce(j) {
  const seen = new Set(store.get('intel.seen', []));
  const fresh = (j.warnings || []).filter((w) => !seen.has(`${w.date}|${w.title}`));
  // World news is shown as Caution (amber): only signs aimed at you turn BlackSwan red. First run: announce only the top few.
  const first = !store.get('intel.seen', null);
  for (const w of (first ? fresh.filter((x) => x.level >= 3).slice(0, 3) : fresh)) raise(Math.min(2, w.level || 2), `Global warning: ${w.title}`, w.text || '', 'intel');
  store.set('intel.seen', [...seen, ...fresh.map((w) => `${w.date}|${w.title}`)].slice(-400));
}
/** Loads the newest feed: cached → online (if older than 20 h or forced) → bundled. */
export async function refreshIntel(force = false) {
  if (!feed) { try { const c = JSON.parse(localStorage.getItem('bs.intel') || 'null'); if (c) use(c, 'saved copy'); } catch { /* ignore */ } }
  const age = feed ? Date.now() - Date.parse(feed.updated) : Infinity;
  if (force || age > MAX_AGE || store.get('intel.checked', 0) < Date.now() - MAX_AGE) {
    try { const j = await fetchJson(`${REMOTE_FEED}?t=${Date.now()}`); use(j, 'online'); store.set('intel.checked', Date.now()); }
    catch (e) { if (!feed) { try { use(await fetchJson('intel/feed.json'), 'built in'); } catch { /* none */ } } if (feed) feed.error = String(e.message || e); }
  }
  if (feed) announce(feed);
  return feed;
}

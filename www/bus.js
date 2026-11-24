// Shared alert log and history for BlackSwan. Kept on the device only (localStorage); export it as JSON for MATLAB.
const K = 'bs.';
export const store = {
  get(k, d = null) { try { const v = localStorage.getItem(K + k); return v == null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem(K + k, JSON.stringify(v)); } catch { /* storage full or blocked */ } },
  del(k) { try { localStorage.removeItem(K + k); } catch { /* fine */ } },
};
const subs = new Set();
export const onAlert = (fn) => subs.add(fn);
export const alerts = () => store.get('alerts', []);
/** level: 1 info · 2 caution · 3 danger · 4 critical. Repeats of the same title within 10 minutes are merged. */
export function raise(level, title, detail = '', source = '') {
  const list = alerts(); const now = Date.now();
  const dup = list.find((a) => a.title === title && now - a.t < 600e3);
  if (dup) { dup.count = (dup.count || 1) + 1; dup.t = now; } else list.unshift({ level, title, detail, source, t: now });
  store.set('alerts', list.slice(0, 500));
  subs.forEach((fn) => fn({ level, dup: !!dup }));
}
export function clearAlerts() { store.set('alerts', []); subs.forEach((fn) => fn()); }
/** Appends a record to a capped history series (cells, wifi, unlocks, scans). */
export function record(series, item, cap = 1000) { const h = store.get('h.' + series, []); h.push({ t: Date.now(), ...item }); store.set('h.' + series, h.slice(-cap)); }
export const history = (series) => store.get('h.' + series, []);
/** Everything MATLAB needs (matlab/bs_load_export.m reads this). */
export function exportAll(extra = {}) {
  return { app: 'BlackSwan', format: 1, exported: new Date().toISOString(), alerts: alerts(),
    history: { cells: history('cells'), wifi: history('wifi'), unlocks: history('unlocks'), scans: history('scans') }, ...extra };
}

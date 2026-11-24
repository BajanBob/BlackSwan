// BlackSwan editions: Free, Plus, Family, Business. Licence keys are signed with the seller's private key
// (scripts/licence.mjs) and checked here offline with the public key in licence-key.json — no server, no account.
import { store } from './bus.js';

export const PLANS = {
  free: { name: 'Free', rank: 0 },
  plus: { name: 'Plus', rank: 1 },
  family: { name: 'Family', rank: 1 },
  business: { name: 'Business', rank: 2 },
};
export const PRICES = [
  { id: 'free', name: 'Free', price: 'US$0', per: 'forever', blurb: 'Check before you click.', features: ['Phone security check-up with spy-app detection', 'Link, QR-code and message scanner', 'Green / amber / red alerts with sound', 'Scam library and recovery assistant', 'Leaked-password check and password generator', 'Daily global warnings and safety tip'] },
  { id: 'plus', name: 'Plus', price: 'US$2.99', per: 'a month · or US$24.99 a year', blurb: 'Always-on protection for one person.', features: ['Everything in Free', 'Real-time scam guard for texts, chats and email', 'Intrusion monitor: fake towers, fake Wi-Fi, router and DNS hijacks', 'Certificate pinning and ARP-spoofing checks', 'Fingerprint vault, automatic password rotation, anti brute-force lock', 'Full daily briefing: exploited software and attacker groups', 'Learns from your answers', 'Windows and Linux desktop editions'] },
  { id: 'family', name: 'Family', price: 'US$39.99', per: 'a year · up to 5 people', blurb: 'Plus for the whole household.', features: ['Everything in Plus on up to 5 devices', 'One licence key to share with family'] },
  { id: 'business', name: 'Business', price: 'US$5', per: 'per device a month · sites from US$99 a month', blurb: 'For firms, IT providers and their clients.', features: ['Everything in Plus', 'ARTEX Shield: AI-attack-tool, port-scan and password-spray detection in logs', 'Leaked-secrets scanning and block lists', 'Alert export for MATLAB and security teams', 'Commercial-use licence and priority support', 'White-label for banks and carriers: ask us'] },
];
const TRIAL_DAYS = 14;

const b64u = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));
let KEY = null, CFG = { buyUrl: '', contact: '', channel: 'direct' };

async function publicKey() {
  if (KEY !== null) return KEY;
  try {
    const r = await fetch('licence-key.json', { cache: 'no-store' });
    const j = await r.json();
    KEY = j?.jwk?.x ? await crypto.subtle.importKey('jwk', j.jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']) : false;
  } catch { KEY = false; }
  return KEY;
}
/** Verifies "BSW1.<payload>.<signature>" and returns the licence, or null. */
export async function verifyLicence(text) {
  const m = String(text || '').trim().match(/^BSW1\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/);
  if (!m) return null;
  const key = await publicKey(); if (!key) return null;
  try {
    const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, b64u(m[2]), new TextEncoder().encode(m[1]));
    if (!ok) return null;
    const p = JSON.parse(new TextDecoder().decode(b64u(m[1])));
    if (!PLANS[p.p]) return null;
    return { plan: p.p, name: p.n || '', devices: p.d || 1, expires: p.x || null, id: p.i || '' };
  } catch { return null; }
}

let current = { plan: 'free' };
/** Works out the active plan: a valid, unexpired licence, else a running trial, else Free. */
export async function loadPlan() {
  try { const c = await (await fetch('edition.json', { cache: 'no-store' })).json(); CFG = { ...CFG, ...c }; } catch { /* defaults */ }
  const saved = store.get('licence', null);
  const lic = saved ? await verifyLicence(saved) : null;
  if (lic && (!lic.expires || Date.parse(lic.expires) > Date.now())) current = { ...lic, source: 'licence' };
  else {
    const t = store.get('trialStart', 0);
    current = t && Date.now() - t < TRIAL_DAYS * 864e5 ? { plan: 'plus', source: 'trial', expires: new Date(t + TRIAL_DAYS * 864e5).toISOString() } : { plan: 'free' };
    if (lic && lic.expires) current.expired = lic;
  }
  return current;
}
export const plan = () => current;
export const config = () => CFG;
export const can = (needed) => (PLANS[current.plan]?.rank ?? 0) >= (PLANS[needed]?.rank ?? 0);
export function startTrial() { if (store.get('trialStart', 0)) return false; store.set('trialStart', Date.now()); return true; }
export const trialUsed = () => !!store.get('trialStart', 0);
export async function applyLicence(text) { const lic = await verifyLicence(text); if (!lic) return null; store.set('licence', String(text).trim()); await loadPlan(); return lic; }
export function removeLicence() { store.del('licence'); }

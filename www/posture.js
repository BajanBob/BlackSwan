// BlackSwan threat posture: one colour for the whole screen plus sound, so a warning is impossible to miss.
//   GREEN  · Level 3 · All clear   — nothing open in the last 24 hours
//   AMBER  · Level 2 · Caution     — something needs checking
//   RED    · Level 1 · DANGER      — an attack sign or a dangerous link / message / network
import { store, alerts, onAlert } from './bus.js';

export const LEVELS = {
  green: { name: 'GREEN', label: 'Level 3 · All clear', color: '#1fbf7a', ink: '#03140c' },
  amber: { name: 'AMBER', label: 'Level 2 · Caution', color: '#ffb020', ink: '#1c1200' },
  red: { name: 'RED', label: 'Level 1 · DANGER', color: '#ff2d4a', ink: '#ffffff' },
};
const WINDOW = 24 * 3600e3;
/** Highest unacknowledged alert in the last 24 hours → green / amber / red. */
export function postureOf(list = alerts(), ackAt = store.get('ackAt', 0), now = Date.now()) {
  let top = 0;
  for (const a of list) if (a.t > ackAt && now - a.t < WINDOW) top = Math.max(top, a.level);
  return top >= 3 ? 'red' : top === 2 ? 'amber' : 'green';
}

// ---------- sound (Web Audio, no files needed) ----------
let ctx = null;
function audio() {
  if (!ctx) { const AC = window.AudioContext || window.webkitAudioContext; if (!AC) return null; ctx = new AC(); }
  if (ctx.state === 'suspended') ctx.resume().catch(() => {});
  return ctx;
}
function tone(c, freq, start, dur, type = 'sine', gain = 0.25, sweepTo = null) {
  const o = c.createOscillator(), g = c.createGain();
  o.type = type; o.frequency.setValueAtTime(freq, c.currentTime + start);
  if (sweepTo) o.frequency.linearRampToValueAtTime(sweepTo, c.currentTime + start + dur);
  g.gain.setValueAtTime(0.0001, c.currentTime + start);
  g.gain.exponentialRampToValueAtTime(gain, c.currentTime + start + 0.02);
  g.gain.exponentialRampToValueAtTime(0.0001, c.currentTime + start + dur);
  o.connect(g).connect(c.destination); o.start(c.currentTime + start); o.stop(c.currentTime + start + dur + 0.05);
}
/** Plays the sound for a level: green = soft rising chime, amber = two beeps, red = three-cycle siren. */
export function playLevel(level) {
  if (!store.get('sound', true)) return;
  const c = audio(); if (!c) return;
  if (level === 'green') { tone(c, 660, 0, 0.18); tone(c, 880, 0.16, 0.28); }
  else if (level === 'amber') { tone(c, 880, 0, 0.16, 'square', 0.12); tone(c, 880, 0.26, 0.16, 'square', 0.12); }
  else if (level === 'red') { for (let i = 0; i < 3; i++) { tone(c, 620, i * 0.8, 0.4, 'sawtooth', 0.16, 1250); tone(c, 1250, i * 0.8 + 0.4, 0.4, 'sawtooth', 0.16, 620); } }
  try { navigator.vibrate?.(level === 'red' ? [400, 150, 400, 150, 400] : level === 'amber' ? [180, 120, 180] : [60]); } catch { /* no vibration */ }
}
// Browsers only allow sound after a tap: unlock on the first one.
window.addEventListener('pointerdown', () => audio(), { once: true });

// ---------- colour ----------
let current = null;
export function paint(level, { flash = false } = {}) {
  const L = LEVELS[level]; const root = document.documentElement;
  root.dataset.threat = level;
  root.style.setProperty('--threat', L.color); root.style.setProperty('--threat-ink', L.ink);
  const bar = document.getElementById('threat-bar');
  if (bar) {
    bar.querySelector('b').textContent = `THREAT LEVEL ${L.name}`;
    bar.querySelector('span').textContent = L.label;
    bar.querySelector('button').hidden = level === 'green';
  }
  document.querySelector('meta[name=theme-color]')?.setAttribute('content', L.color);
  if (flash && store.get('flash', true)) {
    const f = document.getElementById('threat-flash');
    if (f) { f.classList.remove('go'); void f.offsetWidth; f.classList.add('go'); }
  }
}
function update(fromAlert, info = {}) {
  const level = postureOf();
  const worse = current && ['green', 'amber', 'red'].indexOf(level) > ['green', 'amber', 'red'].indexOf(current);
  paint(level, { flash: fromAlert && level !== 'green' });
  if (fromAlert && (worse || (level === 'red' && !info.dup && info.level >= 3))) playLevel(level);
  current = level;
}
export function acknowledge() { store.set('ackAt', Date.now()); update(false); playLevel('green'); }
export function startPosture() {
  update(false);
  onAlert((info) => update(true, info || {}));
  document.getElementById('threat-ack')?.addEventListener('click', acknowledge);
  setInterval(() => update(false), 60e3); // alerts age out of the 24-hour window
}

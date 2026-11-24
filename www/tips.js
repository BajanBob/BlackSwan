// BlackSwan hover info: point at any button or link (computer), tab to it (keyboard), or press and hold it
// for half a second (phone) to see what it does. Text comes from data-tip, then this list, then
// (for links) where the link goes. Built with textContent only — no HTML.
const TIPS = {
  'Check my phone': 'Run the security check-up (reads settings only, changes nothing)',
  'Check again': 'Run the security check-up again',
  'Update now': 'Open the system update screen',
  'Check for updates': 'Open the system update screen',
  'What to do': 'See what to do when a phone gets no more updates',
  'App settings': 'Open this app’s settings to see or remove its permissions',
  Uninstall: 'Ask Android to remove this app (Android asks you to confirm)',
  'Check mobile network': 'See which network and towers your phone is using (2G warning)',
  'Mobile network settings': 'Open mobile network settings, e.g. to turn off 2G',
  'Copy report': 'Copy the report to send to someone who helps you with your phone',
  'Developer options': 'Open Developer options to turn off USB debugging',
  'Security settings': 'Open your phone’s security settings',
  'Open Settings': 'Open your phone’s Settings',
  'Set a screen lock': 'Open screen lock settings to set a PIN',
  'How to restart': 'Show how to restart your phone',
  // BlackSwan tabs
  Phone: 'Phone check-up: updates, settings, risky apps, network and restart reminders',
  Links: 'Check a link before you open it — gives a phishing percentage',
  Messages: 'Paste an email, text, chat or pop-up to check it for scam tricks',
  Network: 'Watch for fake towers, fake Wi-Fi, router changes and man-in-the-middle attacks',
  'ARTEX Shield': 'Find traces of the ARTEX AI attack tool in your logs, and leaked passwords or keys',
  Guard: 'Strong passwords, fingerprint vault and the anti brute-force lock',
  Scams: 'Library of scams and takeover tricks, with red flags and how to stay safe',
  Briefing: 'Today’s worldwide threat warnings, exploited software and attacker groups',
  Plans: 'Free, Plus, Family and Business editions, free trial and licence keys',
  'Try Plus free for 14 days': 'Switch on every Plus feature for 14 days, no payment needed',
  Activate: 'Check and apply your licence key (works offline)',
  'See plans': 'Compare Free, Plus, Family and Business',
  Desktop: 'Desktop checker for Windows, macOS and Linux, and the MATLAB tools',
  // BlackSwan buttons
  'Scan link': 'Check this link (nothing is sent anywhere)',
  'Try a sample': 'Fill in a made-up example so you can see how it works',
  'Scan message': 'Check this message for scam tricks and dangerous links',
  'It was safe': 'Teach BlackSwan: this link was genuine (learning stays on this device)',
  'It was a scam': 'Teach BlackSwan: this link was a scam (learning stays on this device)',
  'Reset learning': 'Forget what BlackSwan learned from your answers',
  'Scan networks now': 'Compare your towers, Wi-Fi, router and DNS with what is normal for you',
  Analyse: 'Look for one device pretending to be another (ARP spoofing)',
  'Pin it': 'Save this site’s certificate fingerprint while you are on a network you trust',
  Compare: 'Check the certificate against the one you pinned',
  'Check for ARTEX': 'Check the pasted or chosen logs for ARTEX attack traffic',
  'Try a sample attack log': 'Load a made-up attack log to see what ARTEX traffic looks like',
  'Check for secrets': 'Look for passwords, tokens and API keys that should not be in this text',
  'Copy indicators': 'Copy the ARTEX block list for your firewall or security team',
  'New password': 'Make a new random password from your device’s secure random generator',
  Copy: 'Copy to the clipboard — clear it after pasting a password',
  'Save current password behind fingerprint': 'Store this password in your phone’s secure hardware; showing it needs your fingerprint',
  Show: 'Show this saved password after your fingerprint (hides again after 20 seconds)',
  Delete: 'Delete this saved password',
  'Set passphrase': 'Save the passphrase that unlocks BlackSwan (stored only as a stretched hash)',
  'Use generated': 'Use the password shown above as your passphrase',
  'Test unlock': 'Try unlocking: wrong tries lock you out for longer each time',
  'Turn on fingerprint': 'Require your fingerprint or face after the passphrase',
  Test: 'Check that your fingerprint works',
  'Turn off': 'Stop asking for your fingerprint',
  Unlock: 'Unlock BlackSwan',
  'Check now': 'Download today’s threat feed now',
  'Export for MATLAB': 'Copy your alerts and history as JSON for the MATLAB tools',
  Clear: 'Delete all alerts from this device',
  'Test green': 'Hear and see the all-clear signal',
  'Test amber': 'Hear and see the caution signal',
  'Test red': 'Hear and see the danger signal',
  Acknowledge: 'I have seen these alerts — set the threat level back to green',
  'Copy script': 'Copy the desktop checker so you can save it as blackswan_agent.py',
};
const PREFIX = [[/^Alerts/, 'Everything BlackSwan has warned you about; the number is open danger alerts'], [/^THREAT LEVEL/, 'Green: all clear · Amber: something to check · Red: danger aimed at you']];

const tip = document.createElement('div');
tip.className = 'tip'; tip.setAttribute('role', 'tooltip'); tip.id = 'gyp-tip'; tip.hidden = true;

function textFor(el) {
  if (el.dataset.tip) return el.dataset.tip;
  const label = (el.getAttribute('aria-label') && !TIPS[el.textContent.trim()] ? el.getAttribute('aria-label') : el.textContent).replace(/\s+/g, ' ').trim();
  if (TIPS[label]) return TIPS[label];
  for (const [re, t] of PREFIX) if (re.test(label)) return t;
  if (el.tagName === 'A' && el.href) {
    try {
      const u = new URL(el.href);
      if (/(^|\.)wa\.me$|whatsapp\.com$/.test(u.hostname)) return 'Opens WhatsApp';
      if (/openstreetmap\.org$/.test(u.hostname)) return 'Opens OpenStreetMap, who make the map';
      if (u.origin !== location.origin) return `Opens ${u.hostname.replace(/^www\./, '')} in a new tab`;
    } catch { /* not a URL */ }
  }
  return null;
}

let current = null, hideTimer = null, press = null;
function show(el) {
  const t = textFor(el);
  if (!t) return;
  current = el;
  if (!tip.isConnected) document.body.append(tip);
  tip.textContent = t; tip.hidden = false;
  el.setAttribute('aria-describedby', 'gyp-tip');
  const host = el.closest('dialog[open]') || document.body; // inside a dialog, the tip must live there to show on top
  if (tip.parentNode !== host) host.append(tip);
  const r = el.getBoundingClientRect(), w = Math.min(280, innerWidth - 16);
  tip.style.maxWidth = `${w}px`;
  const tw = tip.offsetWidth, th = tip.offsetHeight;
  const x = Math.max(8, Math.min(innerWidth - tw - 8, r.left + r.width / 2 - tw / 2));
  let y = r.top - th - 8; if (y < 8) y = r.bottom + 8;
  tip.style.left = `${x}px`; tip.style.top = `${y}px`;
}
function hide() { current?.removeAttribute('aria-describedby'); current = null; tip.hidden = true; }
const target = (e) => e.target.closest?.('[data-tip], a[href], button, summary');

export function installTips() {
  document.addEventListener('pointerover', (e) => { if (e.pointerType === 'mouse') { const el = target(e); if (el && el !== current) show(el); } });
  document.addEventListener('pointerout', (e) => { if (e.pointerType === 'mouse' && current && !current.contains(e.relatedTarget)) hide(); });
  document.addEventListener('focusin', (e) => { const el = target(e); if (el && el.matches(':focus-visible')) show(el); });
  document.addEventListener('focusout', hide);
  document.addEventListener('click', hide, true);
  addEventListener('scroll', hide, { passive: true, capture: true });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') hide(); });
  // Phones: press and hold to see what a button does.
  document.addEventListener('touchstart', (e) => {
    const el = target(e); if (!el) return;
    clearTimeout(press); press = setTimeout(() => { show(el); clearTimeout(hideTimer); hideTimer = setTimeout(hide, 2500); }, 500);
  }, { passive: true });
  for (const ev of ['touchend', 'touchmove', 'touchcancel']) document.addEventListener(ev, () => clearTimeout(press), { passive: true });
}

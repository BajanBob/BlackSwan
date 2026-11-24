// BlackSwan licence keys (run on YOUR computer, never in CI).
//   node scripts/licence.mjs init                       create your signing key; writes the public half to www/licence-key.json
//   node scripts/licence.mjs issue --plan plus --name "Jane Doe" --months 12 [--devices 1]
//   node scripts/licence.mjs issue --plan business --name "Acme Ltd" --months 1 --devices 25
//   node scripts/licence.mjs verify BSW1....
// The private key is saved to ~/.blackswan/licence-private.pem. Back it up somewhere safe and never commit or share it:
// anyone who has it can make licence keys.
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const DIR = path.join(os.homedir(), '.blackswan');
const PRIV = path.join(DIR, 'licence-private.pem');
const PUB = 'www/licence-key.json';
const PLANS = ['plus', 'family', 'business'];
const b64u = (b) => Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const arg = (name, d) => { const i = process.argv.indexOf(`--${name}`); return i > 0 ? process.argv[i + 1] : d; };
const cmd = process.argv[2];

if (cmd === 'init') {
  if (fs.existsSync(PRIV) && !process.argv.includes('--force')) { console.error(`A key already exists at ${PRIV}. Use --force to replace it (old licences stop working).`); process.exit(1); }
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  fs.mkdirSync(DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(PRIV, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  const jwk = publicKey.export({ format: 'jwk' });
  fs.writeFileSync(PUB, JSON.stringify({ about: 'Public key that checks BlackSwan licence keys (safe to publish).', jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } }, null, 2) + '\n');
  console.log(`Private key saved to ${PRIV} — back it up and keep it secret.\nPublic key written to ${PUB} — commit and push it so the apps can check licences.`);
} else if (cmd === 'issue') {
  const plan = arg('plan', 'plus');
  if (!PLANS.includes(plan)) { console.error(`--plan must be one of ${PLANS.join(', ')}`); process.exit(1); }
  const months = Number(arg('months', '12'));
  const exp = months > 0 ? new Date(Date.now() + months * 30.44 * 864e5).toISOString().slice(0, 10) : null;
  const payload = { p: plan, n: arg('name', ''), d: Number(arg('devices', plan === 'family' ? '5' : '1')), x: exp, i: crypto.randomUUID().slice(0, 8), t: new Date().toISOString().slice(0, 10) };
  const body = b64u(JSON.stringify(payload));
  const key = crypto.createPrivateKey(fs.readFileSync(PRIV));
  const sig = crypto.sign('sha256', Buffer.from(body), { key, dsaEncoding: 'ieee-p1363' });
  console.log(`BSW1.${body}.${b64u(sig)}`);
  console.error(`(${plan} for ${payload.n || 'customer'}, ${payload.d} device(s), ${exp ? 'until ' + exp : 'no expiry'}, id ${payload.i})`);
} else if (cmd === 'verify') {
  const m = String(process.argv[3] || '').match(/^BSW1\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/);
  if (!m) { console.error('Not a BlackSwan licence key'); process.exit(1); }
  const { jwk } = JSON.parse(fs.readFileSync(PUB, 'utf8'));
  const key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  const ok = crypto.verify('sha256', Buffer.from(m[1]), { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(m[2].replace(/-/g, '+').replace(/_/g, '/'), 'base64'));
  console.log(ok ? `Valid: ${Buffer.from(m[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString()}` : 'NOT valid'); process.exit(ok ? 0 : 1);
} else {
  console.log('Usage: node scripts/licence.mjs init | issue --plan plus|family|business --name NAME --months N [--devices N] | verify KEY');
}

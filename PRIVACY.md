# BlackSwan privacy notice

BlackSwan protects you without collecting your data. In short: **your messages, links, passwords, logs and device details stay on your device.** BlackSwan has no account, no tracking, no analytics and no advertising.

## What stays on your device
- Phone check-up results, apps list, network and Wi-Fi readings, and the baselines BlackSwan learns from them.
- Links, messages, QR codes, logs and text you scan.
- **Real-time scam guard (Android, opt-in):** when you allow notification access, BlackSwan reads new notifications on the phone to check them. It keeps only its warnings (app name, reason, links and a short snippet of the suspicious message) so it can show them to you. It does not keep or send ordinary messages. You can turn it off any time in Settings → Notification access.
- Passwords you generate, your passphrase (stored only as a salted PBKDF2 hash) and the fingerprint vault (Android Keystore / iPhone Keychain). BlackSwan never sees your fingerprint; the phone's own sensor confirms it.
- Your safe/scam answers used to personalise the link model, and your alert history.

## What BlackSwan downloads
- **The daily threat feed** from BlackSwan's GitHub repository (`www/intel/feed.json`). This is a plain download: nothing about you is sent with it beyond what any web request carries (your IP address, seen by GitHub).

## What leaves your device, and only when you ask
- **Leaked-password check:** only the first 5 characters of the password's SHA-1 fingerprint are sent to Have I Been Pwned (api.pwnedpasswords.com). Your password, and its full fingerprint, never leave the device.
- **Export for MATLAB** and **Copy report** put data on your clipboard; you decide where it goes.
- **Desktop host agent:** makes DNS-over-HTTPS and HTTPS test connections to well-known sites (Google, Microsoft, Apple, PayPal, GitHub, Amazon) to check for interception, and with `--artex` checks your own local network for an ARTEX console. Its report is saved on your computer only.

## Permissions (Android)
Phone state and location (to read mobile towers and Wi-Fi details — Android requires location permission for this), notifications (alerts and reminders), app list (to find risky and spy apps), biometrics (fingerprint vault and lock), notification access (scam guard, only if you turn it on).

## Contact
BajanBob — via https://github.com/BajanBob/BlackSwan. Design: Kammie Holder.

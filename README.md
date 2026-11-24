# BlackSwan

**Commercial alert and defence system against phishing, fake websites, redirects, man-in-the-middle attacks, takeover scams and intrusion — built on [GuardYourPhone](https://github.com/BajanBob/GuardYourPhone).** For Android, iPhone and the web, with a desktop host agent and a MATLAB analysis toolkit. Made for global use: no feature is tied to one country or carrier.

## What it does

| Tab | Protection |
|---|---|
| **Phone** | Everything from GuardYourPhone: security patch age and maker support, screen lock, encryption, verified boot and bootloader, root signs, USB debugging, apps with powerful access (accessibility, device admin, notification access, sideloaded, SMS / microphone), added certificates, proxies, Private DNS, Advanced Protection, Samsung Auto Blocker, a protection checklist (now with theft protection, Identity Check, passkeys and iPhone Stolen Device Protection), restart reminders at 5 am and 7 pm, service codes and a copyable report. |
| **Links** | Phishing probability for any link: typosquats and lookalikes, homograph (punycode) domains, `@` tricks, raw-IP hosts, redirect chains (followed and scored), shorteners, abused domain endings, free hosting, risky downloads and double extensions. |
| **Messages** | Scam-message scanner for email, SMS, chat and pop-ups: remote-access takeovers (AnyDesk, TeamViewer, ScreenConnect…), ClickFix “paste and run”, one-time-code theft, MFA fatigue, gift-card / crypto / wire demands, invoice and bank-detail fraud, sextortion, delivery, investment and authority scams; every link inside is scanned too. |
| **Network** | Intrusion monitor that learns your normal towers, Wi-Fi access points, router and DNS, then flags fake towers (unusually strong new tower, changed tower identity, forced 2G), evil-twin hotspots (same name open and locked, unfamiliar access-point maker), router and DNS changes, proxies and captive portals. Plus ARP-spoofing analysis for computers and certificate pinning. |
| **ARTEX Shield** | Finds traces of ARTEX, the AI attack framework used against banks, governments and software firms worldwide since 2026, and tools built on it (AntiFox): its user agents, servers and TLS fingerprints, its “burst, then think” request rhythm, password spraying and stolen-app-secret sign-ins in your web, proxy, firewall and cloud sign-in logs; a leaked-secrets check; a block list. |
| **Briefing** | Daily global threat briefing: live phishing sites (OpenPhish, Phishing.Database), botnet servers (abuse.ch Feodo Tracker), software holes being exploited now (CISA KEV), recently updated threat groups (MITRE ATT&CK) and BlackSwan’s own watch list of new attackers and AI attack tools. The feed is rebuilt every day and every scan uses it. |
| **Guard** | 15-character (adjustable) random passwords from the device's cryptographic generator, automatic rotation, a **fingerprint vault** in Android Keystore / iPhone Keychain, and an **anti brute-force lock**: PBKDF2 (310,000 rounds), doubling lockouts, a Poisson attack detector, fingerprint as second factor, optional lock on open and optional vault erase after 10 failures. |
| **Scams** | Searchable library of 28 takeover and fraud techniques with red flags and defences. |
| **Alerts** | Every danger in one log, exportable as JSON for MATLAB. |
| **Desktop** | `www/agent/blackswan_agent.py` — read-only Windows/macOS/Linux agent: ARP spoofing and router MAC changes, DNS hijack (vs DNS-over-HTTPS), TLS interception, hosts-file and proxy tampering, running remote-access tools; ARTEX Shield (`--artex` finds ARTEX consoles on your own network and booby-trapped copies, `--logs` checks logs, `--secrets` scans folders and git history for leaked keys). |

## Threat level: green, amber, red

The whole screen shows BlackSwan’s threat level, with sound and vibration:

* **GREEN · Level 3 · All clear** — nothing open in the last 24 hours (soft chime).
* **AMBER · Level 2 · Caution** — something to check: phone maintenance problems, world news, suspicious items (two beeps, amber frame).
* **RED · Level 1 · DANGER** — an attack sign aimed at you: dangerous link or message, fake tower, evil twin, ARTEX traffic, brute force (three-cycle siren, flashing red screen).

**Acknowledge** returns it to green. Sound and flashing can be switched off in the Alerts tab, which also has test buttons.

## Learning and daily checking

* **Learns from you:** after a link scan, “It was safe” / “It was a scam” updates the link model on the phone (online logistic regression, gently pulled back toward the built-in model).
* **Checks every day:** `.github/workflows/intel.yml` rebuilds `www/intel/feed.json` daily; the app downloads it when opened (at most every 20 hours) and reminds you at 8 am. New warnings appear as alerts and in the Briefing tab.
* **Watches for new attackers:** `www/intel/watch.json` is the curated list of new threat actors and AI attack tools with their indicators. A daily research task updates it; any change republishes the feed.

## How detection works

* `www/engine.js` — link and message scoring with a logistic model, `p = 1/(1+e^-(b+Σwᵢxᵢ))`, over 19 link features and 23 message rules; EWMA baselines; Poisson tail test; unbiased password generation.
* `www/netwatch.js` — tower, Wi-Fi and ARP anomaly rules.
* `www/artex.js` — ARTEX Shield indicators, log parser (combined log format, JSON lines, CSV), rhythm detector, spraying and secret checks.
* `www/intel.js`, `scripts/update-intel.mjs` — daily threat feed. `www/posture.js` — green / amber / red screen and sound.
* `matlab/` — the same features and statistics in MATLAB: train new link weights (written to `www/weights.json`, loaded by the app at start), replay network history, tune the brute-force alarm. See `matlab/README.md`.
* `native/android/.../GuardCheckPlugin.java` — GuardYourPhone's read-only Android checks plus `wifi()` for the intrusion monitor.
* Fingerprint / Face ID: `@capgo/capacitor-native-biometric` (Android BiometricPrompt, iOS LocalAuthentication; secrets kept in Keystore / Keychain). In a desktop browser the web build falls back to WebAuthn.

## Build

Every push to `main` runs the tests (`npm test`, agent compile check), builds the app and publishes a GitHub Release `v<version>` with `BlackSwan.apk` and `BlackSwan-iPhone-unsigned.ipa` (sign with an Apple Developer account). Add `ANDROID_KEYSTORE_BASE64`, `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS` and `ANDROID_KEY_PASSWORD` as repository secrets to sign the APK with your permanent key. Raise `version` in `package.json` for each release.

Preview in a browser: `npx serve www` (phone results are examples; the other tools work fully).

## Limits

BlackSwan reads only and sends nothing anywhere. No ordinary app can look inside the baseband chip, prove a phone is free of spyware, or stop an attack at the network level; Android hides some details (for example ARP tables) from apps. BlackSwan detects the signs that remain visible and tells you what to do.

## Licence

Proprietary — see `LICENSE`. Built on GuardYourPhone (same owner).

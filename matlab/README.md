# BlackSwan MATLAB toolkit

Analyse what BlackSwan sees and tune its detectors. Runs in MATLAB R2019b or newer and in GNU Octave 7+; no toolboxes needed.

| File | What it does |
|---|---|
| `bs_demo.m` | Try everything with a **synthetic** export (made-up readings): fake tower, evil-twin router change, brute-force burst. |
| `bs_load_export.m` | Reads the JSON from the app (Alerts tab → **Export for MATLAB**, saved as `blackswan_export.json`). |
| `bs_network_anomaly.m` | Replays the intrusion monitor: EWMA z-scores on tower signal, tower identity changes, 2G downgrades, Wi-Fi router / access-point changes. Charts the signal and the alarms. |
| `bs_bruteforce_model.m` | Fits the Poisson model behind the brute-force alarm to your own unlock history and suggests the alarm level. |
| `bs_artex_rhythm.m` | Tests request times from one address for the ARTEX “burst, then think” rhythm (same rule as the app) and plots the gap histogram. |
| `bs_alert_dashboard.m` | Alerts per day by severity and by source. |
| `bs_url_features.m` | The 19 link features, mirroring `www/engine.js` line for line. |
| `bs_train_url_model.m` | Trains the phishing-link model (regularised logistic regression, Newton/IRLS, 5-fold cross-validated AUC and ROC) and writes `www/weights.json`, which the app loads on start. |
| `bs_score_url.m` | Scores links exactly as the app does, with built-in or trained weights. |
| `bs_urls_sample.csv` | A small labelled starter set (60 links, genuine sites from around the world and typical phishing patterns). Add your own rows: `url,label` with 1 = phishing. |
| `bs_lists.m` | Brand, shortener, hosting and TLD lists plus default weights, generated from the app by `node scripts/gen-matlab-lists.mjs`. |

## Typical session

```matlab
cd matlab
bs_demo                                  % see it work on synthetic data
E = bs_load_export('blackswan_export.json');
bs_network_anomaly(E);
R = bs_bruteforce_model(E);              % put R.lambda into NORMAL_FAILS_PER_HOUR in www/console.js
bs_alert_dashboard(E);
M = bs_train_url_model('my_labelled_urls.csv');   % writes ../www/weights.json
```

Only ship trained weights when the cross-validated AUC beats the built-in weights (`M.aucCV` vs `M.aucDefault`) on a few hundred or more labelled links.

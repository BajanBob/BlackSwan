%BS_DEMO Try the BlackSwan MATLAB tools without a phone.
%   Builds a SYNTHETIC export (made-up readings, clearly not real data): two weeks of normal 4G
%   use, then a fake tower that appears with a very strong signal and forces 2G, an evil-twin Wi-Fi
%   router change, and a burst of wrong passphrases. Then runs every analysis.

rand('state', 7); randn('state', 7); %#ok<RAND>
ms = @(dn) round((dn - datenum(1970, 1, 1)) * 86400000);
t0 = floor(now) - 14;
cells = {}; wifi = {}; unlocks = {};
for i = 0:55
    t = t0 + i / 4;
    c = struct('registered', true, 'gen', '4G', 'cell', 21345600 + mod(i, 3), 'area', 1201, 'dbm', round(-97 + 3 * randn));
    cells{end + 1} = struct('t', ms(t), 'operator', 'Example Mobile', 'data', '4G', 'cells', c); %#ok<SAGROW>
    wifi{end + 1} = struct('t', ms(t), 'ssid', 'Home', 'bssid', 'a4:2b:b0:11:22:33', 'gateway', '192.168.1.1', 'dns', {{'192.168.1.1'}}); %#ok<SAGROW>
    unlocks{end + 1} = struct('t', ms(t), 'ok', rand > 0.05); %#ok<SAGROW>
end
t = t0 + 14.2;
cells{end + 1} = struct('t', ms(t), 'operator', 'Example Mobile', 'data', '2G', 'cells', struct('registered', true, 'gen', '4G', 'cell', 99999, 'area', 1201, 'dbm', -52));
cells{end + 1} = struct('t', ms(t + 0.01), 'operator', 'Example Mobile', 'data', '2G', 'cells', struct('registered', true, 'gen', '4G', 'cell', 21345601, 'area', 4444, 'dbm', -60));
wifi{end + 1} = struct('t', ms(t), 'ssid', 'Home', 'bssid', 'f0:9f:c2:00:aa:01', 'gateway', '192.168.1.66', 'dns', {{'192.168.1.66'}});
for k = 1:9, unlocks{end + 1} = struct('t', ms(t + k / 1440), 'ok', false); end %#ok<SAGROW>
alerts = {struct('level', 4, 'title', 'Unusually strong new tower', 't', ms(t), 'source', 'network'), ...
          struct('level', 3, 'title', 'Router address changed', 't', ms(t), 'source', 'network'), ...
          struct('level', 4, 'title', 'Brute-force attack on BlackSwan lock', 't', ms(t + 0.01), 'source', 'guard'), ...
          struct('level', 3, 'title', 'Dangerous link: paypa1-login.top', 't', ms(t0 + 3), 'source', 'links')};
J = struct('app', 'BlackSwan', 'format', 1, 'exported', datestr(now, 'yyyy-mm-ddTHH:MM:SS'), 'alerts', {alerts}, ...
    'history', struct('cells', {cells}, 'wifi', {wifi}, 'unlocks', {unlocks}, 'scans', {{}}));
file = fullfile(tempdir, 'blackswan_demo_export.json');
fid = fopen(file, 'w'); fprintf(fid, '%s', jsonencode(J)); fclose(fid);
fprintf('Synthetic export written to %s\n\n', file);

E = bs_load_export(file);
fprintf('\n--- Network anomalies ---\n'); bs_network_anomaly(E);
fprintf('\n--- Brute-force model ---\n'); bs_bruteforce_model(E);
fprintf('\n--- Alerts ---\n'); bs_alert_dashboard(E);
fprintf('\n--- Link model (writes weights to a temp file, not into the app) ---\n');
bs_train_url_model([], fullfile(tempdir, 'blackswan_weights_demo.json'));
p = bs_score_url({'https://www.paypal.com/signin', 'http://secure-paypa1.com.account-verify.top/login'});
fprintf('\nScores with built-in weights: genuine %.1f%%, phishing %.1f%%\n', 100 * p(1), 100 * p(2));

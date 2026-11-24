function R = bs_network_anomaly(E)
%BS_NETWORK_ANOMALY Replay BlackSwan's intrusion monitor over exported history and chart it.
%   R = bs_network_anomaly(bs_load_export('blackswan_export.json'))
%   Uses the same statistics as www/netwatch.js: an exponentially weighted mean/variance of the
%   signal of the towers you use (alpha 0.2, 4 dB^2 floor, 5-reading warm-up). Flags
%     - a never-seen tower more than 3 standard deviations stronger than normal (IMSI-catcher sign)
%     - a known tower that reports a different area code (spoofed identity)
%     - a drop of two or more generations from your usual one (forced 2G downgrade)
%     - a Wi-Fi network whose router address or access-point maker changes (evil twin / MITM)

alpha = 0.2; floorVar = 4; z0 = 3;
rank = containers.Map({'2G', '3G', '4G', '5G'}, {2, 3, 4, 5});
known = containers.Map(); areaStats = containers.Map(); gens = containers.Map();
ev = struct('t', {}, 'kind', {}, 'text', {});
T = []; D = []; Z = []; G = {};
for i = 1:numel(E.cells)
    s = E.cells{i};
    t = double(s.t) / 86400000 + datenum(1970, 1, 1);
    C = s.cells; if isstruct(C), C = num2cell(C(:)'); end
    for j = 1:numel(C)
        c = C{j};
        if ~isfield(c, 'registered') || ~c.registered || ~isfield(c, 'cell') || isempty(c.cell), continue; end
        gen = c.gen; key = sprintf('%s:%d', gen, c.cell);
        if isKey(areaStats, gen), st = areaStats(gen); else, st = [0 0 0]; end % [n mean var]
        dbm = NaN; if isfield(c, 'dbm') && ~isempty(c.dbm), dbm = double(c.dbm); end
        z = 0; if st(1) >= 5 && ~isnan(dbm), z = (dbm - st(2)) / sqrt(st(3) + floorVar); end
        if ~isKey(known, key)
            if known.Count >= 3 && z > z0
                ev(end + 1) = struct('t', t, 'kind', 'strong new tower', 'text', sprintf('%s cell %d at %g dBm (z = %.1f)', gen, c.cell, dbm, z)); %#ok<AGROW>
            end
        else
            k = known(key);
            if isfield(c, 'area') && ~isempty(c.area) && ~isempty(k) && k ~= c.area
                ev(end + 1) = struct('t', t, 'kind', 'tower identity changed', 'text', sprintf('cell %d area %d -> %d', c.cell, k, c.area)); %#ok<AGROW>
            end
        end
        if ~isnan(dbm)
            if st(1) == 0, st = [1 dbm 0]; else, d = dbm - st(2); st(2) = st(2) + alpha * d; st(3) = (1 - alpha) * (st(3) + alpha * d^2); st(1) = st(1) + 1; end
            areaStats(gen) = st;
        end
        if isfield(c, 'area') && ~isempty(c.area), known(key) = c.area; else, known(key) = []; end
        T(end + 1) = t; D(end + 1) = dbm; Z(end + 1) = z; G{end + 1} = gen; %#ok<AGROW>
    end
    if isfield(s, 'data') && ~isempty(s.data) && isKey(rank, s.data)
        if isKey(gens, s.data), gens(s.data) = gens(s.data) + 1; else, gens(s.data) = 1; end
        ks = keys(gens); vs = cell2mat(values(gens));
        [~, m] = max(vs); usual = ks{m};
        if sum(vs) >= 5 && rank(usual) - rank(s.data) >= 2
            ev(end + 1) = struct('t', t, 'kind', 'downgrade', 'text', sprintf('usually %s, now %s', usual, s.data)); %#ok<AGROW>
        end
    end
end

nets = containers.Map();
for i = 1:numel(E.wifi)
    w = E.wifi{i};
    if ~isfield(w, 'ssid') || isempty(w.ssid) || strcmp(w.ssid, '<unknown ssid>'), continue; end
    t = double(w.t) / 86400000 + datenum(1970, 1, 1);
    b = ''; if isfield(w, 'bssid') && ~isempty(w.bssid), b = lower(w.bssid); end
    gw = ''; if isfield(w, 'gateway') && ~isempty(w.gateway), gw = w.gateway; end
    if ~isKey(nets, w.ssid), nets(w.ssid) = struct('bssids', {{b}}, 'gateway', gw); continue; end
    n = nets(w.ssid);
    if ~isempty(b) && ~any(strcmp(n.bssids, b))
        sameMaker = any(strncmp(n.bssids, b, 8));
        if ~sameMaker, ev(end + 1) = struct('t', t, 'kind', 'unfamiliar access point', 'text', sprintf('"%s" from %s', w.ssid, b(1:min(8, end)))); end %#ok<AGROW>
        n.bssids{end + 1} = b;
    end
    if ~isempty(gw) && ~isempty(n.gateway) && ~strcmp(gw, n.gateway)
        ev(end + 1) = struct('t', t, 'kind', 'router changed', 'text', sprintf('"%s" %s -> %s', w.ssid, n.gateway, gw)); %#ok<AGROW>
    end
    if isempty(n.gateway), n.gateway = gw; end
    nets(w.ssid) = n;
end

R.events = ev; R.t = T; R.dbm = D; R.z = Z; R.gen = G;
fprintf('%d network anomalies found\n', numel(ev));
for i = 1:numel(ev), fprintf('  %s  %-24s %s\n', datestr(ev(i).t, 'yyyy-mm-dd HH:MM'), ev(i).kind, ev(i).text); end

if ~isempty(T)
    figure('Name', 'BlackSwan towers');
    subplot(2, 1, 1); plot(T, D, '.-'); hold on;
    hit = Z > z0; plot(T(hit), D(hit), 'ro', 'MarkerSize', 10, 'LineWidth', 2); hold off;
    datetick('x', 'mm-dd HH:MM'); ylabel('Signal (dBm)'); title('Signal of the tower your phone used'); grid on;
    subplot(2, 1, 2); stem(T, Z); hold on; plot([min(T) max(T)], [z0 z0], 'r--'); hold off;
    datetick('x', 'mm-dd HH:MM'); ylabel('z-score'); title('How unusual each reading was (red line = alarm)'); grid on;
end
end

function S = bs_alert_dashboard(E)
%BS_ALERT_DASHBOARD Summary charts of BlackSwan alerts: per day by severity, and by source.
%   S = bs_alert_dashboard(bs_load_export('blackswan_export.json'))

a = E.alerts;
if isempty(a.t), fprintf('No alerts in this export.\n'); S = struct(); return; end
names = {'Info', 'Caution', 'Danger', 'Critical'};
day = floor(a.t);
days = (min(day):max(day))';
counts = zeros(numel(days), 4);
for i = 1:numel(day), counts(day(i) - days(1) + 1, a.level(i)) = counts(day(i) - days(1) + 1, a.level(i)) + 1; end
[src, ~, idx] = unique(a.source(:));
src(cellfun(@isempty, src)) = {'(other)'};
bySource = accumarray(idx, 1);
S.days = days; S.counts = counts; S.sources = src; S.bySource = bySource;
fprintf('%d alerts: %d critical, %d danger, %d caution, %d info\n', numel(a.t), sum(a.level == 4), sum(a.level == 3), sum(a.level == 2), sum(a.level == 1));
for i = 1:numel(src), fprintf('  %-10s %d\n', src{i}, bySource(i)); end

figure('Name', 'BlackSwan alerts');
subplot(2, 1, 1);
bar(days, counts, 'stacked'); datetick('x', 'mm-dd'); legend(names, 'Location', 'northwest');
ylabel('Alerts'); title('Alerts per day by severity'); grid on;
subplot(2, 1, 2);
barh(bySource); set(gca, 'YTick', 1:numel(src), 'YTickLabel', src);
xlabel('Alerts'); title('Where alerts came from'); grid on;
end

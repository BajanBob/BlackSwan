function R = bs_bruteforce_model(E, alarmP)
%BS_BRUTEFORCE_MODEL Fit the Poisson model behind BlackSwan's brute-force alarm to your own unlock history.
%   R = bs_bruteforce_model(bs_load_export('blackswan_export.json'))
%   R = bs_bruteforce_model(E, 1e-3)   alarm probability (default 0.001, as in the app)
%   Estimates your normal failed unlocks per hour (lambda, maximum likelihood) and the number of
%   failures in one hour that is too unlikely to be typos. Put R.lambda into NORMAL_FAILS_PER_HOUR
%   in www/console.js to tune the app to you.

if nargin < 2 || isempty(alarmP), alarmP = 1e-3; end
t = E.unlocks.t(:); ok = E.unlocks.ok(:);
if isempty(t), error('bs_bruteforce_model:empty', 'No unlock attempts in this export yet.'); end
hours = max(1, (max(t) - min(t)) * 24);
fails = ~ok;
R.lambda = max(0.05, sum(fails) / hours);
R.lambdaApp = 0.5;
R.threshold = first_k(R.lambda, alarmP);
R.thresholdApp = first_k(R.lambdaApp, alarmP);
edges = floor(min(t) * 24):ceil(max(t) * 24) + 1;
perHour = histc(t(fails) * 24, edges);
R.worstHour = max([0; perHour(:)]);
R.pWorst = ptail(R.worstHour, R.lambda);
fprintf('Unlock attempts: %d (%d failed) over %.1f hours\n', numel(t), sum(fails), hours);
fprintf('Normal failure rate (MLE): %.3f per hour  (app default %.2f)\n', R.lambda, R.lambdaApp);
fprintf('Alarm at %d or more failures in an hour for p < %g  (app default: %d)\n', R.threshold, alarmP, R.thresholdApp);
fprintf('Worst hour: %d failures, chance from typos alone %.2g\n', R.worstHour, R.pWorst);

figure('Name', 'BlackSwan brute-force model');
k = 0:max(12, R.worstHour + 2);
bar(k, arrayfun(@(x) ppmf(x, R.lambda), k)); hold on;
plot([R.threshold R.threshold] - 0.5, [0 1], 'r--', 'LineWidth', 2); hold off;
set(gca, 'YScale', 'log'); ylim([1e-12 1]);
xlabel('Failed unlocks in one hour'); ylabel('Probability by chance');
title(sprintf('Poisson(\\lambda = %.2f): alarm from %d failures', R.lambda, R.threshold)); grid on;
end

function k = first_k(lambda, alarmP)
k = 1; while ptail(k, lambda) >= alarmP && k < 1000, k = k + 1; end
end

function p = ptail(k, lambda)
% P(X >= k) for X ~ Poisson(lambda), without toolboxes
if k <= 0, p = 1; return; end
term = exp(-lambda); cdf = term;
for i = 1:k - 1, term = term * lambda / i; cdf = cdf + term; end
p = max(0, 1 - cdf);
end

function p = ppmf(k, lambda)
p = exp(-lambda + k * log(lambda) - gammaln(k + 1));
end

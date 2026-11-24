function M = bs_train_url_model(csvFile, outFile, lambda)
%BS_TRAIN_URL_MODEL Train BlackSwan's phishing-link model and export weights the app loads.
%   M = bs_train_url_model()                  trains on bs_urls_sample.csv, writes ../www/weights.json
%   M = bs_train_url_model(csvFile, outFile)  CSV with columns url,label (1 = phishing, 0 = genuine)
%   M = bs_train_url_model(csvFile, outFile, lambda)  lambda = pull toward the app's built-in weights (default 1)
%
%   Model: L2-regularised logistic regression fitted with Newton's method (IRLS), shrunk toward the
%   app's default weights so a small labelled set refines them instead of overfitting. Reports 5-fold
%   cross-validated AUC and accuracy, plots the ROC curve, and writes weights.json, which BlackSwan
%   loads at start-up (www/weights.json). No toolboxes needed; runs in MATLAB and GNU Octave 7+.

here = fileparts(mfilename('fullpath'));
if nargin < 1 || isempty(csvFile), csvFile = fullfile(here, 'bs_urls_sample.csv'); end
if nargin < 2 || isempty(outFile), outFile = fullfile(here, '..', 'www', 'weights.json'); end
if nargin < 3 || isempty(lambda), lambda = 1; end

[urls, y] = read_labels(csvFile);
[X, names] = bs_url_features(urls);
L = bs_lists();
w0 = [L.defaultBias, L.defaultW]';
n = numel(y);

% 5-fold cross-validation (stratification is not needed for a quick check; fixed seed for repeatability)
if exist('rng', 'file') == 2 || exist('rng', 'builtin') == 5, rng(2040); else, rand('state', 2040); end %#ok<RAND>
k = min(5, n);
fold = mod(randperm(n), k)' + 1;
pcv = zeros(n, 1);
for f = 1:k
    tr = fold ~= f; te = ~tr;
    w = fit(X(tr, :), y(tr), w0, lambda);
    pcv(te) = sig([ones(sum(te), 1) X(te, :)] * w);
end
w = fit(X, y, w0, lambda);
A = [ones(n, 1) X];
M.names = names;
M.bias = w(1);
M.w = w(2:end)';
M.aucDefault = auc(sig(A * w0), y);
M.aucTrain = auc(sig(A * w), y);
M.aucCV = auc(pcv, y);
M.accCV = mean((pcv >= 0.4) == y);   % 0.4 = the app's "Dangerous" threshold

fprintf('BlackSwan link model: %d links (%d phishing)\n', n, sum(y));
fprintf('  AUC  built-in weights %.3f | trained %.3f | 5-fold CV %.3f\n', M.aucDefault, M.aucTrain, M.aucCV);
fprintf('  CV accuracy at the 40%% "Dangerous" threshold: %.1f%%\n', 100 * M.accCV);
fprintf('  %-20s %8s %8s\n', 'feature', 'default', 'trained');
for j = 1:numel(names), fprintf('  %-20s %8.2f %8.2f\n', names{j}, w0(j + 1), w(j + 1)); end
fprintf('  %-20s %8.2f %8.2f\n', 'bias', w0(1), w(1));

S.bias = w(1);
for j = 1:numel(names), S.w.(names{j}) = w(j + 1); end
S.trained = datestr(now, 'yyyy-mm-ddTHH:MM:SS');
S.samples = n;
S.aucCV = M.aucCV;
fid = fopen(outFile, 'w');
if fid < 0, error('bs_train_url_model:write', 'Cannot write %s', outFile); end
fprintf(fid, '%s\n', jsonencode(S));
fclose(fid);
fprintf('Weights written to %s (BlackSwan loads them on next start).\n', outFile);

[fpr, tpr] = roc(pcv, y);
figure('Name', 'BlackSwan link model');
plot(fpr, tpr, 'LineWidth', 2); hold on; plot([0 1], [0 1], ':'); hold off;
xlabel('False alarms (genuine links flagged)'); ylabel('Phishing caught');
title(sprintf('Cross-validated ROC, AUC = %.3f', M.aucCV)); grid on; axis([0 1 0 1]);
end

function w = fit(X, y, w0, lambda)
% Newton / IRLS for: minimise  -log-likelihood + lambda/2 * ||w - w0||^2
A = [ones(size(X, 1), 1) X];
R = lambda * eye(numel(w0));
w = w0;
for it = 1:100
    p = sig(A * w);
    g = A' * (p - y) + R * (w - w0);
    H = A' * (A .* (p .* (1 - p))) + R;
    step = H \ g;
    w = w - step;
    if norm(step) < 1e-9, break; end
end
end

function p = sig(z)
p = 1 ./ (1 + exp(-z));
end

function a = auc(p, y)
% Probability that a random phishing link scores above a random genuine one (Mann-Whitney).
pos = p(y == 1); neg = p(y == 0);
if isempty(pos) || isempty(neg), a = NaN; return; end
s = 0;
for i = 1:numel(pos), s = s + sum(pos(i) > neg) + 0.5 * sum(pos(i) == neg); end
a = s / (numel(pos) * numel(neg));
end

function [fpr, tpr] = roc(p, y)
t = [Inf; sort(unique(p), 'descend'); -Inf];
fpr = zeros(numel(t), 1); tpr = fpr;
for i = 1:numel(t)
    hit = p >= t(i);
    tpr(i) = sum(hit & y == 1) / max(1, sum(y == 1));
    fpr(i) = sum(hit & y == 0) / max(1, sum(y == 0));
end
end

function [urls, y] = read_labels(file)
fid = fopen(file, 'r');
if fid < 0, error('bs_train_url_model:read', 'Cannot open %s', file); end
C = textscan(fid, '%s %f', 'Delimiter', ',', 'HeaderLines', 1);
fclose(fid);
urls = C{1}; y = C{2};
keep = ~isnan(y) & ~cellfun(@isempty, urls);
urls = urls(keep); y = double(y(keep) > 0);
end

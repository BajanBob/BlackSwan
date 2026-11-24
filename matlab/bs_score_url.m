function [p, X] = bs_score_url(urls, weightsFile)
%BS_SCORE_URL Phishing probability for links, exactly as the BlackSwan app computes it.
%   p = bs_score_url({'https://paypa1-login.top/verify'})          built-in weights
%   p = bs_score_url(urls, fullfile('..','www','weights.json'))    weights trained by bs_train_url_model
%   (The app also follows redirect targets one level deeper; this scores the link as given.)

L = bs_lists();
b = L.defaultBias; w = L.defaultW(:);
if nargin >= 2 && ~isempty(weightsFile)
    S = jsondecode(fileread(weightsFile));
    b = S.bias;
    w = cellfun(@(nm) S.w.(nm), L.features)';
end
X = bs_url_features(urls);
p = 1 ./ (1 + exp(-(b + X * w)));
end

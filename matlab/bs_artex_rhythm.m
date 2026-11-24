function R = bs_artex_rhythm(t, label)
%BS_ARTEX_RHYTHM Test request times from one source for the ARTEX "burst, then think" rhythm.
%   R = bs_artex_rhythm(t)          t = request times in seconds (any origin), e.g. from a web log
%   R = bs_artex_rhythm(t, '198.51.100.77')
%   AI attack agents send bursts of 1-14 requests about a second apart, then pause 25-31 s while the
%   model decides the next step (Unit 42, 2026). Same rule as www/artex.js: flagged when there are at
%   least 3 burst+pause cycles and at least 60% of the gaps longer than 5 s fall in 24-32 s.
%   Plots the gap histogram on a log scale so the "thinking" peak stands out.
%
%   Demo (synthetic):  t = cumsum([repmat([0.8 0.8 0.8 28], 1, 8) 3 + 60*rand(1, 20)]); bs_artex_rhythm(t)

if nargin < 2, label = 'source'; end
t = sort(t(:));
g = diff(t);
cycles = 0; pauses = 0; burst = 1;
for i = 1:numel(g)
    if g(i) <= 2.5, burst = burst + 1; continue; end
    if g(i) >= 24 && g(i) <= 32
        pauses = pauses + 1;
        if burst >= 1 && burst <= 14, cycles = cycles + 1; end
    end
    burst = 1;
end
longGaps = sum(g >= 5);
R.cycles = cycles; R.pauses = pauses;
R.share = 0; if longGaps > 0, R.share = pauses / longGaps; end
R.flagged = cycles >= 3 && R.share >= 0.6;
fprintf('%s: %d requests, %d burst+pause cycles, %.0f%% of long gaps in 24-32 s -> %s\n', label, numel(t), cycles, 100 * R.share, ...
    ifelse(R.flagged, 'AGENT-LIKE (ARTEX rhythm)', 'not agent-like'));
if numel(g) > 1
    figure('Name', ['ARTEX rhythm: ' label]);
    edges = logspace(-1, 3, 41);
    n = histc(max(g, 0.1), edges);
    bar(log10(edges), n, 'histc');
    hold on; yl = ylim; patch(log10([24 32 32 24]), [0 0 yl(2) yl(2)], 'r', 'FaceAlpha', 0.15, 'EdgeColor', 'none'); hold off;
    set(gca, 'XTick', log10([0.1 1 10 30 100 1000]), 'XTickLabel', {'0.1', '1', '10', '30', '100', '1000'});
    xlabel('Gap between requests (s, log scale)'); ylabel('Count');
    title(sprintf('%s: shaded band = model "thinking" pause', label)); grid on;
end
end

function v = ifelse(c, a, b)
if c, v = a; else, v = b; end
end

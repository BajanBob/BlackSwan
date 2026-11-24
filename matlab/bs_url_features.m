function [X, names] = bs_url_features(urls)
%BS_URL_FEATURES Feature matrix for links, mirroring analyzeURL() in www/engine.js.
%   [X, names] = bs_url_features(urls) takes a cell array of link strings and returns an
%   n-by-19 matrix (one row per link) plus the feature names, in the app's order.
%   Works in MATLAB R2019b+ and GNU Octave 7+ (no toolboxes).
%
%   Example:
%     X = bs_url_features({'https://www.paypal.com/signin', 'http://paypa1-login.top/verify'})

if ischar(urls), urls = {urls}; end
L = bs_lists();
names = L.features;
X = zeros(numel(urls), numel(names));
for i = 1:numel(urls)
    X(i, :) = one(strtrim(urls{i}), L);
end
end

function x = one(raw, L)
f = @(name) find(strcmp(L.features, name));
x = zeros(1, numel(L.features));
raw = regexprep(raw, '^hxxp', 'http', 'ignorecase');
raw = strrep(raw, '[.]', '.');
if isempty(raw) || ~isempty(regexpi(raw, '^(javascript|vbscript|data):', 'once')), return; end
hadScheme = ~isempty(regexp(raw, '^[a-zA-Z][a-zA-Z0-9+.-]*://', 'once'));
u = raw; if ~hadScheme, u = ['http://' raw]; end
scheme = lower(regexprep(u, '://.*$', ''));
rest = u(numel(scheme) + 4:end);
cut = regexp(rest, '[/?#]', 'once');
if isempty(cut), authority = rest; tail = ''; else, authority = rest(1:cut - 1); tail = rest(cut:end); end
rawHost = authority;
at = find(authority == '@', 1, 'last');
hostport = authority; if ~isempty(at), hostport = authority(at + 1:end); end
host = hostport; port = '';
if ~isempty(host) && host(1) == '['
    cb = find(host == ']', 1); port = regexprep(host(cb + 1:end), '^:', ''); host = host(1:cb);
else
    c = find(host == ':', 1, 'last'); if ~isempty(c), port = host(c + 1:end); host = host(1:c - 1); end
end
host = lower(regexprep(host, '\.$', ''));
q = find(tail == '?', 1); h = find(tail == '#', 1);
if isempty(h), h = numel(tail) + 1; end
if isempty(q) || q > h, pathname = tail(1:h - 1); query = ''; else, pathname = tail(1:q - 1); query = tail(q + 1:h - 1); end
if isempty(pathname), pathname = '/'; end

labels = strsplit(host, '.'); tld = labels{end};
rd = regdomain(host); dot = find(rd == '.', 1); if isempty(dot), label = rd; else, label = rd(1:dot - 1); end

if strcmp(scheme, 'http') && hadScheme, x(f('http')) = 1; end
if ~isempty(at), x(f('at_sign')) = 1; end
if ~isempty(regexp(host, '^\d{1,3}(\.\d{1,3}){3}$', 'once')) || (~isempty(host) && host(1) == '[') || ~isempty(regexpi(rawHost, '^(0x[0-9a-f]+|\d{8,10})$', 'once'))
    x(f('ip_host')) = 1;
end
if ~isempty(strfind(host, 'xn--')) || any(double(rawHost) > 127), x(f('punycode')) = 1; end
if numel(labels) > 4, x(f('deep_subdomains')) = 1; end
if sum(host == '-') >= 3, x(f('many_hyphens')) = 1; end
if any(strcmp(L.abusedTlds, tld)), x(f('abused_tld')) = 1; end
if ~isempty(port) && ~any(strcmp(port, {'80', '443'})), x(f('odd_port')) = 1; end
if any(strcmp(L.shorteners, host)), x(f('shortener')) = 1; end

tokens = regexp(host, '[.-]', 'split'); tokens = tokens(~cellfun(@isempty, tokens));
nt = cellfun(@deconfuse, tokens, 'UniformOutput', false);
for b = 1:size(L.brands, 1)
    brand = L.brands{b, 1}; off = L.brands{b, 2};
    if isofficial(host, off), continue; end
    if numel(brand) >= 5
        nl = deconfuse(label);
        if strcmp(label, brand), x(f('brand_regional')) = 1; break; end
        d = lev(nl, brand);
        if strcmp(nl, brand) || d == 1 || (numel(brand) >= 8 && d == 2), x(f('typosquat')) = 1; break; end
        if any(strcmp(nt, brand)) || ~isempty(strfind(deconfuse(strrep(host, '.', '')), brand)), x(f('brand_impersonation')) = 1; break; end
    elseif any(strcmp(tokens, brand)) && ~strcmp(label, brand)
        x(f('brand_impersonation')) = 1; break;
    end
end

pathq = lower([pathname, ifelse(isempty(query), '', ['?' query])]);
kw = 0;
for k = 1:numel(L.loginWords)
    w = L.loginWords{k};
    if ~isempty(strfind(host, w)) || ~isempty(strfind(pathq, w)), kw = kw + 1; end
end
x(f('login_words')) = min(5, kw) / 5;
for k = 1:numel(L.freeHosts)
    d = L.freeHosts{k};
    if strcmp(host, d) || endswith_(host, ['.' d]), x(f('free_hosting')) = 1; break; end
end
if ~isempty(regexpi(pathname, '\.(exe|scr|js|jse|vbs|vbe|hta|iso|img|msi|lnk|bat|cmd|ps1|jar|apk|dmg|pkg|zip|rar|7z|xll|one|svg|html?)$', 'once')), x(f('risky_download')) = 1; end
if ~isempty(regexpi(pathname, '\.(pdf|docx?|xlsx?|jpg|png)\.(exe|scr|js|bat|cmd|lnk|hta)$', 'once')), x(f('double_extension')) = 1; end
if numel(raw) > 120, x(f('long_url')) = 1; end
if numel(regexp(raw, '%[0-9a-fA-F]{2}')) > 8, x(f('heavy_encoding')) = 1; end
redirect = false;
if ~isempty(query)
    pairs = strsplit(query, '&');
    for k = 1:numel(pairs)
        kv = pairs{k}; e = find(kv == '=', 1); if isempty(e), continue; end
        key = lower(kv(1:e - 1)); val = kv(e + 1:end);
        if any(strcmp(L.redirectKeys, key)) && ~isempty(regexpi(val, '^(https?:)?//|^www\.|^https?%3a', 'once')), redirect = true; break; end
    end
end
if ~isempty(regexpi(pathname, '/(https?://|https?%3a)', 'once')), redirect = true; end
x(f('redirect')) = double(redirect);
end

function r = regdomain(h)
p = strsplit(h, '.');
if numel(p) <= 2, r = h; return; end
sld = {'co', 'com', 'org', 'net', 'gov', 'ac', 'edu', 'gob', 'or', 'ne', 'go', 'mil', 'nic', 'gv'};
if numel(p{end}) == 2 && any(strcmp(sld, p{end - 1})), r = strjoin(p(end - 2:end), '.'); else, r = strjoin(p(end - 1:end), '.'); end
end

function s = deconfuse(s)
s = lower(s);
s = strrep(s, 'rn', 'm'); s = strrep(s, 'vv', 'w');
s = strrep(s, '0', 'o'); s = regexprep(s, '[1!|]', 'l'); s = strrep(s, '3', 'e');
s = regexprep(s, '[4@]', 'a'); s = regexprep(s, '[5$]', 's'); s = strrep(s, '7', 't'); s = strrep(s, '8', 'b');
s = regexprep(s, '[-_]', '');
end

function d = lev(a, b)
m = numel(a); n = numel(b);
if abs(m - n) > 2, d = 9; return; end
prev = 0:n;
for i = 1:m
    cur = [i, zeros(1, n)];
    for j = 1:n
        cur(j + 1) = min([prev(j + 1) + 1, cur(j) + 1, prev(j) + (a(i) ~= b(j))]);
    end
    prev = cur;
end
d = prev(end);
end

function t = isofficial(host, list)
t = false;
for k = 1:numel(list)
    if strcmp(host, list{k}) || endswith_(host, ['.' list{k}]), t = true; return; end
end
end

function t = endswith_(s, suffix)
t = numel(s) >= numel(suffix) && strcmp(s(end - numel(suffix) + 1:end), suffix);
end

function v = ifelse(c, a, b)
if c, v = a; else, v = b; end
end

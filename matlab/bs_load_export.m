function E = bs_load_export(file)
%BS_LOAD_EXPORT Read a BlackSwan export (Alerts tab → "Export for MATLAB", saved as JSON).
%   E = bs_load_export('blackswan_export.json')
%   E.alerts  struct with vectors t (datenum, UTC), level (1–4), and cells title, source, detail
%   E.cells   cell array of mobile-network scans; E.wifi Wi-Fi scans; E.unlocks lock attempts (t, ok)

if nargin < 1 || isempty(file), file = 'blackswan_export.json'; end
J = jsondecode(fileread(file));
if ~isfield(J, 'app') || ~strcmp(J.app, 'BlackSwan'), warning('bs_load_export:format', 'This does not look like a BlackSwan export.'); end
A = aslist(getf(J, 'alerts', {}));
E.alerts.t = cellfun(@(a) ms2dn(getf(a, 't', 0)), A(:));
E.alerts.level = cellfun(@(a) getf(a, 'level', 1), A(:));
E.alerts.title = cellfun(@(a) getf(a, 'title', ''), A(:), 'UniformOutput', false);
E.alerts.source = cellfun(@(a) getf(a, 'source', ''), A(:), 'UniformOutput', false);
E.alerts.detail = cellfun(@(a) getf(a, 'detail', ''), A(:), 'UniformOutput', false);
H = getf(J, 'history', struct());
E.cells = aslist(getf(H, 'cells', {}));
E.wifi = aslist(getf(H, 'wifi', {}));
U = aslist(getf(H, 'unlocks', {}));
E.unlocks.t = cellfun(@(u) ms2dn(getf(u, 't', 0)), U(:));
E.unlocks.ok = logical(cellfun(@(u) getf(u, 'ok', true), U(:)));
E.scans = aslist(getf(H, 'scans', {}));
E.exported = getf(J, 'exported', '');
fprintf('BlackSwan export %s: %d alerts, %d network scans, %d Wi-Fi scans, %d unlock attempts\n', ...
    E.exported, numel(E.alerts.t), numel(E.cells), numel(E.wifi), numel(E.unlocks.t));
end

function d = ms2dn(ms)
d = double(ms) / 86400000 + datenum(1970, 1, 1);
end

function v = getf(s, name, default)
if isstruct(s) && isfield(s, name) && ~isempty(s.(name)), v = s.(name); else, v = default; end
end

function c = aslist(x)
% jsondecode gives a struct array when every object has the same fields, otherwise a cell array.
if isempty(x), c = {}; elseif iscell(x), c = x(:)'; elseif isstruct(x), c = num2cell(x(:)'); else, c = {}; end
end

// BlackSwan desktop (Windows and Linux). Serves the app from a private local web server on 127.0.0.1 so it runs
// exactly like the phone and web versions (modules, threat feed, WebAuthn need a proper http origin), then opens it
// in a window. Nothing listens on the network: the server accepts connections from this computer only.
const { app, BrowserWindow, shell } = require('electron');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, 'www');
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.png': 'image/png', '.svg': 'image/svg+xml', '.py': 'text/plain; charset=utf-8', '.txt': 'text/plain; charset=utf-8' };
const PORTS = [47811, 47812, 47813, 47814]; // fixed, so saved settings (stored per address) survive restarts

function serve(i = 0) {
  return new Promise((resolve, reject) => {
    const s = http.createServer((req, res) => {
      let p;
      try { p = decodeURIComponent(new URL(req.url, 'http://127.0.0.1').pathname); } catch { res.writeHead(400); return res.end(); }
      if (p === '/') p = '/index.html';
      const f = path.normalize(path.join(ROOT, p));
      if (!f.startsWith(ROOT + path.sep)) { res.writeHead(403); return res.end(); }
      fs.readFile(f, (err, data) => {
        if (err) { res.writeHead(404); return res.end(); }
        res.writeHead(200, { 'content-type': TYPES[path.extname(f).toLowerCase()] || 'application/octet-stream', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
        res.end(data);
      });
    });
    s.once('error', (e) => (i + 1 < PORTS.length ? serve(i + 1).then(resolve, reject) : reject(e)));
    s.listen(PORTS[i], '127.0.0.1', () => resolve(PORTS[i]));
  });
}

if (!app.requestSingleInstanceLock()) app.quit();
let win = null;
app.on('second-instance', () => { if (win) { if (win.isMinimized()) win.restore(); win.focus(); } });

app.whenReady().then(async () => {
  const port = await serve();
  const origin = `http://127.0.0.1:${port}`;
  win = new BrowserWindow({ width: 1100, height: 880, minWidth: 380, backgroundColor: '#070d14', title: 'BlackSwan', icon: path.join(__dirname, 'icon.png'),
    webPreferences: { contextIsolation: true, sandbox: true, nodeIntegration: false } });
  win.setMenuBarVisibility(false);
  // Links to other sites open in the normal browser, never inside BlackSwan.
  win.webContents.setWindowOpenHandler(({ url }) => { if (/^https?:\/\//.test(url)) shell.openExternal(url); return { action: 'deny' }; });
  win.webContents.on('will-navigate', (e, url) => { if (!url.startsWith(origin + '/')) { e.preventDefault(); if (/^https?:\/\//.test(url)) shell.openExternal(url); } });
  win.loadURL(`${origin}/index.html`);
});
app.on('window-all-closed', () => app.quit());

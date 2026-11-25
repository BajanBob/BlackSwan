#!/usr/bin/env python3
"""BlackSwan host agent - read-only defensive checks for MITM, DNS hijack,
TLS interception, hosts/proxy tampering and remote-access takeover tools.
Usage:  python3 blackswan_agent.py --baseline        (first run, trusted network)
        python3 blackswan_agent.py                   (later runs)
ARTEX Shield (AI attack framework):
        python3 blackswan_agent.py --artex           also scan your own local network for exposed ARTEX consoles
        python3 blackswan_agent.py --logs FILE ...   check web/proxy/sign-in logs for ARTEX traffic
        python3 blackswan_agent.py --secrets PATH .. scan folders and git history for leaked keys
Open ports: every run lists the ports this computer listens on and flags risky ones open to the network. and tokens
Standard library only. Works on Windows, macOS and Linux."""
import calendar, concurrent.futures, hashlib, ipaddress, json, os, platform, re, socket, ssl, subprocess, sys, time, urllib.request

BASE = os.path.join(os.path.expanduser("~"), ".blackswan_baseline.json")
REPORT = os.path.join(os.path.expanduser("~"), "blackswan_report.json")
WATCH = ["google.com", "microsoft.com", "apple.com", "paypal.com", "github.com", "amazon.com"]
REMOTE_TOOLS = ["anydesk", "teamviewer", "rustdesk", "ultraviewer", "screenconnect", "connectwise",
                "logmein", "splashtop", "supremo", "quickassist", "ammyy", "rutserv", "rfusclient",
                "atera", "netsupport", "client32", "action1", "simplehelp", "remotepc", "zohoassist"]
alerts = []

def alert(level, msg):
    alerts.append({"level": level, "msg": msg, "time": time.strftime("%Y-%m-%d %H:%M:%S")})
    print(f"[{level}] {msg}")

def run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout
    except Exception:
        return ""

def default_gateway():
    s = platform.system()
    if s == "Windows":
        m = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", run(["route", "print", "-4"]))
    elif s == "Darwin":
        m = re.search(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", run(["route", "-n", "get", "default"]))
    else:
        m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", run(["ip", "route"]))
    return m.group(1) if m else None

def arp_table():
    out = run(["arp", "-a"])
    if not out and os.path.exists("/proc/net/arp"):
        with open("/proc/net/arp") as f:
            out = f.read()
    pairs = []
    for line in out.splitlines():
        ip = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
        mac = re.search(r"\b([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})\b", line)
        if not (ip and mac):
            continue
        m = "-".join(p.zfill(2) for p in re.split("[:-]", mac.group(1).lower()))
        if m in ("ff-ff-ff-ff-ff-ff", "00-00-00-00-00-00") or m.startswith("01-00-5e") or m.startswith("33-33"):
            continue
        pairs.append((ip.group(1), m))
    return pairs

def check_arp(base):
    pairs = arp_table()
    by_mac = {}
    for ip, mac in pairs:
        by_mac.setdefault(mac, set()).add(ip)
    for mac, ips in by_mac.items():
        if len(ips) > 1:
            alert("HIGH", f"MAC {mac} answers for several IPs {sorted(ips)} - possible ARP spoofing")
    gw = default_gateway()
    table = dict(pairs)
    gmac = table.get(gw) if gw else None
    old = base.get("gateway", {}).get(gw or "", None)
    if gw and gmac and old and gmac != old:
        alert("CRITICAL", f"Router {gw} MAC changed {old} -> {gmac} - classic man-in-the-middle sign")
    if gw and gmac and len(by_mac.get(gmac, ())) > 1:
        alert("CRITICAL", f"Another device shares your router's MAC {gmac} - ARP spoofing likely")
    print(f"Router {gw or 'unknown'}  MAC {gmac or 'unknown'}")
    return {gw: gmac} if gw and gmac else {}

def doh(name):
    ips = set()
    for url in (f"https://cloudflare-dns.com/dns-query?name={name}&type=A",
                f"https://dns.google/resolve?name={name}&type=A"):
        try:
            req = urllib.request.Request(url, headers={"accept": "application/dns-json"})
            with urllib.request.urlopen(req, timeout=8) as r:
                data = json.load(r)
            ips |= {a["data"] for a in data.get("Answer", []) if a.get("type") == 1}
        except Exception:
            pass
    return ips

def check_dns():
    for d in WATCH:
        try:
            local = {ai[4][0] for ai in socket.getaddrinfo(d, 443, socket.AF_INET)}
        except Exception:
            alert("MEDIUM", f"Could not resolve {d}")
            continue
        private = [i for i in local if ipaddress.ip_address(i).is_private or ipaddress.ip_address(i).is_loopback]
        if private:
            alert("HIGH", f"{d} resolves to private address {private} - DNS hijack or hosts-file redirect")
        remote = doh(d)
        if remote and not (local & remote):
            alert("LOW", f"{d}: local DNS {sorted(local)} differs from DNS-over-HTTPS {sorted(remote)} (CDNs can differ; re-check if repeated)")

def issuer_org(cert):
    for rdn in cert.get("issuer", ()):
        for k, v in rdn:
            if k == "organizationName":
                return v
    return "unknown"

def check_tls(base):
    seen = {}
    ctx = ssl.create_default_context()
    for d in WATCH:
        try:
            with socket.create_connection((d, 443), timeout=8) as s:
                with ctx.wrap_socket(s, server_hostname=d) as t:
                    der = t.getpeercert(binary_form=True)
                    org = issuer_org(t.getpeercert())
            fp = hashlib.sha256(der).hexdigest()
            seen[d] = {"issuer": org, "sha256": fp}
            old = base.get("tls", {}).get(d)
            if old and old["issuer"] != org:
                alert("HIGH", f"{d} certificate issuer changed '{old['issuer']}' -> '{org}' - possible TLS interception")
            elif old and old["sha256"] != fp:
                alert("INFO", f"{d} certificate renewed (same issuer {org})")
        except ssl.SSLCertVerificationError as e:
            alert("CRITICAL", f"{d} certificate NOT trusted ({e.verify_message}) - interception likely, avoid this network")
        except Exception as e:
            alert("MEDIUM", f"{d} TLS check failed: {e}")
    return seen

def check_hosts():
    path = r"C:\Windows\System32\drivers\etc\hosts" if platform.system() == "Windows" else "/etc/hosts"
    try:
        with open(path, errors="ignore") as f:
            lines = [l.split("#")[0].split() for l in f]
    except Exception:
        return
    for parts in lines:
        if len(parts) < 2:
            continue
        for name in parts[1:]:
            if name in ("localhost", "localhost.localdomain", "broadcasthost", "ip6-localhost", "ip6-loopback"):
                continue
            lvl = "HIGH" if any(name == w or name.endswith("." + w) for w in WATCH) else "INFO"
            alert(lvl, f"Hosts file maps {name} -> {parts[0]} - confirm you added this")

def check_proxy():
    for scheme, url in urllib.request.getproxies().items():
        if scheme in ("http", "https", "ftp", "all", "socks"):
            alert("MEDIUM", f"System {scheme} traffic goes through proxy {url} - confirm you set this")

def check_remote_tools():
    out = run(["tasklist"]) if platform.system() == "Windows" else run(["ps", "-A", "-o", "comm="])
    low = out.lower()
    for tool in REMOTE_TOOLS:
        if tool in low:
            alert("HIGH", f"Remote-access tool running: {tool}. If a caller asked you to install it, disconnect from the internet now")

# ---------------------------------------------------------------- ARTEX Shield
# Indicators from public reporting (Microsoft, Unit 42, CrowdStrike, Censys, BadByte, StepSecurity, Sophos, Talos,
# ThreatDefence, SOCRadar, Elastic, CERT-In), up to 2026-11-25. Mirrors www/artex.js.
ARTEX_UA = [re.compile(p, re.I) for p in (r"artex-enrich/\d", r"\bnorma/0\.\d", r"compatible;\s*artex/\d", r"compatible;\s*infra-hunt/\d", r"verify-911-probe/\d", r"artex-pentest/\d", r"\bartex\b")]
ARTEX_IPS = {"91.92.240.238", "85.11.168.45", "178.16.54.129", "31.77.229.35", "199.19.77.84", "65.87.223.26", "157.22.126.128",
             "144.172.64.60", "144.172.64.99", "144.172.64.128", "38.244.50.120", "154.64.252.77", "183.1.65.106", "95.169.20.166", "203.190.1.60", "43.240.29.11"}
ARTEX_JA4 = {"t13d3013h1_1d37bd780c83_8537cf56674e", "t13d3013h2_1d37bd780c83_8537cf56674e", "t13d3014h1_1d37bd780c83_5ae85263eb3b"}
ARTEX_IMAGES = ("tomicdd/artex", "congdonglinux/artex")
ARTEX_SHA256 = "d5070f52262effe216b840711343bff8f2787f39208d887d8dfd9c673f8d1573"
ARTEX_PORT = 8787
ARTEX_ARTIFACTS = re.compile(r"[\\/]ProgramData[\\/]artx5v\b|[\\/]Temp[\\/]artx[\w.-]*|[\\/]tmp[\\/]artx[\w.-]*", re.I)
CALLBACKS = ("webhook.site", "requestbin", "pipedream.net", "interact.sh", "oast.fun", "oast.pro", "oast.live", "oast.site", "oast.online",
             "oast.me", "burpcollaborator.net", "oastify.com", "dnslog.cn", "ceye.io", "ngrok-free.app", "ngrok.io", "ngrok.app",
             "trycloudflare.com", "serveo.net", "loca.lt")
AI_APIS = ("api.deepseek.com", "open.bigmodel.cn", "api.z.ai", "api.x.ai", "api.anthropic.com", "api.openai.com", "openrouter.ai",
           "api.moonshot.cn", "api.moonshot.ai", "dashscope.aliyuncs.com")
HARVEST = re.compile(r'"(?:GET|POST|HEAD) (\S*?(?:\.js\.map|/\.env|/\.git/|/\.aws/|/config\.(?:json|js|ya?ml)|/actuator/(?:env|heapdump|configprops)|/server-status|/phpinfo|/swagger|/api-docs|/web\.config|/appsettings[\w.]*\.json)\S*)', re.I)
TOOL_UA = (("curl", r"\bcurl/"), ("wget", r"\bwget/"), ("Python", r"python-requests|python-urllib|aiohttp|httpx"), ("Go", r"Go-http-client"),
           ("Nuclei", r"nuclei"), ("Nmap", r"nmap"), ("sqlmap", r"sqlmap"), ("ffuf", r"\bffuf\b"), ("gobuster", r"gobuster"),
           ("Nikto", r"nikto"), ("zgrab", r"zgrab"), ("PowerShell", r"WindowsPowerShell"))
LATERAL_PORTS = {135, 445, 3389, 5985, 5986}

def local_ipv4():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 80))  # no packet is sent; this only picks the outgoing interface
        return s.getsockname()[0]
    except Exception:
        return None
    finally:
        s.close()

def probe_console(ip):
    try:
        with socket.create_connection((ip, ARTEX_PORT), timeout=0.6) as c:
            c.settimeout(2)
            c.sendall(f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
            data = c.recv(8192).decode("utf-8", "ignore")
        title = re.search(r"<title>(.*?)</title>", data, re.I | re.S)
        return ip, (title.group(1).strip() if title else "")
    except Exception:
        return None

def check_artex_lan():
    me = local_ipv4()
    if not me:
        return
    net = ipaddress.ip_network(me + "/24", strict=False)
    print(f"Scanning your own network {net} for ARTEX consoles on port {ARTEX_PORT}...")
    hosts = ["127.0.0.1"] + [str(h) for h in net.hosts()]
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
        for r in ex.map(probe_console, hosts):
            if not r:
                continue
            ip, title = r
            if re.match(r"\s*ARTEX", title, re.I) or "自主渗透测试控制台" in title:
                alert("CRITICAL", f"ARTEX attack console running on {ip}:{ARTEX_PORT} ('{title}'). If it is not yours, isolate that device now")
            else:
                alert("LOW", f"Something answers on {ip}:{ARTEX_PORT} (title '{title or 'none'}') - the ARTEX console port; check what it is")

def check_artex_local():
    if os.path.exists("/app/artex"):
        try:
            with open("/app/artex", "rb") as f:
                h = hashlib.sha256(f.read()).hexdigest()
            if h == ARTEX_SHA256:
                alert("CRITICAL", "Backdoored ARTEX binary at /app/artex - anyone can run commands as root through its login form. Rebuild this machine and rotate every key on it")
            else:
                alert("HIGH", "ARTEX binary present at /app/artex - confirm it is an authorised copy")
        except Exception:
            pass
    imgs = run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"])
    ps = run(["docker", "ps", "-a", "--format", "{{.Image}} {{.Ports}}"])
    for line in (imgs + "\n" + ps).splitlines():
        low = line.lower()
        if any(i in low for i in ARTEX_IMAGES):
            alert("CRITICAL", f"Backdoored ARTEX Docker image on this machine: {line.strip()}. Remove it, rebuild the host and rotate all AI and cloud keys used in it")
        elif "artex" in low:
            alert("HIGH", f"ARTEX container or image: {line.strip()}")
        if f"0.0.0.0:{ARTEX_PORT}" in line or f":::{ARTEX_PORT}" in line:
            alert("HIGH", f"A container publishes port {ARTEX_PORT} on all interfaces: {line.strip()}. Bind it to 127.0.0.1")
    home = os.path.expanduser("~")
    for root, dirs, files in os.walk(home):
        if root[len(home):].count(os.sep) >= 4:
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("node_modules", "Library", "AppData")]
        for fn in files:
            if re.match(r"(docker-)?compose.*\.ya?ml$", fn):
                try:
                    with open(os.path.join(root, fn), errors="ignore") as f:
                        txt = f.read()
                    if any(i in txt for i in ARTEX_IMAGES):
                        alert("CRITICAL", f"Compose file uses a backdoored ARTEX image: {os.path.join(root, fn)}")
                except Exception:
                    pass
    temps = [os.environ.get("TEMP", ""), os.environ.get("TMP", ""), r"C:\Windows\Temp", r"C:\ProgramData", "/tmp", "/var/tmp"]
    for d in {t for t in temps if t and os.path.isdir(t)}:
        try:
            for name in os.listdir(d):
                if name.lower().startswith("artx"):
                    alert("CRITICAL", f"ARTEX working files at {os.path.join(d, name)} - ARTEX agents keep their files in 'artx' folders. Isolate this machine, rebuild it and rotate every password and key it held")
        except Exception:
            pass
    procs = (run(["tasklist"]) if platform.system() == "Windows" else run(["ps", "-A", "-o", "comm="])).lower()
    if re.search(r"\bartex\b", procs):
        alert("HIGH", "An ARTEX process is running on this machine - confirm it is authorised and not reachable from the internet")

def _log_fields(line):
    ip = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
    t = None
    m = re.search(r"\[(\d{1,2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?\]", line)
    if m:
        try:
            st = time.strptime(f"{m.group(1)}/{m.group(2)}/{m.group(3)}:{m.group(4)}:{m.group(5)}:{m.group(6)}", "%d/%b/%Y:%H:%M:%S")
            off = m.group(7) or "+0000"
            t = calendar.timegm(st) - (1 if off[0] == "+" else -1) * (int(off[1:3]) * 3600 + int(off[3:]) * 60)
        except Exception:
            t = None
    else:
        m = re.search(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(\.\d+)?", line)
        if m:
            try:
                t = calendar.timegm(time.strptime(m.group(1) + " " + m.group(2), "%Y-%m-%d %H:%M:%S")) + float(m.group(3) or 0)
            except Exception:
                t = None
    return (ip.group(1) if ip else None), t

def rhythm(times):
    times = sorted(times)
    cycles = pauses = 0
    burst = 1
    long_gaps = 0
    for a, b in zip(times, times[1:]):
        g = b - a
        if g <= 2.5:
            burst += 1
            continue
        if g >= 5:
            long_gaps += 1
        if 24 <= g <= 32:
            pauses += 1
            if 1 <= burst <= 14:
                cycles += 1
        burst = 1
    share = pauses / long_gaps if long_gaps else 0
    return cycles, share, cycles >= 3 and share >= 0.6

def check_artex_logs(paths):
    by_ip, fails, ports = {}, {}, {}
    artifacts, callbacks, ai_calls, tools, harvest, fan = set(), {}, {}, {}, {}, {}
    ua_hits = ip_hits = 0
    n = 0
    for path in paths:
        try:
            f = open(path, errors="ignore")
        except Exception as e:
            alert("MEDIUM", f"Cannot read {path}: {e}")
            continue
        with f:
            for line in f:
                n += 1
                ip, t = _log_fields(line)
                if any(r.search(line) for r in ARTEX_UA):
                    ua_hits += 1
                    if ua_hits <= 5:
                        alert("CRITICAL", f"ARTEX user agent in {os.path.basename(path)}: {line.strip()[:160]}")
                if ip in ARTEX_IPS:
                    ip_hits += 1
                    if ip_hits <= 5:
                        alert("CRITICAL", f"Known ARTEX infrastructure {ip} in {os.path.basename(path)}")
                if any(j in line for j in ARTEX_JA4):
                    alert("HIGH", f"ARTEX TLS fingerprint in {os.path.basename(path)}")
                if ip and t is not None:
                    by_ip.setdefault(ip, []).append(t)
                am = ARTEX_ARTIFACTS.search(line)
                if am:
                    artifacts.add(am.group(0))
                low = line.lower()
                for d in CALLBACKS:
                    if d in low:
                        callbacks[d] = callbacks.get(d, 0) + 1
                        break
                for d in AI_APIS:
                    if d in low:
                        ai_calls[d] = ai_calls.get(d, 0) + 1
                        break
                if ip:
                    for fam, pat in TOOL_UA:
                        if re.search(pat, line, re.I):
                            tools.setdefault(ip, []).append((t or 0, fam))
                            break
                    hv = HARVEST.search(line)
                    if hv:
                        harvest.setdefault(ip, set()).add(hv.group(1).split("?")[0])
                fw = re.search(r"SRC=(\d{1,3}(?:\.\d{1,3}){3}).*?DPT=(\d+)", line) or re.search(r"\b(?:DROP|ALLOW|BLOCK|DENY)\s+(?:TCP|UDP)\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\d+\s+(\d+)", line, re.I)
                if fw:
                    ports.setdefault(fw.group(1), set()).add(int(fw.group(2)))
                    dst = re.search(r"DST=(\d{1,3}(?:\.\d{1,3}){3})", line) or re.search(r"\b(?:DROP|ALLOW|BLOCK|DENY)\s+(?:TCP|UDP)\s+\S+\s+(\S+)", line, re.I)
                    if dst and int(fw.group(2)) in LATERAL_PORTS:
                        fan.setdefault(fw.group(1), set()).add(dst.group(1))
                if ip and re.search(r'(login|signin|auth|token|password|reset|oauth)\S*\s+HTTP/[\d.]+"\s+(401|403|429)\b|AADSTS7000215|AADSTS7000222|"status"\s*:\s*(401|403|429)', line, re.I):
                    fails[ip] = fails.get(ip, 0) + 1
    if ua_hits > 5 or ip_hits > 5:
        alert("CRITICAL", f"In total {ua_hits} ARTEX user-agent lines and {ip_hits} lines from known ARTEX addresses")
    for ip, ts in by_ip.items():
        cycles, share, flagged = rhythm(ts)
        if flagged:
            alert("HIGH", f"Agent-like 'burst, then think' request rhythm from {ip}: {cycles} bursts with 25-31 s pauses")
    for ip, ps in ports.items():
        if len(ps) >= 15:
            alert("CRITICAL" if len(ps) >= 100 else "HIGH", f"Port scan from {ip}: tried {len(ps)} different ports ({', '.join(map(str, sorted(ps)[:10]))}...). Block this address")
    for ip, c in fails.items():
        if c >= 20:
            alert("HIGH", f"Password / secret guessing from {ip}: {c} failed sign-ins")
    for a in sorted(artifacts):
        alert("CRITICAL", f"ARTEX working files on a computer: {a}. Isolate it, rebuild it and rotate every key it held")
    for d, c in callbacks.items():
        alert("HIGH", f"Callback or tunnel service {d} in {c} lines - attack agents use these to confirm exploits and move data out. Find the server that called it")
    for d, c in ai_calls.items():
        alert("MEDIUM", f"Server talking to AI model service {d} ({c} lines) - if no approved app uses it, an attack agent may be running inside")
    for ip, lst in tools.items():
        lst.sort()
        j = 0
        for i in range(len(lst)):
            while lst[i][0] - lst[j][0] > 60:
                j += 1
            fams = {f for _, f in lst[j:i + 1]}
            if len(fams) >= 3:
                alert("HIGH", f"Several attack tools from {ip} within one minute: {', '.join(sorted(fams))} - typical of an AI agent driving its toolbox")
                break
    for ip, paths in harvest.items():
        if len(paths) >= 5:
            alert("HIGH", f"Config and source-map harvesting from {ip}: {len(paths)} files such as {', '.join(sorted(paths)[:4])}. Remove them from the live site")
    for ip, dsts in fan.items():
        if len(dsts) >= 10:
            alert("CRITICAL", f"Lateral movement from {ip}: reached {len(dsts)} machines on remote-management, file-sharing or remote-desktop ports. Isolate it now")
    print(f"Checked {n} log lines from {len(by_ip)} addresses for ARTEX traces")

SECRET_PATTERNS = [
    ("AWS access key", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("GitHub token", r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
    ("Anthropic API key", r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
    ("OpenAI API key", r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b"),
    ("Google API key", r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ("Slack token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    ("Stripe live key", r"\b(sk|rk)_live_[A-Za-z0-9]{20,}\b"),
    ("Private key", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    ("Azure storage connection string", r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{40,}"),
    ("Android keystore password", r"(?i)\b(KEYSTORE|STORE|KEY)_?PASS(WORD)?\s*[=:]\s*[\"']?[^\s\"'$]{6,}"),
    ("Generic secret assignment", r"(?i)\b(client_?secret|api_?key|secret_?key|access_?token|auth_?token|password)\b\s*[=:]\s*[\"'][A-Za-z0-9_\-+/=.]{16,}[\"']"),
]
SECRET_RE = [(n, re.compile(p)) for n, p in SECRET_PATTERNS]

def mask(s):
    return "*" * len(s) if len(s) <= 10 else s[:4] + "*" * min(12, len(s) - 8) + s[-4:]

def scan_text_for_secrets(text, where):
    found = 0
    for i, line in enumerate(text.splitlines(), 1):
        for name, rx in SECRET_RE:
            m = rx.search(line)
            if m:
                found += 1
                alert("HIGH", f"{name} in {where} line {i}: {mask(m.group(0))} - remove it and rotate it with the provider")
                break
    return found

def check_secrets(paths):
    total = 0
    for base in paths:
        base = os.path.abspath(base)
        for root, dirs, files in os.walk(base):
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "dist", "build", ".venv", "__pycache__")]
            for fn in files:
                p = os.path.join(root, fn)
                try:
                    if os.path.getsize(p) > 2_000_000:
                        continue
                    with open(p, "rb") as f:
                        raw = f.read()
                    if b"\0" in raw[:4096]:
                        continue
                    total += scan_text_for_secrets(raw.decode("utf-8", "ignore"), os.path.relpath(p, base))
                except Exception:
                    pass
        if os.path.isdir(os.path.join(base, ".git")):
            # Deleted from the files is not deleted from history: scan every commit too.
            hist = run(["git", "-C", base, "log", "-p", "--all", "--no-color", "--format=commit %H"])
            commit = "?"
            for line in hist.splitlines():
                if line.startswith("commit "):
                    commit = line[7:15]
                    continue
                if line.startswith("+") and not line.startswith("+++"):
                    for name, rx in SECRET_RE:
                        m = rx.search(line)
                        if m:
                            total += 1
                            alert("HIGH", f"{name} in git history of {os.path.basename(base)} (commit {commit}): {mask(m.group(0))} - rotate it; rewriting history does not undo exposure")
                            break
    print(f"Secret scan finished: {total} possible secrets")

# ---------------------------------------------------------------- open-port audit
RISKY_PORTS = {21: "FTP (passwords sent in clear)", 23: "Telnet (passwords sent in clear)", 135: "Windows RPC", 139: "Windows file sharing (NetBIOS)",
               445: "Windows file sharing (SMB)", 1433: "SQL Server database", 2375: "Docker API without TLS (full control of the machine)",
               3306: "MySQL database", 3389: "Remote Desktop", 5432: "PostgreSQL database", 5555: "Android debugging (ADB)", 5900: "VNC remote desktop",
               5985: "Windows remote management", 6379: "Redis database", 8787: "ARTEX attack console", 9200: "Elasticsearch", 11211: "Memcached",
               27017: "MongoDB database", 22: "SSH remote login"}

def listening_ports():
    """[(address, port, process)] for TCP ports this computer listens on."""
    out = []
    system = platform.system()
    if system == "Windows":
        for line in run(["netstat", "-ano", "-p", "TCP"]).splitlines():
            m = re.match(r"\s*TCP\s+(\S+):(\d+)\s+\S+\s+LISTENING\s+(\d+)", line)
            if m:
                out.append((m.group(1), int(m.group(2)), "pid " + m.group(3)))
    elif system == "Darwin":
        for line in run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"]).splitlines()[1:]:
            parts = line.split()
            m = re.search(r"(\S+):(\d+)\s*\(LISTEN\)", line)
            if m and parts:
                out.append((m.group(1), int(m.group(2)), parts[0]))
    else:
        txt = run(["ss", "-tlnpH"]) or run(["netstat", "-tlnp"])
        if not txt:
            # No ss/netstat: read the kernel's socket tables directly (state 0A = listening).
            for fn, v6 in (("/proc/net/tcp", False), ("/proc/net/tcp6", True)):
                try:
                    with open(fn) as f:
                        for row in f.readlines()[1:]:
                            c = row.split()
                            if len(c) > 3 and c[3] == "0A":
                                hexip, hexport = c[1].split(":")
                                if v6:
                                    addr = "::" if set(hexip) == {"0"} else ("::1" if hexip.endswith("01000000") and set(hexip[:24]) == {"0"} else "v6")
                                else:
                                    addr = ".".join(str(int(hexip[i:i + 2], 16)) for i in (6, 4, 2, 0))
                                out.append((addr, int(hexport, 16), ""))
                except Exception:
                    pass
        for line in txt.splitlines():
            m = re.search(r"\s(\[?[0-9a-fA-F:.*%]+\]?):(\d+)\s+\S+:\*?\S*\s*(.*)$", line)
            if m:
                proc = re.search(r'"([^"]+)"', m.group(3))
                out.append((m.group(1).strip("[]"), int(m.group(2)), proc.group(1) if proc else ""))
    return sorted(set(out), key=lambda x: x[1])

def check_open_ports():
    ports = listening_ports()
    exposed = [(a, p, pr) for a, p, pr in ports if not (a.startswith("127.") or a in ("::1", "localhost") or a.startswith("::ffff:127."))]
    print(f"This computer listens on {len(ports)} TCP ports ({len(exposed)} reachable from the network)")
    for a, p, pr in exposed:
        if p in RISKY_PORTS:
            level = "CRITICAL" if p in (2375, 8787, 5555, 23) else "HIGH" if p in (3389, 445, 5900, 21, 6379, 27017, 9200, 11211) else "MEDIUM"
            alert(level, f"Port {p} ({RISKY_PORTS[p]}) is open to the network on {a}{' by ' + pr if pr else ''}. Close it or limit it with the firewall unless you need it")
        else:
            alert("INFO", f"Port {p} open to the network on {a}{' by ' + pr if pr else ''}")

def args_after(flag):
    if flag not in sys.argv:
        return []
    out = []
    for a in sys.argv[sys.argv.index(flag) + 1:]:
        if a.startswith('--'):
            break
        out.append(a)
    return out

def main():
    try:
        with open(BASE) as f:
            base = json.load(f)
    except Exception:
        base = {}
    print("BlackSwan host agent -", platform.platform())
    gw = check_arp(base)
    check_dns()
    tls = check_tls(base)
    check_hosts()
    check_proxy()
    check_remote_tools()
    check_artex_local()
    check_open_ports()
    if "--artex" in sys.argv:
        check_artex_lan()
    if "--logs" in sys.argv:
        check_artex_logs(args_after("--logs"))
    if "--secrets" in sys.argv:
        check_secrets(args_after("--secrets") or ["."])
    if "--baseline" in sys.argv:
        with open(BASE, "w") as f:
            json.dump({"gateway": gw, "tls": tls, "saved": time.ctime()}, f, indent=2)
        print(f"Baseline saved to {BASE}")
    with open(REPORT, "w") as f:
        json.dump({"host": platform.node(), "alerts": alerts}, f, indent=2)
    worst = [a for a in alerts if a["level"] in ("HIGH", "CRITICAL")]
    print(f"\n{len(alerts)} findings, {len(worst)} high/critical. Report: {REPORT}")
    sys.exit(2 if worst else 0)

MENU = """
BlackSwan host agent - read-only security checks for this computer
  1  Check this computer (do this first, on a network you trust: it also saves a baseline)
  2  Check this computer and scan my network for ARTEX attack consoles
  3  Check log files for ARTEX and other attack traffic
  4  Scan a folder for leaked passwords, keys and tokens
  Q  Quit
"""

def interactive():
    """Double-clicked (no arguments): show a menu instead of running and closing at once."""
    print(MENU)
    choice = input("Choose 1-4 and press Enter: ").strip().lower()
    if choice in ("q", ""):
        return False
    extra = {"1": [] if os.path.exists(BASE) else ["--baseline"], "2": ["--artex"]}.get(choice)
    if choice == "3":
        paths = input("Drag log files here (or type their paths), then press Enter: ").strip()
        extra = ["--logs"] + [x.strip('"') for x in re.findall(r'"[^"]+"|\S+', paths)]
    elif choice == "4":
        folder = input("Drag a folder here (or type its path), then press Enter: ").strip().strip('"')
        extra = ["--secrets", folder or "."]
    if extra is None:
        print("Please choose 1, 2, 3 or 4.")
        return True
    sys.argv[1:] = extra
    return True

def pause():
    try:
        input("\nPress Enter to close this window...")
    except Exception:
        pass

if __name__ == "__main__":
    double_clicked = len(sys.argv) == 1 and sys.stdin is not None and sys.stdin.isatty()
    code = 0
    try:
        if double_clicked:
            while True:
                if not interactive():
                    break
                if len(sys.argv) > 1:
                    try:
                        main()
                    except SystemExit as e:
                        code = e.code or 0
                    print("\nWhat the levels mean: CRITICAL and HIGH need action now; MEDIUM and LOW are worth checking.")
                    pause()
                    break
        else:
            main()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"\nBlackSwan agent stopped with an error: {e}")
        code = 1
        if double_clicked:
            pause()
    sys.exit(code)

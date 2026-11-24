#!/usr/bin/env python3
"""BlackSwan host agent - read-only defensive checks for MITM, DNS hijack,
TLS interception, hosts/proxy tampering and remote-access takeover tools.
Usage:  python3 blackswan_agent.py --baseline   (first run, trusted network)
        python3 blackswan_agent.py              (later runs)
Standard library only. Works on Windows, macOS and Linux."""
import hashlib, ipaddress, json, os, platform, re, socket, ssl, subprocess, sys, time, urllib.request

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
    if "--baseline" in sys.argv:
        with open(BASE, "w") as f:
            json.dump({"gateway": gw, "tls": tls, "saved": time.ctime()}, f, indent=2)
        print(f"Baseline saved to {BASE}")
    with open(REPORT, "w") as f:
        json.dump({"host": platform.node(), "alerts": alerts}, f, indent=2)
    worst = [a for a in alerts if a["level"] in ("HIGH", "CRITICAL")]
    print(f"\n{len(alerts)} findings, {len(worst)} high/critical. Report: {REPORT}")
    sys.exit(2 if worst else 0)

if __name__ == "__main__":
    main()

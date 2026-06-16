#!/usr/bin/env python3
"""filtertest — measure filtering on the network you're connected to, legitimately.

Only tests well-known, clean domains (news / social / privacy / dev) and outbound
port reachability. It does NOT ping inappropriate/illegal content. Run it only from
your own device, with your own traffic.

Tests:
  - DNS tampering / hijack   (system + @8.8.8.8 vs DoH comparison)
  - TLS / SNI-based blocking (DPI)
  - Block page signatures    (BTK/5651, FortiGuard, Sophos, Squid…)
  - Outbound port / VPN protocol reachability (via portquiz.net)
  - Tor bootstrap            (does it actually come up)

Usage:
  ./filtertest.py
  ./filtertest.py --json report.json
  ./filtertest.py --no-tor --timeout 8
"""
import argparse
import copy
import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.message
import dns.query
import requests

# ── clean target list (category → domain). NO inappropriate content. ──────────
SITES = {
    "info/wikipedia": "wikipedia.org",
    "digital-rights/eff": "eff.org",
    "anonymity/tor": "torproject.org",
    "messaging/signal": "signal.org",
    "vpn-info/proton": "protonvpn.com",
    "dev/github": "github.com",
    "search/duckduckgo": "duckduckgo.com",
    "social/reddit": "reddit.com",
    "social/x": "x.com",
    "chat/discord": "discord.com",
    "messaging/telegram": "telegram.org",
    "archive/archive.org": "archive.org",
    "news/bbc": "bbc.com",
    # AI tools (often blocked at schools)
    "ai/chatgpt": "chatgpt.com",
    "ai/openai": "openai.com",
    "ai/claude": "claude.ai",
    "ai/anthropic": "anthropic.com",
    "ai/gemini": "gemini.google.com",
    "ai/perplexity": "perplexity.ai",
    "ai/copilot": "copilot.microsoft.com",
    "ai/huggingface": "huggingface.co",
    # VPN site/API (where the app logs in + pulls config; if blocked the VPN fails)
    "vpn-api/proton": "api.protonvpn.ch",
    "vpn-api/mullvad": "mullvad.net",
    "vpn-api/nordvpn": "nordvpn.com",
    "vpn-api/windscribe": "windscribe.com",
    "vpn-api/airvpn": "airvpn.org",
    # video / media (often blocked at schools)
    "video/youtube": "youtube.com",
    "video/tiktok": "tiktok.com",
    "video/twitch": "twitch.tv",
    "social/instagram": "instagram.com",
    "social/facebook": "facebook.com",
    "social/mastodon": "mastodon.social",
    "social/bluesky": "bsky.app",
    # news — international + independent (evidence of political filtering)
    "news/reuters": "reuters.com",
    "news/aljazeera": "aljazeera.com",
    "news/dw": "dw.com",
    "news/guardian": "theguardian.com",
    "news-tr/bianet": "bianet.org",
    "news-tr/diken": "diken.com.tr",
    # privacy tools
    "privacy/proton": "proton.me",
    "privacy/tutanota": "tuta.com",
    "privacy/startpage": "startpage.com",
    "privacy/privacyguides": "privacyguides.org",
    # human rights (evidence of over-blocking)
    "rights/amnesty": "amnesty.org",
    "rights/hrw": "hrw.org",
    "rights/accessnow": "accessnow.org",
    # education / health (school filters often over-block these)
    "education/khan": "khanacademy.org",
    "education/coursera": "coursera.org",
    "health/who": "who.int",
    # censorship-circumvention tools
    "circumvention/psiphon": "psiphon.ca",
    "circumvention/lantern": "getlantern.org",
    "circumvention/riseup": "riseup.net",
    # dev / storage / games
    "dev/stackoverflow": "stackoverflow.com",
    "dev/gitlab": "gitlab.com",
    "storage/mega": "mega.nz",
    "storage/dropbox": "dropbox.com",
    "games/steam": "store.steampowered.com",
    "games/epic": "epicgames.com",
}

# outbound port reachability (portquiz.net listens on every TCP port → egress test)
PORTS = {
    "HTTPS 443": 443,
    "HTTP 80": 80,
    "SSH 22": 22,
    "DoT 853": 853,
    "OpenVPN-TCP 1194": 1194,
    "L2TP 1701": 1701,
    "WireGuard-TCP 51820": 51820,  # WG is normally UDP; this is a TCP-reachability hint only
    "Tor-OR 9001": 9001,
    "alt-HTTPS 8443": 8443,
}
PORTQUIZ = "portquiz.net"

DOH_SERVERS = {
    "cloudflare": "https://cloudflare-dns.com/dns-query",
    "google": "https://dns.google/dns-query",
}

# block page / filter signatures (matched lowercased)
BLOCKPAGE_SIGNS = [
    "5651", "btk.gov.tr", "internet2.btk", "bu siteye erişim",
    "erişime engel", "engellenmiştir", "guvenli internet", "güvenli internet",
    "fortiguard", "web page blocked", "blocked by sophos", "web filter",
    "access denied", "erişim engellendi", "yasaklı", "content blocked",
    "this site is blocked", "url blocked", "category blocked",
]

C = {"g": "\033[32m", "r": "\033[31m", "y": "\033[33m", "b": "\033[34m",
     "d": "\033[2m", "0": "\033[0m", "bold": "\033[1m"}


def col(s, c):
    return f"{C[c]}{s}{C['0']}"


# ── DNS ────────────────────────────────────────────────────────────────────
def doh_resolve(name, server, timeout):
    # Skip dnspython's h3/httpx dependency: raw DNS message + requests POST (RFC 8484)
    q = dns.message.make_query(name, "A")
    r = requests.post(server, data=q.to_wire(), timeout=timeout,
                      headers={"content-type": "application/dns-message",
                               "accept": "application/dns-message"})
    r.raise_for_status()
    msg = dns.message.from_wire(r.content)
    return sorted({rr.address for ans in msg.answer for rr in ans
                   if rr.rdtype == dns.rdatatype.A})


def udp53_resolve(name, server, timeout):
    q = dns.message.make_query(name, "A")
    r = dns.query.udp(q, where=server, timeout=timeout)
    return sorted({rr.address for ans in r.answer for rr in ans
                   if rr.rdtype == dns.rdatatype.A})


def system_resolve(name):
    try:
        infos = socket.getaddrinfo(name, 443, socket.AF_INET, socket.SOCK_STREAM)
        return sorted({i[4][0] for i in infos})
    except OSError:
        return []


def is_private(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_unspecified
    except ValueError:
        return False


def dns_test(name, timeout):
    """Use DoH as the trusted reference; compare system and direct-53 answers."""
    res = {"truth": [], "system": [], "udp53": [], "verdict": "", "note": ""}
    try:
        res["truth"] = doh_resolve(name, DOH_SERVERS["cloudflare"], timeout)
    except Exception as e:
        try:
            res["truth"] = doh_resolve(name, DOH_SERVERS["google"], timeout)
        except Exception:
            res["note"] = f"DoH failed ({e})"
    res["system"] = system_resolve(name)
    try:
        res["udp53"] = udp53_resolve(name, "8.8.8.8", timeout)
    except Exception as e:
        res["udp53"] = []
        res["note"] = (res["note"] + f" udp53:{type(e).__name__}").strip()

    truth = set(res["truth"])
    sysip = set(res["system"])
    u53 = set(res["udp53"])

    # Low-false-positive strategy: do NOT treat a mere IP difference as tampering
    # (CDN/anycast returns different IPs per query). Only high-confidence signals:
    if not truth:
        res["verdict"] = "?"                       # no reference, don't judge
    elif (sysip or u53) and any(is_private(ip) for ip in sysip | u53) \
            and not any(is_private(ip) for ip in truth):
        res["verdict"] = "HIJACK-blockpage"        # redirect to a private/local IP
    elif not sysip and not u53:
        res["verdict"] = "DNS-BLOCK"               # DoH resolves, resolver empty/NXDOMAIN
    else:
        res["verdict"] = "ok"
        if truth.isdisjoint(sysip | u53):
            res["note"] = "different IPs (probably CDN)"
    return res


# ── TLS / SNI ────────────────────────────────────────────────────────────────
def tcp_open(host, port, timeout):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True, ""
    except Exception as e:
        return False, type(e).__name__


def tls_handshake(ip, sni, timeout):
    ctx = ssl._create_unverified_context()
    try:
        with socket.create_connection((ip, 443), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=sni):
                return "ok", ""
    except ssl.SSLError as e:
        return "tls-error", type(e).__name__   # server cert rejection etc. (not DPI)
    except (ConnectionResetError, BrokenPipeError):
        return "reset", "RST"                   # reset during handshake → DPI suspected
    except socket.timeout:
        return "timeout", "timeout"
    except Exception as e:
        return "fail", type(e).__name__


def sni_test(domain, ip, timeout):
    """If the real SNI gets reset but a harmless SNI passes → SNI-based DPI."""
    tcp_ok, tcp_err = tcp_open(ip, 443, timeout)
    if not tcp_ok:
        return {"tcp": False, "verdict": "tcp-block", "detail": tcp_err}
    real, real_d = tls_handshake(ip, domain, timeout)
    if real == "ok":
        return {"tcp": True, "verdict": "ok", "detail": ""}
    # control: harmless SNI to the same IP
    ctrl, ctrl_d = tls_handshake(ip, "example.com", timeout)
    if real in ("reset", "timeout") and ctrl == "ok":
        return {"tcp": True, "verdict": "SNI-DPI", "detail": f"{domain}:{real} / ctrl:ok"}
    if real in ("reset", "timeout"):
        return {"tcp": True, "verdict": "tls-block?", "detail": f"{real}/ctrl:{ctrl}"}
    return {"tcp": True, "verdict": "ok", "detail": real_d}


# ── HTTP block page ───────────────────────────────────────────────────────────
def blockpage_test(domain, timeout):
    out = {"verdict": "ok", "detail": ""}
    try:
        r = requests.get(f"http://{domain}", timeout=timeout, allow_redirects=True,
                         headers={"User-Agent": "Mozilla/5.0 filtertest"})
        body = r.text[:8000].lower()
        final = r.url.lower()
        for sig in BLOCKPAGE_SIGNS:
            if sig in body or sig in final:
                out["verdict"] = "BLOCKPAGE"
                out["detail"] = f"sign='{sig}' url={r.url}"
                return out
        # did it redirect to a completely different host than its own domain
        if domain.split(".")[-2] not in final and "://" in final:
            out["detail"] = f"redirected → {r.url}"
    except requests.exceptions.RequestException as e:
        out["verdict"] = "unreachable"
        out["detail"] = type(e).__name__
    return out


# ── ECH / encrypted-SNI ────────────────────────────────────────────────────────
def ech_test(domain, timeout):
    """ECH support: does the HTTPS/SVCB RR carry an 'ech' param (queried via DoH).
    ECH encrypts the SNI → defeats SNI-based DPI. If the site publishes ECH and the
    network only inspects SNI, ECH can restore access."""
    try:
        q = dns.message.make_query(domain, dns.rdatatype.HTTPS)
        r = requests.post(DOH_SERVERS["cloudflare"], data=q.to_wire(), timeout=timeout,
                          headers={"content-type": "application/dns-message",
                                   "accept": "application/dns-message"})
        r.raise_for_status()
        msg = dns.message.from_wire(r.content)
        for ans in msg.answer:
            if ans.rdtype == dns.rdatatype.HTTPS:
                for rr in ans:
                    if "ech=" in rr.to_text():
                        return True
        return False
    except Exception:
        return None


# ── UDP egress (indicator for UDP VPNs like WireGuard/IPsec) ──────────────────
STUN_SERVERS = [
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
    ("global.stun.twilio.com", 3478),
]


def stun_udp_test(host="stun.l.google.com", port=19302, timeout=4):
    """STUN binding request → response. Does UDP egress work (DPI/port block)."""
    msg = b"\x00\x01\x00\x00\x21\x12\xa4\x42" + os.urandom(12)  # RFC 5389
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(msg, (host, port))
        data, _ = s.recvfrom(1500)
        return "open" if data[:2] == b"\x01\x01" else "bad-reply"
    except socket.timeout:
        return "BLOCKED (timeout)"
    except OSError as e:
        return f"error ({type(e).__name__})"
    finally:
        s.close()


def stun_multi(timeout):
    """Multiple STUN servers/ports — test UDP egress on different ports."""
    with ThreadPoolExecutor(max_workers=4) as ex:
        futs = {ex.submit(stun_udp_test, h, p, timeout): f"{h}:{p}"
                for h, p in STUN_SERVERS}
        return {futs[f]: f.result() for f in as_completed(futs)}


def ssh_probe(host="github.com", port=22, timeout=5):
    """Grab a real SSH banner → is an SSH tunnel (ssh -D SOCKS) possible here."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        banner = s.recv(64)
        s.close()
        if banner.startswith(b"SSH-"):
            return "open", banner.decode(errors="replace").strip()
        return "responded", ""
    except socket.timeout:
        return "BLOCKED (timeout)", ""
    except OSError as e:
        return "error", type(e).__name__


def tunnel_advice(report, ssh_status):
    """Tunnel methods that bypass SNI-DPI/filtering — advice based on observations."""
    out = []
    sni_dpi = any(d["sni"]["verdict"] == "SNI-DPI" for d in report["sites"].values())
    p443 = not report["ports"].get("HTTPS 443", "").startswith("BLOCKED")
    tor_ok = report.get("tor", {}).get("verdict") == "ok"

    if ssh_status == "open":
        out.append(("g", "SSH tunnel works → `ssh -D 1080 user@server`, then SOCKS5"))
        out.append(("d", "  127.0.0.1:1080. All traffic inside SSH, DPI can't see it."))
    elif ssh_status.startswith("BLOCKED"):
        out.append(("r", "SSH (22) blocked → use a server listening for SSH on 443."))

    if p443 and sni_dpi:
        out.append(("g", "443 open + SNI-DPI only → SNI-hiding tunnels PASS:"))
        out.append(("d", "  • Shadowsocks / VLESS+TLS / Trojan-Go  (harmless or empty SNI)"))
        out.append(("d", "  • wstunnel / websocket-over-443  (tunnel inside WebSocket)"))
        out.append(("d", "  • OpenVPN-TCP-443 or WireGuard-over-TCP (udp2raw/wstunnel)"))
        out.append(("d", "  • Cloudflare WARP (MASQUE/443) — engage.cloudflareclient.com"))
    elif p443:
        out.append(("g", "443 open → TLS-based tunnels (Shadowsocks/VLESS) should work."))

    tor_v = report.get("tor", {}).get("verdict")
    if tor_ok:
        out.append(("g", "Tor works directly → easiest tunnel: Tor Browser / `tor` SOCKS 9050."))
    elif tor_v in (None, ""):
        out.append(("d", "Tor not tested (--no-tor). If blocked, try obfs4/Snowflake bridge."))
    else:
        out.append(("y", "Tor blocked directly → try obfs4 / Snowflake / meek bridge."))
    return out


def vpn_advice(report):
    """Why is the VPN failing → diagnosis + advice. Returns a list of (color, text)."""
    out = []
    vpn_blocked = sorted(
        dom for dom, d in report["sites"].items()
        if d["cat"].startswith(("vpn-api", "vpn-info"))
        and d["sni"]["verdict"] not in ("ok", "?", "no-dns"))
    udp_ok = report.get("udp", "") == "open"
    p443 = not report["ports"].get("HTTPS 443", "").startswith("BLOCKED")

    if vpn_blocked:
        out.append(("r", f"VPN site/API blocked (SNI-DPI): {', '.join(vpn_blocked)}"))
        out.append(("d", "  → the app can't log in / pull config = it FAILS at connect (API, not tunnel)."))
        out.append(("d", "  → fix: set the app up on another network and copy the config; or ECH/DoH;"))
        out.append(("d", "    or pick a provider whose API isn't blocked."))
    if not udp_ok:
        out.append(("r", "UDP egress blocked → WireGuard / OpenVPN-UDP FAIL."))
        out.append(("d", f"  → switch to TCP: OpenVPN-TCP-443 (443 open: {p443}),"))
        out.append(("d", "    WireGuard-over-TCP (wstunnel/udp2raw), OpenConnect, Shadowsocks."))
    else:
        out.append(("g", "UDP egress open → WireGuard / OpenVPN-UDP worth trying."))
        out.append(("d", "  → definitive end-to-end test: filterscope wg --config <wg.conf>"))
    if not vpn_blocked and udp_ok:
        out.append(("g", "No clear blocking at the VPN layer; the issue may be config/provider side."))
    return out


# ── network identity / evidence history ──────────────────────────────────────────
def net_fingerprint(label):
    fp = {"label": label or "", "search": "", "gateway": "", "resolver": "", "ssid": ""}
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                if line.startswith("search"):
                    fp["search"] = line.split(None, 1)[1].strip()
                elif line.startswith("nameserver") and not fp["resolver"]:
                    fp["resolver"] = line.split()[1]
    except OSError:
        pass
    try:
        out = subprocess.run(["ip", "route", "show", "default"],
                             capture_output=True, text=True, timeout=3).stdout
        m = re.search(r"default via (\S+)", out)
        if m:
            fp["gateway"] = m.group(1)
    except Exception:
        pass
    try:
        fp["ssid"] = subprocess.run(["iwgetid", "-r"], capture_output=True,
                                    text=True, timeout=3).stdout.strip()
    except Exception:
        pass
    fp["id"] = hashlib.sha1(
        f"{fp['search']}|{fp['gateway']}|{fp['resolver']}|{fp['ssid']}".encode()
    ).hexdigest()[:8]
    return fp


def history_record(report):
    """Compact record for the time series (evidence mode)."""
    sites_blocked = sorted(
        f"{dom}:{k}={d[k]['verdict']}"
        for dom, d in report["sites"].items()
        for k in ("dns", "sni", "blockpage")
        if d[k]["verdict"] not in ("ok", "?", "no-dns", "unreachable"))
    return {
        "ts": report["ts"],
        "net": report["net"]["id"],
        "label": report["net"].get("label", ""),
        "blocked": sites_blocked,
        "ports_blocked": [l for l, s in report["ports"].items() if s.startswith("BLOCKED")],
        "udp": report.get("udp", ""),
        "tor": report.get("tor", {}).get("verdict", ""),
    }


def anonymize(report):
    """Shareable report: strip local network identity and resolver answers."""
    r = copy.deepcopy(report)
    r["net"] = {"id": report["net"]["id"], "label": report["net"].get("label", "")}
    for d in r.get("sites", {}).values():
        for k in ("system", "udp53"):
            d.get("dns", {}).pop(k, None)
    return r


# ── port / protocol ───────────────────────────────────────────────────────────
def port_test(label, port, timeout):
    """timeout = packets dropped (real filter). refused/RST = packet got out → no filter."""
    try:
        s = socket.create_connection((PORTQUIZ, port), timeout=timeout)
        s.close()
        return label, "open"
    except socket.timeout:
        return label, "BLOCKED (timeout)"
    except ConnectionRefusedError:
        return label, "passed (refused)"
    except ConnectionResetError:
        return label, "passed (RST)"
    except OSError as e:
        return label, f"error ({type(e).__name__})"


# ── Tor ───────────────────────────────────────────────────────────────────────
def tor_test(timeout=60):
    with tempfile.TemporaryDirectory() as d:
        cfg = f"{d}/torrc"
        with open(cfg, "w") as f:
            f.write(f"SocksPort 0\nDataDirectory {d}/data\nLog notice stdout\n")
        try:
            p = subprocess.Popen(["tor", "-f", cfg], stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, text=True)
        except FileNotFoundError:
            return {"verdict": "tor-missing", "detail": "tor is not installed"}
        start = time.time()
        last = ""
        try:
            for line in p.stdout:
                last = line.strip()
                if "Bootstrapped 100%" in line:
                    p.terminate()
                    return {"verdict": "ok", "detail": "bootstrap 100%"}
                if time.time() - start > timeout:
                    break
            p.terminate()
            return {"verdict": "BLOCKED?", "detail": f"never reached 100%. last: {last[-120:]}"}
        finally:
            try:
                p.terminate()
            except Exception:
                pass


# ── report ─────────────────────────────────────────────────────────────────────
def run(args):
    fp = net_fingerprint(args.label)
    report = {"sites": {}, "ports": {}, "tor": {}, "udp": "", "net": fp,
              "ts": time.strftime("%Y-%m-%d %H:%M:%S")}
    print(col("\n  NETWORK FILTERING TEST", "bold"), col(f"({report['ts']})", "d"))
    netline = f"  network: {fp.get('label') or fp['ssid'] or fp['search'] or '?'}  [id {fp['id']}]"
    print(col(netline, "d"))
    print(col("  your own traffic, clean allowlist — no inappropriate sites pinged\n", "d"))

    # site tests (parallel)
    print(col("  ── DNS / TLS-SNI / Block page / ECH ──", "b"))
    def site_job(cat, dom):
        dns_r = dns_test(dom, args.timeout)
        ip = (dns_r["truth"] or dns_r["system"] or [None])[0]
        sni = sni_test(dom, ip, args.timeout) if ip else {"verdict": "no-dns", "detail": ""}
        bp = blockpage_test(dom, args.timeout)
        ech = ech_test(dom, args.timeout)
        return cat, dom, dns_r, sni, bp, ech

    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = [ex.submit(site_job, c, d) for c, d in SITES.items()]
        rows = [f.result() for f in as_completed(futs)]
    rows.sort(key=lambda r: r[0])

    print(f"  {'category/site':28} {'DNS':14} {'TLS/SNI':12} {'block':12} {'ECH':5}")
    print(col("  " + "-" * 74, "d"))
    for cat, dom, dns_r, sni, bp, ech in rows:
        dv, sv, bv = dns_r["verdict"], sni["verdict"], bp["verdict"]
        def mark(v, good="ok"):
            if v == good:
                return col(f"{v:12}", "g")
            if v in ("?", "no-dns", "unreachable"):
                return col(f"{v:12}", "y")
            return col(f"{v:12}", "r")
        echm = col(f"{'yes':5}", "g") if ech else (col(f"{'no':5}", "y") if ech is False else col(f"{'?':5}", "d"))
        print(f"  {cat:28} {mark(dv)} {mark(sv)} {mark(bv)} {echm}")
        # SNI-DPI + ECH available: bypass possible
        if sv == "SNI-DPI" and ech:
            print(col("      └ ECH can bypass the SNI-DPI (site publishes ECH)", "g"))
        for tag, r in (("dns", dns_r), ("sni", sni), ("bp", bp)):
            note = r.get("note") or r.get("detail")
            if note and (r.get("verdict") not in ("ok",)):
                print(col(f"      └ {tag}: {note}", "d"))
        report["sites"][dom] = {"cat": cat, "dns": dns_r, "sni": sni,
                                "blockpage": bp, "ech": ech}

    # port tests
    print(col("\n  ── Outbound Port / VPN Protocol reachability (portquiz.net) ──", "b"))
    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = [ex.submit(port_test, l, p, args.timeout) for l, p in PORTS.items()]
        pres = [f.result() for f in as_completed(futs)]
    for label, status in sorted(pres):
        c = "r" if status.startswith("BLOCKED") else ("g" if status == "open" else "y")
        print(f"  {label:24} {col(status, c)}")
        report["ports"][label] = status

    # UDP egress (for UDP VPNs like WireGuard/IPsec) — multiple servers/ports
    udp_detail = stun_multi(args.timeout)
    for srv, st in sorted(udp_detail.items()):
        uc = "r" if st.startswith("BLOCKED") else ("g" if st == "open" else "y")
        print(f"  {'UDP ' + srv:24} {col(st, uc)}")
    report["udp_detail"] = udp_detail
    report["udp"] = "open" if any(s == "open" for s in udp_detail.values()) else "BLOCKED"

    # tor
    if not args.no_tor:
        print(col("\n  ── Tor bootstrap ──", "b"))
        print(col("  (can take up to 60s)", "d"))
        tr = tor_test(args.tor_timeout)
        c = "g" if tr["verdict"] == "ok" else ("y" if tr["verdict"] == "tor-missing" else "r")
        print(f"  Tor: {col(tr['verdict'], c)}  {col(tr['detail'], 'd')}")
        report["tor"] = tr

    # summary
    print(col("\n  ── SUMMARY ──", "bold"))
    flagged = []
    for dom, d in report["sites"].items():
        for k in ("dns", "sni", "blockpage"):
            v = d[k]["verdict"]
            if v not in ("ok", "?", "no-dns", "unreachable"):
                flagged.append(f"{dom}: {k}={v}")
    blocked_ports = [l for l, s in report["ports"].items() if s.startswith("BLOCKED")]
    if flagged:
        print(col("  ⚑ Possible interference:", "r"))
        for f in flagged:
            print(f"     {f}")
    else:
        print(col("  No clear interference at the site DNS/TLS layer.", "g"))
    if blocked_ports:
        print(col("  ⚑ Blocked outbound ports:", "r"), ", ".join(blocked_ports))
    if report.get("udp", "").startswith("BLOCKED"):
        print(col("  ⚑ UDP egress blocked — WireGuard/IPsec may not work.", "r"))
    if report.get("tor", {}).get("verdict") not in ("ok", None):
        print(col(f"  ⚑ Tor: {report['tor']['verdict']}", "r"))
    # SNI-DPI sites recoverable via ECH
    ech_bypass = [dom for dom, d in report["sites"].items()
                  if d["sni"]["verdict"] == "SNI-DPI" and d.get("ech")]
    if ech_bypass:
        print(col("  ⓘ Reachable via ECH (SNI-DPI bypassed):", "g"), ", ".join(ech_bypass))

    # VPN diagnosis
    print(col("\n  ── VPN DIAGNOSIS ──", "bold"))
    for c, line in vpn_advice(report):
        print(col("  " + line, c))

    # Tunnel / circumvention options
    ssh_status, ssh_banner = ssh_probe(timeout=args.timeout)
    report["ssh"] = ssh_status
    print(col("\n  ── TUNNEL / CIRCUMVENTION ──", "bold"))
    sc = "g" if ssh_status == "open" else ("r" if ssh_status.startswith("BLOCKED") else "y")
    print(col(f"  SSH egress (22): {ssh_status}", sc),
          col(ssh_banner, "d") if ssh_banner else "")
    for c, line in tunnel_advice(report, ssh_status):
        print(col("  " + line, c))

    if args.json:
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(col(f"\n  JSON written: {args.json}", "d"))
    if args.anon_json:
        with open(args.anon_json, "w") as f:
            json.dump(anonymize(report), f, indent=2, ensure_ascii=False)
        print(col(f"  Anonymized report written: {args.anon_json}", "d"))
    if not args.no_history:
        os.makedirs(os.path.dirname(args.history), exist_ok=True)
        with open(args.history, "a") as f:
            f.write(json.dumps(history_record(report), ensure_ascii=False) + "\n")
        print(col(f"  Appended to history: {args.history}", "d"))
    print()


def main():
    ap = argparse.ArgumentParser(description="Network filtering/censorship meter (legitimate, clean)")
    ap.add_argument("--timeout", type=float, default=6, help="connection timeout (s)")
    ap.add_argument("--tor-timeout", type=float, default=60, help="tor bootstrap timeout (s)")
    ap.add_argument("--no-tor", action="store_true", help="skip the Tor test")
    ap.add_argument("--label", help="network label (e.g. 'school', 'mobile')")
    ap.add_argument("--json", help="write the full report to a JSON file")
    ap.add_argument("--anon-json", help="write an anonymized (shareable) report")
    ap.add_argument("--history", default=os.path.expanduser("~/.filterscope/history.jsonl"),
                    help="evidence history JSONL path")
    ap.add_argument("--no-history", action="store_true", help="don't write to history")
    args = ap.parse_args()
    try:
        run(args)
    except KeyboardInterrupt:
        sys.exit("\naborted")


if __name__ == "__main__":
    main()

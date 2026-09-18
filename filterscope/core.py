"""Measurement primitives. Pure functions, no printing — used by the CLI, the TUI
and the tests.

Every probe only touches well-known, clean domains and public test endpoints.
Nothing here pings inappropriate or illegal content.
"""
from __future__ import annotations

import base64
import copy
import ipaddress
import os
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import certifi
import dns.exception
import dns.message
import dns.query
import dns.rdatatype
import requests

from . import __version__

SCHEMA = 2

# ── clean target list (category/name → domain). NO inappropriate content. ─────
# Well-known, mainstream services only. Categories are the part before "/".
SITES = {
    # information / reference
    "info/wikipedia": "wikipedia.org", "info/wikimedia": "wikimedia.org", "info/britannica": "britannica.com",
    "info/archive.org": "archive.org", "info/stackexchange": "stackexchange.com", "info/quora": "quora.com",
    "info/imdb": "imdb.com", "info/weather": "weather.com", "info/speedtest": "speedtest.net", "info/fast": "fast.com",
    # search
    "search/google": "google.com", "search/bing": "bing.com", "search/duckduckgo": "duckduckgo.com",
    "search/startpage": "startpage.com", "search/yandex": "yandex.com", "search/brave": "search.brave.com",
    # digital rights / press freedom / civic
    "rights/eff": "eff.org", "rights/amnesty": "amnesty.org", "rights/hrw": "hrw.org", "rights/accessnow": "accessnow.org",
    "rights/rsf": "rsf.org", "rights/cpj": "cpj.org", "rights/freedomhouse": "freedomhouse.org", "rights/ooni": "ooni.org",
    "rights/torproject": "torproject.org", "rights/wikileaks": "wikileaks.org", "rights/un": "un.org", "rights/icrc": "icrc.org",
    # news — international
    "news/bbc": "bbc.com", "news/reuters": "reuters.com", "news/apnews": "apnews.com", "news/aljazeera": "aljazeera.com",
    "news/dw": "dw.com", "news/guardian": "theguardian.com", "news/nytimes": "nytimes.com", "news/cnn": "cnn.com",
    "news/bloomberg": "bloomberg.com", "news/france24": "france24.com", "news/euronews": "euronews.com",
    "news/washingtonpost": "washingtonpost.com", "news/economist": "economist.com", "news/voanews": "voanews.com",
    # news — Turkey (mainstream + independent)
    "news-tr/bbcturkce": "bbc.co.uk", "news-tr/bianet": "bianet.org", "news-tr/diken": "diken.com.tr", "news-tr/t24": "t24.com.tr", "news-tr/medyascope": "medyascope.tv",
    "news-tr/sozcu": "sozcu.com.tr", "news-tr/cumhuriyet": "cumhuriyet.com.tr", "news-tr/birgun": "birgun.net",
    "news-tr/evrensel": "evrensel.net", "news-tr/duvar": "gazeteduvar.com.tr", "news-tr/hurriyet": "hurriyet.com.tr", "news-tr/eksisozluk": "eksisozluk.com",
    # social
    "social/x": "x.com", "social/facebook": "facebook.com", "social/instagram": "instagram.com", "social/threads": "threads.net",
    "social/reddit": "reddit.com", "social/mastodon": "mastodon.social", "social/bluesky": "bsky.app", "social/tumblr": "tumblr.com",
    "social/pinterest": "pinterest.com", "social/linkedin": "linkedin.com", "social/snapchat": "snapchat.com", "social/vk": "vk.com",
    "social/imgur": "imgur.com", "social/deviantart": "deviantart.com", "social/wattpad": "wattpad.com", "social/patreon": "patreon.com",
    # chat / messaging / calls
    "chat/discord": "discord.com", "chat/whatsapp": "whatsapp.com", "chat/messenger": "messenger.com", "chat/slack": "slack.com",
    "chat/teams": "teams.microsoft.com", "chat/zoom": "zoom.us", "chat/meet": "meet.google.com", "chat/skype": "skype.com",
    "messaging/telegram": "telegram.org", "messaging/signal": "signal.org", "messaging/viber": "viber.com",
    "messaging/element": "element.io", "messaging/wire": "wire.com", "messaging/threema": "threema.ch", "messaging/session": "getsession.org",
    # video / streaming / music
    "video/youtube": "youtube.com", "video/tiktok": "tiktok.com", "video/twitch": "twitch.tv", "video/kick": "kick.com",
    "video/vimeo": "vimeo.com", "video/dailymotion": "dailymotion.com", "video/netflix": "netflix.com", "video/primevideo": "primevideo.com",
    "video/disneyplus": "disneyplus.com", "video/max": "max.com", "video/crunchyroll": "crunchyroll.com", "video/exxen": "exxen.com",
    "video/blutv": "blutv.com", "music/spotify": "spotify.com", "music/soundcloud": "soundcloud.com", "music/deezer": "deezer.com",
    "music/applemusic": "music.apple.com", "music/ytmusic": "music.youtube.com", "music/bandcamp": "bandcamp.com",
    # games — stores, launchers, platforms
    "games/steam": "store.steampowered.com", "games/steamcommunity": "steamcommunity.com", "games/epic": "epicgames.com",
    "games/fortnite": "fortnite.com", "games/roblox": "roblox.com", "games/minecraft": "minecraft.net", "games/mojang": "mojang.com",
    "games/riot": "riotgames.com", "games/leagueoflegends": "leagueoflegends.com", "games/valorant": "playvalorant.com",
    "games/battlenet": "battle.net", "games/blizzard": "blizzard.com", "games/ea": "ea.com", "games/ubisoft": "ubisoft.com",
    "games/rockstar": "rockstargames.com", "games/playstation": "playstation.com", "games/xbox": "xbox.com",
    "games/nintendo": "nintendo.com", "games/gog": "gog.com", "games/itch": "itch.io", "games/gamejolt": "gamejolt.com",
    "games/geforcenow": "nvidia.com", "games/chess": "chess.com", "games/lichess": "lichess.org", "games/pubg": "pubg.com",
    "games/supercell": "supercell.com", "games/genshin": "hoyoverse.com", "games/curseforge": "curseforge.com",
    "games/speedrun": "speedrun.com", "games/ign": "ign.com",
    # AI tools
    "ai/chatgpt": "chatgpt.com", "ai/openai": "openai.com", "ai/claude": "claude.ai", "ai/anthropic": "anthropic.com",
    "ai/gemini": "gemini.google.com", "ai/perplexity": "perplexity.ai", "ai/copilot": "copilot.microsoft.com",
    "ai/huggingface": "huggingface.co", "ai/mistral": "mistral.ai", "ai/deepseek": "deepseek.com", "ai/grok": "grok.com",
    "ai/characterai": "character.ai", "ai/poe": "poe.com", "ai/midjourney": "midjourney.com", "ai/openrouter": "openrouter.ai",
    # education / research / health
    "education/khan": "khanacademy.org", "education/coursera": "coursera.org", "education/edx": "edx.org", "education/udemy": "udemy.com",
    "education/duolingo": "duolingo.com", "education/quizlet": "quizlet.com", "education/brilliant": "brilliant.org",
    "education/mitocw": "ocw.mit.edu", "education/arxiv": "arxiv.org", "education/scholar": "scholar.google.com",
    "education/eba": "eba.gov.tr", "education/yok": "yok.gov.tr", "education/ted": "ted.com", "education/wolfram": "wolframalpha.com",
    "health/who": "who.int", "health/nhs": "nhs.uk", "health/mayoclinic": "mayoclinic.org", "health/webmd": "webmd.com",
    "health/cdc": "cdc.gov", "health/planned-parenthood": "plannedparenthood.org",
    # religion (mainstream reference sites — a classic over-blocking category)
    "religion/quran": "quran.com", "religion/bible": "bible.com", "religion/diyanet": "diyanet.gov.tr",
    # dev / open source / hosting
    "dev/github": "github.com", "dev/gitlab": "gitlab.com", "dev/codeberg": "codeberg.org", "dev/bitbucket": "bitbucket.org",
    "dev/stackoverflow": "stackoverflow.com", "dev/npm": "npmjs.com", "dev/pypi": "pypi.org", "dev/dockerhub": "hub.docker.com",
    "dev/replit": "replit.com", "dev/codepen": "codepen.io", "dev/vercel": "vercel.com", "dev/netlify": "netlify.com",
    "dev/cloudflare": "cloudflare.com", "dev/sourceforge": "sourceforge.net", "dev/kernel": "kernel.org", "dev/debian": "debian.org",
    "dev/archlinux": "archlinux.org", "dev/mozilla": "mozilla.org", "dev/brave": "brave.com", "dev/vscode": "code.visualstudio.com",
    # cloud / storage / mail
    "storage/drive": "drive.google.com", "storage/onedrive": "onedrive.live.com", "storage/icloud": "icloud.com", "storage/dropbox": "dropbox.com",
    "storage/box": "box.com", "storage/mega": "mega.nz", "storage/wetransfer": "wetransfer.com", "storage/mediafire": "mediafire.com",
    "storage/pcloud": "pcloud.com", "mail/gmail": "mail.google.com", "mail/outlook": "outlook.live.com", "mail/yahoo": "mail.yahoo.com",
    "mail/proton": "proton.me", "mail/tuta": "tuta.com", "mail/yandex": "mail.yandex.com",
    # privacy tools
    "privacy/privacyguides": "privacyguides.org", "privacy/tails": "tails.net",
    "privacy/whonix": "whonix.org", "privacy/keepass": "keepassxc.org",
    "privacy/bitwarden": "bitwarden.com", "privacy/ublock": "ublockorigin.com", "privacy/simplelogin": "simplelogin.io",
    # VPN providers (site + API — if these are blocked the app fails at login)
    "vpn-info/proton": "protonvpn.com", "vpn-api/proton": "api.protonvpn.ch", "vpn-api/mullvad": "mullvad.net",
    "vpn-api/nordvpn": "nordvpn.com", "vpn-api/windscribe": "windscribe.com", "vpn-api/airvpn": "airvpn.org",
    "vpn-api/expressvpn": "expressvpn.com", "vpn-api/surfshark": "surfshark.com", "vpn-api/cyberghost": "cyberghostvpn.com",
    "vpn-api/pia": "privateinternetaccess.com", "vpn-api/ivpn": "ivpn.net", "vpn-api/tunnelbear": "tunnelbear.com",
    "vpn-api/hideme": "hide.me", "vpn-api/warp": "one.one.one.one", "vpn-api/cloudflarewarp": "cloudflarewarp.com",
    # circumvention / tunnelling projects (software sites)
    "circumvention/psiphon": "psiphon.ca", "circumvention/lantern": "getlantern.org", "circumvention/riseup": "riseup.net",
    "circumvention/outline": "getoutline.org", "circumvention/wireguard": "wireguard.com", "circumvention/openvpn": "openvpn.net",
    "circumvention/shadowsocks": "shadowsocks.org", "circumvention/torbridges": "bridges.torproject.org",
    "circumvention/snowflake": "snowflake.torproject.org", "circumvention/tailscale": "tailscale.com", "circumvention/zerotier": "zerotier.com",
    "circumvention/ngrok": "ngrok.com", "circumvention/bittorrent": "bittorrent.com", "circumvention/qbittorrent": "qbittorrent.org",
    # web proxies (commonly blocked at schools)
    "webproxy/croxyproxy": "croxyproxy.com", "webproxy/proxysite": "proxysite.com",
    "webproxy/kproxy": "kproxy.com", "webproxy/4everproxy": "4everproxy.com",
    # shopping / marketplaces
    "shopping/amazon": "amazon.com", "shopping/ebay": "ebay.com", "shopping/aliexpress": "aliexpress.com", "shopping/temu": "temu.com",
    "shopping/trendyol": "trendyol.com", "shopping/hepsiburada": "hepsiburada.com", "shopping/sahibinden": "sahibinden.com",
    "shopping/etsy": "etsy.com", "shopping/shein": "shein.com",
    # crypto (mainstream exchanges/explorers — often blocked by institutions)
    "crypto/coinbase": "coinbase.com", "crypto/binance": "binance.com", "crypto/kraken": "kraken.com", "crypto/blockchain": "blockchain.com",
    "crypto/etherscan": "etherscan.io", "crypto/coinmarketcap": "coinmarketcap.com",
    # apps / platforms / misc
    "apps/appstore": "apps.apple.com", "apps/playstore": "play.google.com", "apps/aurora": "auroraoss.com", "apps/fdroid": "f-droid.org",
    "apps/microsoftstore": "apps.microsoft.com", "misc/paypal": "paypal.com", "misc/wise": "wise.com", "misc/booking": "booking.com",
    "misc/airbnb": "airbnb.com", "misc/uber": "uber.com", "misc/notion": "notion.so", "misc/canva": "canva.com", "misc/figma": "figma.com",
    "misc/trello": "trello.com", "misc/medium": "medium.com", "misc/substack": "substack.com", "misc/change": "change.org",
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
    "adguard": "https://dns.adguard-dns.com/dns-query",   # Quad9 DoH needs HTTP/2 (requests is h1.1)
}
DOT_SERVERS = {
    "cloudflare": ("1.1.1.1", "one.one.one.one"),
    "google": ("8.8.8.8", "dns.google"),
    "quad9": ("9.9.9.9", "dns.quad9.net"),
}

# block page / filter signatures (matched lowercased).
# STRONG = a filtering product/regulator page. Counted on any response.
# WEAK   = generic wording that legitimate sites also use ("access denied" on an Akamai 403, "5651"
#          in a Turkish legal footer). Counted only on a plain-http final response, where a network
#          can actually inject a page; over verified HTTPS the page came from the origin itself.
BLOCKPAGE_STRONG = [
    "fortiguard", "blocked by sophos", "cisco umbrella", "opendns", "lightspeed", "securly", "goguardian",
    "netsweeper", "smoothwall", "palo alto networks", "zscaler", "websense", "forcepoint", "barracuda",
    "mcafee web gateway", "btk.gov.tr", "internet2.btk", "guvenli internet", "güvenli internet",
    "bu siteye erişim", "erişime engel", "engellenmiştir", "erişim engellendi", "web page blocked",
]
BLOCKPAGE_WEAK = [
    "5651", "web filter", "access denied", "yasaklı", "content blocked", "this site is blocked",
    "url blocked", "category blocked",
]
BLOCKPAGE_SIGNS = BLOCKPAGE_STRONG + BLOCKPAGE_WEAK

# response headers that give away a transparent HTTP proxy / filter appliance
PROXY_HEADERS = ["via", "x-squid-error", "x-cache", "x-cache-lookup", "proxy-connection",
                 "x-bluecoat-via", "x-forcepoint", "x-fortigate", "x-sophos", "x-proxy-id"]
PROXY_SERVERS = ["squid", "bluecoat", "fortigate", "sophos", "mikrotik", "zscaler", "proxy"]

STUN_SERVERS = [
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
    ("global.stun.twilio.com", 3478),
]

QUIC_SERVERS = [("cloudflare.com", 443), ("www.google.com", 443)]

# canaries for TLS-interception (MITM) detection: big, stable, publicly-trusted certs
TLS_CANARIES = ["wikipedia.org", "github.com", "duckduckgo.com", "bbc.com"]

# benign words some URL filters key on (Lightspeed/Securly style). Nothing offensive.
URL_KEYWORDS = ["vpn", "proxy", "tor", "torrent", "bypass", "unblock"]

# fingerprint hints → vendor name
VENDOR_HINTS = {
    "fortiguard": "Fortinet FortiGate", "fortigate": "Fortinet FortiGate", "fortinet": "Fortinet FortiGate",
    "sophos": "Sophos", "squid": "Squid proxy", "bluecoat": "Symantec BlueCoat", "blue coat": "Symantec BlueCoat",
    "cisco umbrella": "Cisco Umbrella", "opendns": "Cisco Umbrella/OpenDNS", "lightspeed": "Lightspeed Systems",
    "securly": "Securly", "goguardian": "GoGuardian", "netsweeper": "Netsweeper", "smoothwall": "Smoothwall",
    "palo alto": "Palo Alto Networks", "zscaler": "Zscaler", "websense": "Forcepoint/Websense",
    "forcepoint": "Forcepoint", "barracuda": "Barracuda", "mcafee": "McAfee/Skyhigh", "mikrotik": "MikroTik",
    "btk": "BTK (Turkish regulator, 5651)", "5651": "BTK (Turkish regulator, 5651)", "guvenli internet": "BTK Safe Internet",
    "watchguard": "WatchGuard", "sonicwall": "SonicWall", "checkpoint": "Check Point", "check point": "Check Point",
    "untangle": "Untangle/Arista", "pfsense": "pfSense", "cloudflare gateway": "Cloudflare Gateway", "kaspersky": "Kaspersky",
}

# verdicts that do NOT count as interference
NEUTRAL = ("ok", "?", "no-dns", "unreachable", "", None)

UA = f"Mozilla/5.0 (compatible; filterscope/{__version__})"


def safe_name(s: str, default: str = "scan") -> str:
    """Filesystem-safe slug for user-supplied labels (no separators, no dot-prefix)."""
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", (s or "").strip())[:48].strip("._-")
    return s or default


def retry(fn, times=2, ok=lambda r: True):
    """Call fn until ok(result) or attempts run out; returns the last result."""
    r = None
    for _ in range(times):
        r = fn()
        if ok(r):
            return r
    return r


def vendor_guess(*texts) -> str:
    blob = " ".join(t for t in texts if t).lower()
    for k, v in VENDOR_HINTS.items():
        if k in blob:
            return v
    return ""


def categories() -> list[str]:
    return sorted({c.split("/")[0] for c in SITES})


def select_sites(cats: list[str] | None = None, extra: list[str] | None = None) -> dict:
    """Filter SITES by category prefix and/or add user domains (category 'custom')."""
    out = {}
    if cats:
        want = {c.strip().lower() for c in cats if c.strip()}
        out = {c: d for c, d in SITES.items() if c.split("/")[0] in want}
    else:
        out = dict(SITES)
    for d in extra or []:
        d = d.strip().lower()
        if d and d not in out.values():
            out[f"custom/{d}"] = d
    return out


# ── DNS ───────────────────────────────────────────────────────────────────────
def _doh_post(name, rtype, server, timeout):
    """RFC 8484 over plain requests (skips dnspython's h3/httpx dependency).
    POST first; some resolvers (Quad9) reject HTTP/1.1 POST → GET with base64url."""
    q = dns.message.make_query(name, rtype, id=0)
    wire = q.to_wire()
    hdr = {"content-type": "application/dns-message", "accept": "application/dns-message",
           "user-agent": UA}
    r = requests.post(server, data=wire, timeout=timeout, headers=hdr)
    if r.status_code in (405, 415, 505):
        b64 = base64.urlsafe_b64encode(wire).decode().rstrip("=")
        r = requests.get(server, params={"dns": b64}, timeout=timeout, headers=hdr)
    r.raise_for_status()
    return dns.message.from_wire(r.content)


def doh_resolve(name, server, timeout, rtype="A"):
    msg = _doh_post(name, rtype, server, timeout)
    want = dns.rdatatype.from_text(rtype)
    return sorted({rr.address for ans in msg.answer for rr in ans if rr.rdtype == want})


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


def dns_verdict(truth, sysip, u53):
    """Low-false-positive strategy: a mere IP difference is NOT tampering
    (CDN/anycast returns different IPs per query). Only high-confidence signals."""
    truth, sysip, u53 = set(truth), set(sysip), set(u53)
    if not truth:
        return "?", ""                             # no reference, don't judge
    if (sysip or u53) and any(is_private(ip) for ip in sysip | u53) \
            and not any(is_private(ip) for ip in truth):
        return "HIJACK-blockpage", ""              # redirect to a private/local IP
    if not sysip and not u53:
        return "DNS-BLOCK", ""                     # DoH resolves, resolver empty/NXDOMAIN
    if truth.isdisjoint(sysip | u53):
        return "ok", "different IPs (probably CDN)"
    return "ok", ""


def dns_test(name, timeout):
    """Use DoH as the trusted reference; compare system and direct-53 answers."""
    res = {"truth": [], "system": [], "udp53": [], "verdict": "", "note": ""}
    err = ""
    for srv in ("cloudflare", "google", "adguard"):
        try:
            res["truth"] = doh_resolve(name, DOH_SERVERS[srv], timeout)
            break
        except Exception as e:
            err = f"DoH failed ({type(e).__name__})"
    if not res["truth"] and err:
        res["note"] = err
    res["system"] = system_resolve(name)
    try:
        res["udp53"] = udp53_resolve(name, "8.8.8.8", timeout)
    except Exception as e:
        res["udp53"] = []
        res["note"] = (res["note"] + f" udp53:{type(e).__name__}").strip()
    v, note = dns_verdict(res["truth"], res["system"], res["udp53"])
    res["verdict"] = v
    if note:
        res["note"] = note
    return res


def dns_intercept_test(timeout=3):
    """Transparent DNS proxy: send a plain-53 query to an address that cannot run a
    resolver (TEST-NET-1, RFC 5737). Any answer at all = the network intercepts port 53."""
    q = dns.message.make_query("example.com", "A")
    try:
        r = dns.query.udp(q, where="192.0.2.1", timeout=timeout, ignore_unexpected=True)
        ips = sorted({rr.address for ans in r.answer for rr in ans
                      if rr.rdtype == dns.rdatatype.A})
        return {"verdict": "INTERCEPTED", "detail": f"answer from bogus resolver: {ips}"}
    except dns.exception.Timeout:
        return {"verdict": "ok", "detail": "no answer from 192.0.2.1 (expected)"}
    except OSError as e:
        return {"verdict": "?", "detail": type(e).__name__}
    except Exception as e:
        return {"verdict": "?", "detail": type(e).__name__}


def dot_test(ip, sni, timeout):
    """DNS-over-TLS (RFC 7858): TLS to :853, 2-byte length-prefixed query."""
    ctx = ssl.create_default_context()
    q = dns.message.make_query("example.com", "A").to_wire()
    t0 = time.monotonic()
    try:
        with socket.create_connection((ip, 853), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=sni) as ts:
                ts.sendall(struct.pack("!H", len(q)) + q)
                hdr = ts.recv(2)
                if len(hdr) < 2:
                    return "bad-reply"
                (n,) = struct.unpack("!H", hdr)
                buf = b""
                while len(buf) < n:
                    chunk = ts.recv(n - len(buf))
                    if not chunk:
                        break
                    buf += chunk
                dns.message.from_wire(buf)
                return f"open ({int((time.monotonic() - t0) * 1000)} ms)"
    except socket.timeout:
        return "BLOCKED (timeout)"
    except ConnectionResetError:
        return "BLOCKED (RST)"
    except ConnectionRefusedError:
        return "refused"
    except ssl.SSLError as e:
        return f"tls-error ({e.reason or type(e).__name__})"
    except Exception as e:
        return f"error ({type(e).__name__})"


def doh_probe(server, timeout):
    t0 = time.monotonic()
    try:
        _doh_post("example.com", "A", server, timeout)
        return f"open ({int((time.monotonic() - t0) * 1000)} ms)"
    except requests.exceptions.Timeout:
        return "BLOCKED (timeout)"
    except requests.exceptions.ConnectionError as e:
        s = str(e).lower()
        if "reset" in s:
            return "BLOCKED (RST)"
        if "name resolution" in s or "getaddrinfo" in s or "nodename" in s:
            return "BLOCKED (no-dns)"
        return f"error ({type(e).__name__})"
    except Exception as e:
        return f"error ({type(e).__name__})"


def encrypted_dns_test(timeout):
    """Is encrypted DNS (DoH/DoT) itself reachable — networks that force their own
    resolver often block these."""
    jobs = {}
    with ThreadPoolExecutor(max_workers=6) as ex:
        for n, url in DOH_SERVERS.items():
            jobs[ex.submit(doh_probe, url, timeout)] = f"DoH {n}"
        for n, (ip, sni) in DOT_SERVERS.items():
            jobs[ex.submit(dot_test, ip, sni, timeout)] = f"DoT {n}"
        return {jobs[f]: f.result() for f in as_completed(jobs)}


# ── TLS / SNI ─────────────────────────────────────────────────────────────────
def tcp_open(host, port, timeout):
    """Returns (ok, error_name, rtt_ms)."""
    t0 = time.monotonic()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True, "", (time.monotonic() - t0) * 1000
    except Exception as e:
        return False, type(e).__name__, (time.monotonic() - t0) * 1000


def tls_handshake(ip, sni, timeout):
    """Returns (status, detail, elapsed_ms). elapsed is measured from the moment the
    ClientHello is sent, so it can be compared against the TCP RTT."""
    ctx = ssl._create_unverified_context()
    t0 = None
    try:
        with socket.create_connection((ip, 443), timeout=timeout) as s:
            t0 = time.monotonic()
            with ctx.wrap_socket(s, server_hostname=sni):
                return "ok", "", (time.monotonic() - t0) * 1000
    except ssl.SSLError as e:
        return "tls-error", type(e).__name__, _ms(t0)   # cert rejection etc. (not DPI)
    except (ConnectionResetError, BrokenPipeError):
        return "reset", "RST", _ms(t0)                  # reset during handshake → DPI suspected
    except socket.timeout:
        return "timeout", "timeout", _ms(t0)
    except Exception as e:
        return "fail", type(e).__name__, _ms(t0)


def _ms(t0):
    return (time.monotonic() - t0) * 1000 if t0 else 0.0


def sni_test(domain, ip, timeout):
    """If the real SNI gets reset but a harmless SNI passes → SNI-based DPI.
    Also compares time-to-RST with the TCP RTT: an RST that arrives clearly faster
    than a round trip to the server was injected by an in-path middlebox."""
    tcp_ok, tcp_err, rtt = tcp_open(ip, 443, timeout)
    if not tcp_ok:
        return {"tcp": False, "verdict": "tcp-block", "detail": tcp_err}
    real, real_d, t_real = tls_handshake(ip, domain, timeout)
    if real == "ok":
        return {"tcp": True, "verdict": "ok", "detail": "", "rtt_ms": round(rtt, 1)}
    # control: harmless SNI to the same IP
    ctrl, ctrl_d, _ = tls_handshake(ip, "example.com", timeout)
    out = {"tcp": True, "rtt_ms": round(rtt, 1), "rst_ms": round(t_real, 1)}
    injected = real == "reset" and rtt > 5 and t_real < rtt * 0.75
    out["injected"] = injected
    if real in ("reset", "timeout") and ctrl == "ok":
        out["verdict"] = "SNI-DPI"
        out["detail"] = f"{domain}:{real} / ctrl:ok"
        if injected:
            out["detail"] += f" / RST {t_real:.0f} ms < RTT {rtt:.0f} ms → in-path injection"
        return out
    if real in ("reset", "timeout"):
        out["verdict"] = "tls-block?"
        out["detail"] = f"{real}/ctrl:{ctrl}"
        return out
    out["verdict"] = "ok"
    out["detail"] = real_d
    return out


# ── HTTP block page / transparent proxy ───────────────────────────────────────
def blockpage_test(domain, timeout):
    out = {"verdict": "ok", "detail": ""}
    try:
        r = requests.get(f"http://{domain}", timeout=timeout, allow_redirects=True,
                         headers={"User-Agent": UA})
        body = r.text[:8000].lower()
        final = r.url.lower()
        signs = BLOCKPAGE_STRONG if final.startswith("https://") else BLOCKPAGE_SIGNS
        for sig in signs:
            if sig in body or sig in final:
                out["verdict"] = "BLOCKPAGE"
                out["detail"] = f"sign='{sig}' url={r.url}"
                return out
        if final.startswith("https://") and any(sig in body for sig in BLOCKPAGE_WEAK):
            out["detail"] = "generic wording on the origin's own HTTPS page (not counted)"
        # did it redirect to a completely different host than its own domain
        if domain.split(".")[-2] not in final and "://" in final:
            out["detail"] = f"redirected → {r.url}"
    except requests.exceptions.RequestException as e:
        out["verdict"] = "unreachable"
        out["detail"] = type(e).__name__
    return out


def http_proxy_test(timeout):
    """Transparent HTTP proxy / filter appliance: look for tell-tale response headers
    on a plain-HTTP fetch of a neutral page."""
    try:
        r = requests.get("http://example.com/", timeout=timeout, allow_redirects=False,
                         headers={"User-Agent": UA})
    except requests.exceptions.RequestException as e:
        return {"verdict": "unreachable", "detail": type(e).__name__, "headers": {}}
    hdrs = {k.lower(): v for k, v in r.headers.items()}
    hits = [h for h in PROXY_HEADERS if h in hdrs]
    server = hdrs.get("server", "").lower()
    if any(p in server for p in PROXY_SERVERS):
        hits.append(f"server={server}")
    if r.status_code in (301, 302, 303, 307) and "example.com" not in hdrs.get("location", ""):
        hits.append(f"redirect→{hdrs.get('location')}")
    if hits:
        return {"verdict": "PROXY", "detail": ", ".join(hits),
                "headers": {h: hdrs[h] for h in PROXY_HEADERS if h in hdrs}}
    return {"verdict": "ok", "detail": f"status {r.status_code}, server={server or '?'}",
            "headers": {}}


# ── ECH / encrypted-SNI ───────────────────────────────────────────────────────
def ech_test(domain, timeout):
    """ECH support: does the HTTPS/SVCB RR carry an 'ech' param (queried via DoH).
    ECH encrypts the SNI → defeats SNI-based DPI."""
    for srv in ("cloudflare", "google"):
        try:
            msg = _doh_post(domain, "HTTPS", DOH_SERVERS[srv], timeout)
            for ans in msg.answer:
                if ans.rdtype == dns.rdatatype.HTTPS:
                    for rr in ans:
                        if "ech=" in rr.to_text():
                            return True
            return False
        except Exception:
            continue
    return None


# ── UDP egress: STUN + QUIC ───────────────────────────────────────────────────
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
    with ThreadPoolExecutor(max_workers=4) as ex:
        futs = {ex.submit(stun_udp_test, h, p, timeout): f"{h}:{p}"
                for h, p in STUN_SERVERS}
        return {futs[f]: f.result() for f in as_completed(futs)}


def quic_vn_packet():
    """A QUIC long-header packet with a reserved (greased) version, padded to 1200
    bytes. RFC 9000 §6: a server MUST answer with a Version Negotiation packet.
    No crypto needed — a clean 'is UDP/443 QUIC egress alive' probe."""
    dcid, scid = os.urandom(8), os.urandom(8)
    hdr = b"\xc0" + b"\x1a\x2a\x3a\x4a" + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
    return hdr.ljust(1200, b"\x00"), dcid


def quic_test(host, port=443, timeout=4):
    pkt, dcid = quic_vn_packet()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (host, port))
        data, _ = s.recvfrom(1500)
        if len(data) > 5 and data[0] & 0x80 and data[1:5] == b"\x00\x00\x00\x00":
            return "open"
        return "bad-reply"
    except socket.timeout:
        return "BLOCKED (timeout)"
    except OSError as e:
        return f"error ({type(e).__name__})"
    finally:
        s.close()


def quic_multi(timeout):
    with ThreadPoolExecutor(max_workers=2) as ex:
        futs = {ex.submit(quic_test, h, p, timeout): f"{h}:{p}" for h, p in QUIC_SERVERS}
        return {futs[f]: f.result() for f in as_completed(futs)}


# ── IPv6 ──────────────────────────────────────────────────────────────────────
def ipv6_test(timeout):
    if not socket.has_ipv6:
        return {"verdict": "unavailable", "detail": "no IPv6 support in this Python"}
    for ip in ("2606:4700:4700::1111", "2001:4860:4860::8888"):
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, 443))
            s.close()
            return {"verdict": "open", "detail": f"TCP 443 to {ip}"}
        except socket.timeout:
            last = "timeout"
        except OSError as e:
            last = type(e).__name__
            if getattr(e, "errno", None) in (101, 51, 65, 10051):   # ENETUNREACH family
                return {"verdict": "unavailable", "detail": "no IPv6 route"}
    return {"verdict": "BLOCKED" if last == "timeout" else "unavailable", "detail": last}


# ── SSH / throughput ──────────────────────────────────────────────────────────
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


def speed_test(mbytes=10, timeout=30):
    """Rough downstream throughput from Cloudflare's speed endpoint (Mbit/s)."""
    url = f"https://speed.cloudflare.com/__down?bytes={mbytes * 1_000_000}"
    t0 = time.monotonic()
    n = 0
    try:
        with requests.get(url, stream=True, timeout=timeout, headers={"User-Agent": UA}) as r:
            r.raise_for_status()
            for chunk in r.iter_content(65536):
                n += len(chunk)
                if time.monotonic() - t0 > timeout:
                    break
    except Exception as e:
        return {"mbps": 0.0, "bytes": n, "detail": type(e).__name__}
    dt = max(time.monotonic() - t0, 1e-3)
    return {"mbps": round(n * 8 / dt / 1e6, 1), "bytes": n, "seconds": round(dt, 2), "detail": ""}


# ── throughput / throttling ───────────────────────────────────────────────────
# Public, large, Range-capable files on the CDNs that games/video actually use.
THROTTLE_TARGETS = {
    "cloudflare": "https://speed.cloudflare.com/__down?bytes=4000000",
    "google": "https://dl.google.com/chrome/install/latest/chrome_installer.exe",
    "akamai-steam": "https://cdn.akamai.steamstatic.com/client/installer/SteamSetup.exe",
    "microsoft": "https://aka.ms/vs/17/release/vc_redist.x64.exe",
    "fastly-debian": "https://deb.debian.org/debian/ls-lR.gz",
}


def throughput_one(url, mbytes=4, seconds=8):
    t0 = time.monotonic()
    n = 0
    try:
        with requests.get(url, stream=True, timeout=(6, 6), allow_redirects=True,
                          headers={"User-Agent": UA, "Range": f"bytes=0-{mbytes * 1_000_000 - 1}"}) as r:
            r.raise_for_status()
            for chunk in r.iter_content(65536):
                n += len(chunk)
                if n >= mbytes * 1_000_000 or time.monotonic() - t0 > seconds:
                    break
    except Exception as e:
        return {"mbps": 0.0, "bytes": n, "error": type(e).__name__}
    dt = max(time.monotonic() - t0, 0.05)
    return {"mbps": round(n * 8 / dt / 1e6, 1), "bytes": n, "seconds": round(dt, 2), "error": ""}


def throttle_test(targets=None, mbytes=4):
    """Sequential downloads from several CDNs; a target far below the best one on the
    same link = selective throttling (video/game CDNs are the usual victims)."""
    targets = targets or THROTTLE_TARGETS
    res = {}
    for name, url in targets.items():
        res[name] = throughput_one(url, mbytes)
    ok = {k: v["mbps"] for k, v in res.items() if not v["error"] and v["bytes"] > 200_000}
    best = max(ok.values()) if ok else 0.0
    throttled = sorted(k for k, m in ok.items() if best >= 5 and m < best * 0.25)
    verdict = "THROTTLED" if throttled else ("ok" if ok else "?")
    return {"verdict": verdict, "best_mbps": best, "throttled": throttled, "targets": res,
            "detail": ("throttled: " + ", ".join(f"{k} {ok[k]} Mbps" for k in throttled) + f" vs best {best} Mbps")
                      if throttled else (f"best {best} Mbps, all targets within range" if ok else "no target reachable")}


# ── update check ──────────────────────────────────────────────────────────────
RELEASES_API = "https://api.github.com/repos/tunnelmoth/filterscope/releases/latest"
RELEASES_URL = "https://github.com/tunnelmoth/filterscope/releases/latest"


def _vtuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


def check_update(timeout=6):
    """Returns {'latest': '3.4.120', 'url': ..., 'newer': bool} or None on any failure."""
    try:
        r = requests.get(RELEASES_API, timeout=timeout, headers={"User-Agent": UA, "Accept": "application/vnd.github+json"})
        r.raise_for_status()
        tag = str(r.json().get("tag_name", "")).lstrip("v")
        if not tag:
            return None
        return {"latest": tag, "url": RELEASES_URL, "newer": _vtuple(tag) > _vtuple(__version__)}
    except Exception:
        return None


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
def find_tor():
    """Locate a tor binary: PATH first, then the usual Tor Browser / Expert Bundle spots."""
    p = shutil.which("tor")
    if p:
        return p
    cands = []
    if sys.platform.startswith("win"):
        for base in (os.environ.get("LOCALAPPDATA", ""), os.environ.get("PROGRAMFILES", ""),
                     os.environ.get("USERPROFILE", ""), os.path.join(os.path.expanduser("~"), "Desktop")):
            if base:
                cands += [os.path.join(base, "Tor Browser", "Browser", "TorBrowser", "Tor", "tor.exe"),
                          os.path.join(base, "tor", "tor.exe"),
                          os.path.join(base, "Tor", "tor.exe")]
        exe_dir = os.path.dirname(getattr(sys, "executable", "") or "")
        cands.append(os.path.join(exe_dir, "tor.exe"))
    elif sys.platform == "darwin":
        cands += ["/Applications/Tor Browser.app/Contents/MacOS/Tor/tor",
                  "/opt/homebrew/bin/tor", "/usr/local/bin/tor"]
    else:
        home = os.path.expanduser("~")
        cands += [os.path.join(home, "tor-browser", "Browser", "TorBrowser", "Tor", "tor"),
                  "/usr/bin/tor", "/usr/local/bin/tor"]
    for c in cands:
        if c and os.path.isfile(c):
            return c
    return None


def tor_test(timeout=60):
    tor = find_tor()
    if not tor:
        return {"verdict": "tor-missing", "detail": "tor is not installed (put tor/tor.exe on PATH)"}
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
        cfg = os.path.join(d, "torrc")
        with open(cfg, "w", encoding="utf-8") as f:
            f.write(f"SocksPort 0\nDataDirectory {os.path.join(d, 'data')}\nLog notice stdout\n")
        try:
            p = subprocess.Popen([tor, "-f", cfg], stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                                 errors="replace")
        except OSError as e:
            return {"verdict": "tor-missing", "detail": f"could not start tor: {e}"}
        start = time.time()
        last = ""
        try:
            for line in p.stdout:
                last = line.strip()
                if "Bootstrapped 100%" in line:
                    return {"verdict": "ok", "detail": "bootstrap 100%"}
                if time.time() - start > timeout:
                    break
            return {"verdict": "BLOCKED?", "detail": f"never reached 100%. last: {last[-120:]}"}
        finally:
            try:
                p.terminate()
                p.wait(timeout=5)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass


# ── TLS interception (MITM / SSL inspection) ──────────────────────────────────
def _cert_names(der: bytes):
    """(issuer, subject, san) from a DER certificate, via cryptography."""
    try:
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID, NameOID
        c = x509.load_der_x509_certificate(der)

        def cn(name):
            try:
                v = name.get_attributes_for_oid(NameOID.COMMON_NAME)
                o = name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
                return (v[0].value if v else "") + (f" ({o[0].value})" if o else "")
            except Exception:
                return name.rfc4514_string()
        try:
            san = c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
            names = san.get_values_for_type(x509.DNSName)[:3]
        except Exception:
            names = []
        return cn(c.issuer), cn(c.subject), names
    except Exception:
        return "?", "?", []


def tls_intercept_test(domain, timeout):
    """Verified TLS handshake against the Mozilla CA bundle (certifi). If verification
    fails but an unverified handshake succeeds, look at who signed the presented cert:
    a private/enterprise issuer for a big public site = SSL inspection (MITM)."""
    out = {"verdict": "ok", "issuer": "", "detail": ""}
    ctx = ssl.create_default_context(cafile=certifi.where())
    try:
        with socket.create_connection((domain, 443), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=domain) as ts:
                der = ts.getpeercert(binary_form=True)
                out["issuer"] = _cert_names(der)[0]
                return out
    except ssl.SSLCertVerificationError as e:
        reason = getattr(e, "verify_message", "") or str(e)
    except socket.timeout:
        return {"verdict": "?", "issuer": "", "detail": "timeout"}
    except ssl.SSLError as e:
        return {"verdict": "?", "issuer": "", "detail": e.reason or type(e).__name__}
    except OSError as e:
        return {"verdict": "?", "issuer": "", "detail": type(e).__name__}
    # verification failed → fetch the presented chain unverified
    uctx = ssl._create_unverified_context()
    try:
        with socket.create_connection((domain, 443), timeout=timeout) as s:
            with uctx.wrap_socket(s, server_hostname=domain) as ts:
                der = ts.getpeercert(binary_form=True)
    except Exception as e:
        return {"verdict": "?", "issuer": "", "detail": f"verify failed ({reason}); unverified {type(e).__name__}"}
    issuer, subject, san = _cert_names(der)
    out.update(issuer=issuer, subject=subject, san=san)
    if "self" in reason.lower() or "unable to get local issuer" in reason.lower() or "self-signed" in reason.lower():
        out["verdict"] = "TLS-MITM"
        out["detail"] = f"cert for {domain} signed by '{issuer}' — not publicly trusted ({reason})"
    elif "expired" in reason.lower():
        out["verdict"] = "?"
        out["detail"] = f"cert expired ({issuer}) — not MITM evidence"
    else:
        out["verdict"] = "TLS-MITM?"
        out["detail"] = f"verify failed: {reason}; issuer '{issuer}'"
    return out


def tls_intercept_multi(timeout):
    with ThreadPoolExecutor(max_workers=4) as ex:
        futs = {ex.submit(tls_intercept_test, d, timeout): d for d in TLS_CANARIES}
        return {futs[f]: f.result() for f in as_completed(futs)}


# ── NXDOMAIN hijack (search-redirect / ad injection on non-existent names) ───────
def nxdomain_test(timeout):
    name = f"fs-{os.urandom(6).hex()}.example.com"     # reserved domain, authoritative NXDOMAIN
    ips = system_resolve(name)
    if ips:
        return {"verdict": "NXDOMAIN-HIJACK", "detail": f"{name} → {ips} (should not exist)"}
    try:
        u = udp53_resolve(name, "8.8.8.8", timeout)
        if u:
            return {"verdict": "NXDOMAIN-HIJACK", "detail": f"@8.8.8.8 answered {u} for {name}"}
    except Exception:
        pass
    return {"verdict": "ok", "detail": "non-existent name correctly returns nothing"}


# ── URL keyword filtering (benign words in the query string) ──────────────────
def url_keyword_test(timeout):
    base_url = "http://example.com/"

    def fetch(q):
        try:
            r = requests.get(base_url, params={"q": q}, timeout=timeout, allow_redirects=False,
                             headers={"User-Agent": UA})
            body = r.text[:4000].lower()
            sig = next((sg for sg in BLOCKPAGE_SIGNS if sg in body), "")
            return r.status_code, sig, r.headers.get("location", "")
        except requests.exceptions.RequestException as e:
            return None, type(e).__name__, ""

    base = fetch("hello")
    if base[0] is None:
        return {"verdict": "?", "detail": f"baseline unreachable ({base[1]})", "hits": []}
    hits = []
    with ThreadPoolExecutor(max_workers=4) as ex:
        res = dict(zip(URL_KEYWORDS, ex.map(fetch, URL_KEYWORDS)))
    for w, (code, sig, loc) in res.items():
        if code is None or code != base[0] or sig or (loc and loc != base[2]):
            hits.append(f"{w}({code or sig})")
    if hits:
        return {"verdict": "URL-KEYWORD-FILTER", "detail": "blocked words: " + ", ".join(hits), "hits": hits}
    return {"verdict": "ok", "detail": f"{len(URL_KEYWORDS)} benign keywords pass unchanged", "hits": []}


# ── where am I (public vantage point) ─────────────────────────────────────────
def geo_context(timeout):
    """Public IP / country / Cloudflare colo via 1.1.1.1 trace (no third-party API)."""
    try:
        t = requests.get("https://1.1.1.1/cdn-cgi/trace", timeout=timeout, headers={"User-Agent": UA}).text
        kv = dict(l.split("=", 1) for l in t.splitlines() if "=" in l)
        return {"ip": kv.get("ip", ""), "country": kv.get("loc", ""), "colo": kv.get("colo", ""),
                "warp": kv.get("warp", ""), "http": kv.get("http", "")}
    except Exception as e:
        return {"ip": "", "country": "", "colo": "", "warp": "", "http": "", "error": type(e).__name__}


# ── advice ────────────────────────────────────────────────────────────────────
def tunnel_advice_items(report):
    """(color, key, params) — render with i18n.t. Tunnel methods that bypass what was observed."""
    out = []
    ssh_status = report.get("ssh", "")
    sni_dpi = any(d["sni"]["verdict"] == "SNI-DPI" for d in report["sites"].values())
    p443 = not report["ports"].get("HTTPS 443", "").startswith("BLOCKED")
    tor_v = report.get("tor", {}).get("verdict")
    quic = report.get("quic", "")
    if ssh_status == "open":
        out += [("g", "adv.ssh.open", {}), ("d", "adv.ssh.open2", {})]
    elif ssh_status.startswith("BLOCKED"):
        out.append(("r", "adv.ssh.blocked", {}))
    if p443 and sni_dpi:
        out += [("g", "adv.443.sni", {}), ("d", "adv.443.l1", {}), ("d", "adv.443.l2", {}), ("d", "adv.443.l3", {}), ("d", "adv.443.l4", {})]
    elif p443:
        out.append(("g", "adv.443.open", {}))
    if quic == "open":
        out.append(("g", "adv.quic.open", {}))
    elif quic.startswith("BLOCKED"):
        out.append(("y", "adv.quic.blocked", {}))
    if tor_v == "ok":
        out.append(("g", "adv.tor.ok", {}))
    elif tor_v in (None, ""):
        out.append(("d", "adv.tor.untested", {}))
    elif tor_v == "tor-missing":
        out.append(("d", "adv.tor.missing", {}))
    else:
        out.append(("y", "adv.tor.blocked", {}))
    th = report.get("throttle", {})
    if th.get("verdict") == "THROTTLED":
        out.append(("r", "adv.throttle", {"targets": ", ".join(th.get("throttled", []))}))
    return out


def vpn_advice_items(report):
    out = []
    vpn_blocked = sorted(
        dom for dom, d in report["sites"].items()
        if d["cat"].startswith(("vpn-api", "vpn-info"))
        and d["sni"]["verdict"] not in ("ok", "?", "no-dns"))
    udp = report.get("udp", "")
    udp_ok = udp == "open"
    p443 = not report["ports"].get("HTTPS 443", "").startswith("BLOCKED")
    if vpn_blocked:
        out += [("r", "adv.vpn.blocked", {"doms": ", ".join(vpn_blocked)}), ("d", "adv.vpn.why", {}),
                ("d", "adv.vpn.fix1", {}), ("d", "adv.vpn.fix2", {})]
    if not udp:
        out.append(("d", "adv.udp.untested", {}))
    elif not udp_ok:
        out += [("r", "adv.udp.blocked", {}), ("d", "adv.udp.tcp", {"p443": p443}), ("d", "adv.udp.alt", {})]
    else:
        out += [("g", "adv.udp.open", {}), ("d", "adv.udp.test", {})]
    if not vpn_blocked and (udp_ok or not udp):
        out.append(("g", "adv.vpn.noclear", {}))
    if any(r.get("verdict", "").startswith("TLS-MITM") for r in report.get("tls_intercept", {}).values()):
        out.append(("r", "adv.mitm", {}))
    enc = report.get("dns_encrypted", {})
    if enc and all(v.startswith("BLOCKED") for v in enc.values()):
        out.append(("r", "adv.encdns", {}))
    if report.get("dns_intercept", {}).get("verdict") == "INTERCEPTED":
        out.append(("r", "adv.dnsint", {}))
    return out


def _render_items(items):
    from .i18n import t
    return [(c, t(k, **kw)) for c, k, kw in items]


def tunnel_advice(report):
    """Backwards-compatible: list of (color, localized text)."""
    return _render_items(tunnel_advice_items(report))


def vpn_advice(report):
    return _render_items(vpn_advice_items(report))


# ── evidence helpers ──────────────────────────────────────────────────────────
def flagged(report):
    """Everything that counts as interference, as short strings."""
    out = []
    for dom, d in report.get("sites", {}).items():
        for k in ("dns", "sni", "blockpage"):
            v = d[k]["verdict"]
            if v not in NEUTRAL:
                out.append(f"{dom}: {k}={v}")
    for label, st in report.get("ports", {}).items():
        if st.startswith("BLOCKED"):
            out.append(f"port {label}")
    if report.get("udp", "").startswith("BLOCKED"):
        out.append("udp egress")
    if report.get("quic", "").startswith("BLOCKED"):
        out.append("quic/udp-443")
    tv = report.get("tor", {}).get("verdict")
    if tv not in ("ok", "", None, "tor-missing"):
        out.append(f"tor={tv}")
    for k, v in report.get("dns_encrypted", {}).items():
        if v.startswith("BLOCKED"):
            out.append(f"encrypted-dns {k}")
    if report.get("dns_intercept", {}).get("verdict") == "INTERCEPTED":
        out.append("dns-53 intercepted")
    if report.get("http_proxy", {}).get("verdict") == "PROXY":
        out.append("http transparent proxy")
    for dom, r in report.get("tls_intercept", {}).items():
        if r.get("verdict", "").startswith("TLS-MITM"):
            out.append(f"tls-mitm {dom}")
    if report.get("nxdomain", {}).get("verdict") == "NXDOMAIN-HIJACK":
        out.append("nxdomain hijack")
    if report.get("url_filter", {}).get("verdict") == "URL-KEYWORD-FILTER":
        out.append("url keyword filter")
    if report.get("throttle", {}).get("verdict") == "THROTTLED":
        out.append("throttling " + ",".join(report["throttle"].get("throttled", [])))
    return out


def history_record(report):
    """Compact record for the time series (evidence mode)."""
    sites_blocked = sorted(
        f"{dom}:{k}={d[k]['verdict']}"
        for dom, d in report["sites"].items()
        for k in ("dns", "sni", "blockpage")
        if d[k]["verdict"] not in NEUTRAL)
    return {
        "ts": report["ts"],
        "net": report["net"]["id"],
        "label": report["net"].get("label", ""),
        "blocked": sites_blocked,
        "ports_blocked": [l for l, s in report["ports"].items() if s.startswith("BLOCKED")],
        "udp": report.get("udp", ""),
        "quic": report.get("quic", ""),
        "tor": report.get("tor", {}).get("verdict", ""),
        "dns_encrypted_blocked": sorted(k for k, v in report.get("dns_encrypted", {}).items()
                                        if v.startswith("BLOCKED")),
        "dns_intercept": report.get("dns_intercept", {}).get("verdict", ""),
        "http_proxy": report.get("http_proxy", {}).get("verdict", ""),
        "tls_mitm": sorted(d for d, r in report.get("tls_intercept", {}).items()
                           if r.get("verdict", "").startswith("TLS-MITM")),
        "nxdomain": report.get("nxdomain", {}).get("verdict", ""),
        "url_filter": report.get("url_filter", {}).get("verdict", ""),
        "throttle": report.get("throttle", {}).get("verdict", ""),
        "score": report.get("analysis", {}).get("score"),
    }


def anonymize(report):
    """Shareable report: strip local network identity and resolver answers."""
    r = copy.deepcopy(report)
    r["net"] = {"id": report["net"]["id"], "label": report["net"].get("label", "")}
    for d in r.get("sites", {}).values():
        for k in ("system", "udp53"):
            d.get("dns", {}).pop(k, None)
    r.get("http_proxy", {}).pop("headers", None)
    if "geo" in r:
        r["geo"] = {k: v for k, v in r["geo"].items() if k in ("country", "colo", "warp")}
    return r

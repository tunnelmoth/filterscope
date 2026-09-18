"""Analysis engine — turns a raw report into a filtering score, the techniques in
use, a vendor guess, per-category impact and a one-paragraph verdict."""
from __future__ import annotations

from collections import defaultdict

from . import core

TECHNIQUE_INFO = {
    "SNI-DPI":          ("TLS server-name inspection", 4),
    "RST-injection":    ("in-path RST injection (middlebox)", 2),
    "TLS-MITM":         ("TLS interception / SSL inspection", 25),
    "DNS-hijack":       ("DNS redirection to a block page", 6),
    "DNS-block":        ("DNS answers withheld (NXDOMAIN/empty)", 5),
    "DNS-intercept":    ("transparent port-53 DNS proxy", 8),
    "encrypted-DNS-block": ("DoH/DoT blocked", 8),
    "NXDOMAIN-hijack":  ("NXDOMAIN hijacking / search redirect", 3),
    "block-page":       ("HTTP block page", 3),
    "HTTP-proxy":       ("transparent HTTP proxy / filter appliance", 4),
    "URL-keyword-filter": ("URL keyword filtering", 5),
    "port-filter":      ("outbound TCP port filtering", 3),
    "UDP-block":        ("UDP egress blocked", 6),
    "QUIC-block":       ("QUIC / UDP-443 blocked", 3),
    "Tor-block":        ("Tor bootstrap blocked", 6),
    "SSH-block":        ("SSH egress blocked", 3),
    "IPv6-block":       ("IPv6 egress blocked", 1),
}

LEVELS = [(0, "clean"), (1, "light"), (20, "moderate"), (45, "heavy"), (70, "severe")]


def level(score: int) -> str:
    out = "clean"
    for th, name in LEVELS:
        if score >= th:
            out = name
    return out


def techniques(report: dict) -> list[str]:
    t = set()
    for d in report.get("sites", {}).values():
        sv, dv, bv = d["sni"]["verdict"], d["dns"]["verdict"], d["blockpage"]["verdict"]
        if sv == "SNI-DPI":
            t.add("SNI-DPI")
        if d["sni"].get("injected"):
            t.add("RST-injection")
        if dv == "HIJACK-blockpage":
            t.add("DNS-hijack")
        if dv == "DNS-BLOCK":
            t.add("DNS-block")
        if bv == "BLOCKPAGE":
            t.add("block-page")
    if report.get("dns_intercept", {}).get("verdict") == "INTERCEPTED":
        t.add("DNS-intercept")
    enc = report.get("dns_encrypted", {})
    if enc and sum(v.startswith("BLOCKED") for v in enc.values()) >= max(1, len(enc) // 2):
        t.add("encrypted-DNS-block")
    if report.get("nxdomain", {}).get("verdict") == "NXDOMAIN-HIJACK":
        t.add("NXDOMAIN-hijack")
    if report.get("http_proxy", {}).get("verdict") == "PROXY":
        t.add("HTTP-proxy")
    if report.get("url_filter", {}).get("verdict") == "URL-KEYWORD-FILTER":
        t.add("URL-keyword-filter")
    if any(r.get("verdict", "").startswith("TLS-MITM") for r in report.get("tls_intercept", {}).values()):
        t.add("TLS-MITM")
    if any(s.startswith("BLOCKED") for s in report.get("ports", {}).values()):
        t.add("port-filter")
    if report.get("udp", "").startswith("BLOCKED"):
        t.add("UDP-block")
    if report.get("quic", "").startswith("BLOCKED"):
        t.add("QUIC-block")
    tv = report.get("tor", {}).get("verdict")
    if tv not in ("ok", "", None, "tor-missing"):
        t.add("Tor-block")
    if report.get("ssh", "").startswith("BLOCKED"):
        t.add("SSH-block")
    if report.get("ipv6", {}).get("verdict") == "BLOCKED":
        t.add("IPv6-block")
    return sorted(t, key=lambda k: -TECHNIQUE_INFO[k][1])


def vendor(report: dict) -> str:
    texts = []
    for d in report.get("sites", {}).values():
        texts.append(d["blockpage"].get("detail", ""))
    hp = report.get("http_proxy", {})
    texts.append(hp.get("detail", ""))
    texts += [f"{k} {v}" for k, v in hp.get("headers", {}).items()]
    for r in report.get("tls_intercept", {}).values():
        texts.append(r.get("issuer", ""))
        texts.append(r.get("detail", ""))
    return core.vendor_guess(*texts)


def category_impact(report: dict) -> list[dict]:
    per = defaultdict(lambda: {"total": 0, "blocked": 0, "domains": []})
    for dom, d in report.get("sites", {}).items():
        cat = d["cat"].split("/")[0]
        per[cat]["total"] += 1
        if any(d[k]["verdict"] not in core.NEUTRAL for k in ("dns", "sni", "blockpage")):
            per[cat]["blocked"] += 1
            per[cat]["domains"].append(dom)
    rows = [{"category": c, **v} for c, v in per.items()]
    rows.sort(key=lambda r: (-r["blocked"] / max(r["total"], 1), r["category"]))
    return rows


def score(report: dict) -> int:
    sites = report.get("sites", {})
    n = len(sites)
    blocked = sum(any(d[k]["verdict"] not in core.NEUTRAL for k in ("dns", "sni", "blockpage"))
                  for d in sites.values())
    s = 0.0
    if n:
        frac = blocked / n
        sample = min(1.0, (n / 12) ** 0.5)              # a 1-site scan cannot claim "heavy"
        s += min(50.0, 50.0 * (frac ** 0.6) * sample)   # 10% of 58 sites ≈ 12.5 pts, 50% ≈ 33
    for t in techniques(report):
        s += TECHNIQUE_INFO[t][1]
    s += 2 * sum(v.startswith("BLOCKED") for v in report.get("ports", {}).values())
    return int(min(100, round(s)))


def confidence(report: dict) -> str:
    """How trustworthy the verdicts are: were positives re-checked, did references work."""
    sites = report.get("sites", {})
    if not sites:
        return "low"
    unknown = sum(d["dns"]["verdict"] == "?" for d in sites.values())
    if unknown > len(sites) / 3:
        return "low"      # DoH reference mostly failed
    transient = sum(1 for d in sites.values() if d.get("transient"))
    positives = sum(any(d[k]["verdict"] not in core.NEUTRAL for k in ("dns", "sni", "blockpage"))
                    for d in sites.values())
    if positives and report.get("verified") is False:
        return "medium"
    if transient > positives:
        return "medium"
    return "high"


def summary_text(report: dict, an: dict) -> str:
    net = report.get("net", {})
    name = net.get("label") or net.get("ssid") or "this network"
    n = len(report.get("sites", {}))
    blocked = sum(r["blocked"] for r in an["categories"])
    lvl = an["level"]
    if an["score"] == 0:
        return (f"No interference detected on {name}: {n} sites, all outbound probes and encrypted DNS "
                f"behaved normally.")
    parts = [f"{name} shows {lvl} filtering (score {an['score']}/100)."]
    if blocked:
        worst = [r for r in an["categories"] if r["blocked"]][:3]
        cats = ", ".join(f"{r['category']} ({r['blocked']}/{r['total']})" for r in worst)
        parts.append(f"{blocked} of {n} sites are affected, mostly {cats}.")
    if an["techniques"]:
        parts.append("Techniques: " + ", ".join(TECHNIQUE_INFO[t][0] for t in an["techniques"][:4]) + ".")
    if an["vendor"]:
        parts.append(f"Signatures point to {an['vendor']}.")
    if "TLS-MITM" in an["techniques"]:
        parts.append("HTTPS is decrypted by the network — treat every session as readable by the operator.")
    elif "SNI-DPI" in an["techniques"] and "UDP-block" not in an["techniques"]:
        parts.append("The filter is application-layer only; SNI-hiding tunnels and ECH get through.")
    return " ".join(parts)


def analyze(report: dict) -> dict:
    an = {"techniques": techniques(report), "vendor": vendor(report),
          "categories": category_impact(report), "score": score(report)}
    an["level"] = level(an["score"])
    an["confidence"] = confidence(report)
    an["technique_labels"] = {t: TECHNIQUE_INFO[t][0] for t in an["techniques"]}
    an["summary"] = summary_text(report, an)
    return an


def diff(old: dict, new: dict) -> dict:
    """What changed between two reports (flagged sets + score)."""
    common = set(old.get("sites", {})) & set(new.get("sites", {}))

    def comparable(items, other):
        # site findings only count when the domain was scanned in BOTH reports
        out = set()
        for x in items:
            dom = x.split(":", 1)[0]
            if dom in other.get("sites", {}) and dom not in common:
                continue
            if dom in old.get("sites", {}) or dom in new.get("sites", {}):
                if dom not in common:
                    continue
            out.add(x)
        return out
    a = comparable(core.flagged(old), new)
    b = comparable(core.flagged(new), old)
    return {"added": sorted(b - a), "removed": sorted(a - b), "same": sorted(a & b),
            "score_old": old.get("analysis", {}).get("score", score(old)),
            "score_new": new.get("analysis", {}).get("score", score(new))}

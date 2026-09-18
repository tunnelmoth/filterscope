"""Scan orchestrator — one thread pool, every probe group in flight at once, Tor in
its own thread from the start, a verification pass that re-checks every positive
before it is reported, then the analysis engine. Results stream through a callback
so the CLI, the TUI and watch mode share one engine.

Events (name, *args):
  net        fp
  geo        dict
  progress   done, total
  site       dom, result
  port       label, status
  udp        server, status          udp_done  "open"|"BLOCKED"
  quic       server, status          quic_done "open"|"BLOCKED"
  ipv6       result
  dns_enc    name, status            dns_int   result
  http_proxy result                  ssh       status, banner
  mitm       domain, result          nxdomain  result
  url_filter result                  speed     result
  tor        result
  verify_start n                     verify    dom, confirmed(bool), result
  analysis   dict
  done       report
"""
from __future__ import annotations

import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from . import __version__, analysis, core, sysinfo

ALL_STEPS = ("sites", "ports", "udp", "quic", "ipv6", "dns", "proxy", "ssh",
             "mitm", "nxdomain", "urlfilter", "geo", "throttle", "tor")

STEP_LABELS = {
    "sites": "sites: DNS / TLS-SNI / block page / ECH", "ports": "outbound TCP ports",
    "udp": "UDP egress (STUN)", "quic": "QUIC / UDP-443", "ipv6": "IPv6 egress",
    "dns": "encrypted DNS + port-53 interception", "proxy": "transparent HTTP proxy",
    "ssh": "SSH egress", "mitm": "TLS interception (MITM)", "nxdomain": "NXDOMAIN hijack",
    "urlfilter": "URL keyword filter", "geo": "vantage point", "throttle": "throughput / throttling", "tor": "Tor bootstrap",
}


@dataclass
class ScanOptions:
    label: str | None = None
    timeout: float = 6.0
    tor_timeout: float = 60.0
    tor: bool = True
    steps: tuple = ALL_STEPS
    categories: list = field(default_factory=list)
    domains: list = field(default_factory=list)
    ech: bool = True
    blockpage: bool = True
    speed: bool = False
    verify: bool = True
    workers: int = 20

    @classmethod
    def quick(cls, **kw):
        kw.setdefault("tor", False)
        kw.setdefault("ech", False)
        kw.setdefault("blockpage", False)
        kw.setdefault("steps", ("sites", "ports", "udp", "quic", "dns", "geo"))
        return cls(**kw)

    @classmethod
    def from_config(cls, cfg: dict, profile: str | None = None, **overrides):
        from .config import PROFILES
        prof = PROFILES.get(profile or "full", {})
        steps_off = set(cfg.get("steps_off", [])) | set(prof.get("steps_off", []))
        kw = dict(
            label=cfg.get("label") or None, timeout=float(cfg.get("timeout", 6)),
            tor=bool(prof.get("tor", cfg.get("tor", True))),
            categories=list(prof.get("categories") or cfg.get("categories") or []),
            domains=list(cfg.get("domains") or []), verify=bool(cfg.get("verify", True)),
            workers=int(cfg.get("workers", 20)),
            steps=tuple(s for s in ALL_STEPS if s not in steps_off),
        )
        for k, v in overrides.items():
            if v is not None:
                kw[k] = v
        return cls(**kw)


def _noop(*a, **k):
    pass


def site_job(cat, dom, opts: ScanOptions):
    t0 = time.monotonic()
    dns_r = core.dns_test(dom, opts.timeout)
    ip = (dns_r["truth"] or dns_r["system"] or [None])[0]
    sni = core.sni_test(dom, ip, opts.timeout) if ip else {"verdict": "no-dns", "detail": ""}
    bp = core.blockpage_test(dom, opts.timeout) if opts.blockpage else {"verdict": "?", "detail": "skipped"}
    ech = core.ech_test(dom, opts.timeout) if opts.ech else None
    return dom, {"cat": cat, "dns": dns_r, "sni": sni, "blockpage": bp, "ech": ech,
                 "ms": int((time.monotonic() - t0) * 1000)}


def _positive_keys(res):
    return [k for k in ("dns", "sni", "blockpage") if res[k]["verdict"] not in core.NEUTRAL]


def recheck_job(dom, first, opts: ScanOptions):
    """Re-run only the sub-tests that came back positive (cheap, targeted)."""
    out = {}
    keys = _positive_keys(first)
    if "dns" in keys or "sni" in keys:
        dns_r = core.dns_test(dom, opts.timeout)
        out["dns"] = dns_r
        if "sni" in keys:
            ip = (dns_r["truth"] or dns_r["system"] or first["dns"].get("truth") or [None])[0]
            out["sni"] = core.sni_test(dom, ip, opts.timeout) if ip else {"verdict": "no-dns", "detail": ""}
    if "blockpage" in keys:
        out["blockpage"] = core.blockpage_test(dom, opts.timeout)
    return dom, out


def run_scan(opts: ScanOptions, emit=_noop, cancelled=lambda: False) -> dict:
    fp = sysinfo.net_fingerprint(opts.label)
    report = {"schema": 3, "version": __version__,
              "ts": time.strftime("%Y-%m-%d %H:%M:%S"), "net": fp, "geo": {},
              "sites": {}, "ports": {}, "udp": "", "udp_detail": {},
              "quic": "", "quic_detail": {}, "ipv6": {}, "dns_encrypted": {},
              "dns_intercept": {}, "http_proxy": {}, "ssh": "", "tls_intercept": {},
              "nxdomain": {}, "url_filter": {}, "tor": {}, "speed": {}, "throttle": {},
              "verified": opts.verify, "steps": list(opts.steps), "timings": {}}
    emit("net", fp)
    steps = set(opts.steps)
    t_start = time.monotonic()

    # Tor is slow and independent → its own thread from second zero
    tor_box = {}
    tor_thread = None
    if "tor" in steps and opts.tor:
        def _tor():
            t0 = time.monotonic()
            tor_box["r"] = core.tor_test(opts.tor_timeout)
            tor_box["ms"] = int((time.monotonic() - t0) * 1000)
        tor_thread = threading.Thread(target=_tor, daemon=True)
        tor_thread.start()

    sites = core.select_sites(opts.categories, opts.domains) if "sites" in steps else {}
    ex = ThreadPoolExecutor(max_workers=opts.workers)
    futs = {}

    def submit(kind, key, fn, *a):
        futs[ex.submit(fn, *a)] = (kind, key)

    for c, d in sites.items():
        submit("site", d, site_job, c, d, opts)
    if "ports" in steps:
        for l, p in core.PORTS.items():
            submit("port", l, core.port_test, l, p, opts.timeout)
    if "udp" in steps:
        for h, p in core.STUN_SERVERS:
            submit("udp", f"{h}:{p}", core.stun_udp_test, h, p, opts.timeout)
    if "quic" in steps:
        for h, p in core.QUIC_SERVERS:
            submit("quic", f"{h}:{p}", core.quic_test, h, p, opts.timeout)
    if "ipv6" in steps:
        submit("ipv6", "", core.ipv6_test, opts.timeout)
    if "dns" in steps:
        for n, url in core.DOH_SERVERS.items():
            submit("dns_enc", f"DoH {n}", core.doh_probe, url, opts.timeout)
        for n, (ip, sni) in core.DOT_SERVERS.items():
            submit("dns_enc", f"DoT {n}", core.dot_test, ip, sni, opts.timeout)
        submit("dns_int", "", core.dns_intercept_test, min(opts.timeout, 4))
    if "proxy" in steps:
        submit("http_proxy", "", core.http_proxy_test, opts.timeout)
    if "ssh" in steps:
        submit("ssh", "", core.ssh_probe, "github.com", 22, opts.timeout)
    if "mitm" in steps:
        for d in core.TLS_CANARIES:
            submit("mitm", d, core.tls_intercept_test, d, opts.timeout)
    if "nxdomain" in steps:
        submit("nxdomain", "", core.nxdomain_test, opts.timeout)
    if "urlfilter" in steps:
        submit("url_filter", "", core.url_keyword_test, opts.timeout)
    if "geo" in steps:
        submit("geo", "", core.geo_context, opts.timeout)
    if "throttle" in steps:
        submit("throttle", "", core.throttle_test)
    if opts.speed:
        submit("speed", "", core.speed_test)

    total = len(futs) + (1 if tor_thread else 0)
    done = 0
    emit("progress", 0, total)

    try:
        for f in as_completed(futs):
            if cancelled():
                ex.shutdown(wait=False, cancel_futures=True)
                return report
            kind, key = futs[f]
            try:
                r = f.result()
            except Exception as e:      # a probe must never kill the scan
                r = {"verdict": "?", "detail": f"probe error: {type(e).__name__}"}
                if kind in ("port", "udp", "quic", "dns_enc"):
                    r = f"error ({type(e).__name__})"
                elif kind == "site":
                    r = (key, {"cat": sites.get(key, "custom/" + key), "dns": r, "sni": r,
                               "blockpage": r, "ech": None, "ms": 0})
                elif kind == "ssh":
                    r = ("error", type(e).__name__)
            done += 1
            if kind == "site":
                dom, res = r
                report["sites"][dom] = res
                emit("site", dom, res)
            elif kind == "port":
                label, status = r
                report["ports"][label] = status
                emit("port", label, status)
            elif kind == "udp":
                report["udp_detail"][key] = r
                emit("udp", key, r)
            elif kind == "quic":
                report["quic_detail"][key] = r
                emit("quic", key, r)
            elif kind == "ipv6":
                report["ipv6"] = r
                emit("ipv6", r)
            elif kind == "dns_enc":
                report["dns_encrypted"][key] = r
                emit("dns_enc", key, r)
            elif kind == "dns_int":
                report["dns_intercept"] = r
                emit("dns_int", r)
            elif kind == "http_proxy":
                report["http_proxy"] = r
                emit("http_proxy", r)
            elif kind == "ssh":
                st, banner = r
                report["ssh"] = st
                emit("ssh", st, banner)
            elif kind == "mitm":
                report["tls_intercept"][key] = r
                emit("mitm", key, r)
            elif kind == "nxdomain":
                report["nxdomain"] = r
                emit("nxdomain", r)
            elif kind == "url_filter":
                report["url_filter"] = r
                emit("url_filter", r)
            elif kind == "geo":
                report["geo"] = r
                emit("geo", r)
            elif kind == "speed":
                report["speed"] = r
                emit("speed", r)
            elif kind == "throttle":
                report["throttle"] = r
                emit("throttle", r)
            emit("progress", done, total)

        if report["udp_detail"]:
            report["udp"] = "open" if any(v == "open" for v in report["udp_detail"].values()) else "BLOCKED"
            emit("udp_done", report["udp"])
        if report["quic_detail"]:
            report["quic"] = "open" if any(v == "open" for v in report["quic_detail"].values()) else "BLOCKED"
            emit("quic_done", report["quic"])
        report["timings"]["probes_ms"] = int((time.monotonic() - t_start) * 1000)

        # ── verification pass: re-check every positive once ──
        if opts.verify and sites:
            suspects = [d for d, res in report["sites"].items() if _positive_keys(res)]
            if suspects:
                emit("verify_start", len(suspects))
                t0 = time.monotonic()
                vf = {ex.submit(recheck_job, d, report["sites"][d], opts): d for d in suspects}
                for f in as_completed(vf):
                    if cancelled():
                        break
                    dom = vf[f]
                    first = report["sites"][dom]
                    try:
                        _, second = f.result()
                    except Exception:
                        continue
                    confirmed_any = False
                    for k in _positive_keys(first):
                        if k not in second:
                            continue
                        v1, v2 = first[k]["verdict"], second[k]["verdict"]
                        if v2 == v1:
                            first[k]["confirmed"] = True
                            confirmed_any = True
                        elif v2 in core.NEUTRAL:
                            first[k]["verdict"] = "?"
                            first[k]["note"] = f"transient: {v1} on first try, {v2 or 'ok'} on retry"
                            first["transient"] = True
                        else:
                            first[k]["confirmed"] = True
                            first[k]["note"] = f"retry: {v2}"
                            confirmed_any = True
                    first["confirmed"] = confirmed_any
                    emit("verify", dom, confirmed_any, first)
                report["timings"]["verify_ms"] = int((time.monotonic() - t0) * 1000)
    finally:
        ex.shutdown(wait=True)

    if tor_thread:
        emit("progress", done, total)
        tor_thread.join(timeout=opts.tor_timeout + 15)
        report["tor"] = tor_box.get("r", {"verdict": "BLOCKED?", "detail": "tor thread did not finish"})
        report["timings"]["tor_ms"] = tor_box.get("ms", 0)
        done += 1
        emit("tor", report["tor"])
        emit("progress", done, total)

    report["timings"]["total_ms"] = int((time.monotonic() - t_start) * 1000)
    report["flagged"] = core.flagged(report)
    report["analysis"] = analysis.analyze(report)
    report["lang"] = __import__("filterscope.i18n", fromlist=["get_lang"]).get_lang()
    emit("analysis", report["analysis"])
    emit("done", report)
    return report


def write_outputs(report, json_path=None, anon_path=None, html_path=None,
                  history_path=sysinfo.HISTORY_PATH, history=True, store=True):
    from . import config
    written = []
    if json_path:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        written.append(("JSON", json_path))
    if anon_path:
        with open(anon_path, "w", encoding="utf-8") as f:
            json.dump(core.anonymize(report), f, indent=2, ensure_ascii=False)
        written.append(("anonymized JSON", anon_path))
    if html_path:
        from .htmlreport import render_html
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(render_html(report))
        written.append(("HTML report", html_path))
    if history and history_path:
        os.makedirs(os.path.dirname(history_path), exist_ok=True)
        with open(history_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(core.history_record(report), ensure_ascii=False) + "\n")
        written.append(("history", history_path))
    if history and store:
        written.append(("stored report", config.store_report(report)))
    return written

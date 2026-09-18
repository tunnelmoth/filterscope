"""Scan orchestrator — runs the probes in parallel and streams results through a
callback so the CLI and the TUI share one engine.

Events (name, *args):
  net        fp
  section    key                          ("sites", "ports", "udp", "dns", "tor", …)
  site       dom, result                  result = {cat, dns, sni, blockpage, ech}
  port       label, status
  udp        server, status               one STUN server
  udp_done   "open"|"BLOCKED"
  quic       server, status
  quic_done  "open"|"BLOCKED"
  ipv6       result
  dns_enc    name, status
  dns_int    result
  http_proxy result
  ssh        status, banner
  speed      result
  tor        result
  done       report
"""
from __future__ import annotations

import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from . import __version__, core, sysinfo

ALL_STEPS = ("sites", "ports", "udp", "quic", "ipv6", "dns", "proxy", "ssh", "tor")


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
    workers: int = 8

    @classmethod
    def quick(cls, **kw):
        kw.setdefault("tor", False)
        kw.setdefault("ech", False)
        kw.setdefault("blockpage", False)
        kw.setdefault("steps", ("sites", "ports", "udp", "dns"))
        return cls(**kw)


def _noop(*a, **k):
    pass


def site_job(cat, dom, opts: ScanOptions):
    dns_r = core.dns_test(dom, opts.timeout)
    ip = (dns_r["truth"] or dns_r["system"] or [None])[0]
    sni = core.sni_test(dom, ip, opts.timeout) if ip else {"verdict": "no-dns", "detail": ""}
    bp = core.blockpage_test(dom, opts.timeout) if opts.blockpage else {"verdict": "?", "detail": "skipped"}
    ech = core.ech_test(dom, opts.timeout) if opts.ech else None
    return dom, {"cat": cat, "dns": dns_r, "sni": sni, "blockpage": bp, "ech": ech}


def run_scan(opts: ScanOptions, emit=_noop, cancelled=lambda: False) -> dict:
    fp = sysinfo.net_fingerprint(opts.label)
    report = {"schema": core.SCHEMA, "version": __version__,
              "ts": time.strftime("%Y-%m-%d %H:%M:%S"), "net": fp,
              "sites": {}, "ports": {}, "udp": "", "udp_detail": {},
              "quic": "", "quic_detail": {}, "ipv6": {}, "dns_encrypted": {},
              "dns_intercept": {}, "http_proxy": {}, "ssh": "", "tor": {}, "speed": {}}
    emit("net", fp)
    steps = set(opts.steps)

    if "sites" in steps:
        emit("section", "sites")
        sites = core.select_sites(opts.categories, opts.domains)
        with ThreadPoolExecutor(max_workers=opts.workers) as ex:
            futs = [ex.submit(site_job, c, d, opts) for c, d in sites.items()]
            for f in as_completed(futs):
                if cancelled():
                    return report
                dom, res = f.result()
                report["sites"][dom] = res
                emit("site", dom, res)

    if "ports" in steps:
        emit("section", "ports")
        with ThreadPoolExecutor(max_workers=opts.workers) as ex:
            futs = [ex.submit(core.port_test, l, p, opts.timeout) for l, p in core.PORTS.items()]
            for f in as_completed(futs):
                label, status = f.result()
                report["ports"][label] = status
                emit("port", label, status)

    if "udp" in steps:
        emit("section", "udp")
        det = core.stun_multi(opts.timeout)
        report["udp_detail"] = det
        for k, v in sorted(det.items()):
            emit("udp", k, v)
        report["udp"] = "open" if any(v == "open" for v in det.values()) else "BLOCKED"
        emit("udp_done", report["udp"])

    if "quic" in steps:
        emit("section", "quic")
        det = core.quic_multi(opts.timeout)
        report["quic_detail"] = det
        for k, v in sorted(det.items()):
            emit("quic", k, v)
        report["quic"] = "open" if any(v == "open" for v in det.values()) else "BLOCKED"
        emit("quic_done", report["quic"])

    if "ipv6" in steps:
        emit("section", "ipv6")
        report["ipv6"] = core.ipv6_test(opts.timeout)
        emit("ipv6", report["ipv6"])

    if "dns" in steps:
        emit("section", "dns")
        enc = core.encrypted_dns_test(opts.timeout)
        report["dns_encrypted"] = enc
        for k, v in sorted(enc.items()):
            emit("dns_enc", k, v)
        report["dns_intercept"] = core.dns_intercept_test(min(opts.timeout, 4))
        emit("dns_int", report["dns_intercept"])

    if "proxy" in steps:
        emit("section", "proxy")
        report["http_proxy"] = core.http_proxy_test(opts.timeout)
        emit("http_proxy", report["http_proxy"])

    if "ssh" in steps:
        emit("section", "ssh")
        st, banner = core.ssh_probe(timeout=opts.timeout)
        report["ssh"] = st
        emit("ssh", st, banner)

    if opts.speed:
        emit("section", "speed")
        report["speed"] = core.speed_test()
        emit("speed", report["speed"])

    if "tor" in steps and opts.tor:
        emit("section", "tor")
        report["tor"] = core.tor_test(opts.tor_timeout)
        emit("tor", report["tor"])

    report["flagged"] = core.flagged(report)
    emit("done", report)
    return report


def write_outputs(report, json_path=None, anon_path=None, html_path=None,
                  history_path=sysinfo.HISTORY_PATH, history=True):
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
    return written

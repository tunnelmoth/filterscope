"""filterscope command line.

  filterscope                       live TUI
  filterscope scan [opts]           CLI scan (streams results, exit 2 on interference)
  filterscope compare A.json B.json
  filterscope history [--last N] [--network X]
  filterscope wg --config wg0.conf  real WireGuard handshake test
  filterscope warp ...              Cloudflare WARP tunnel manager (Linux)
  filterscope report scan.json --html out.html   re-render a saved JSON
  filterscope categories            list site categories
"""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__, core, scan, sysinfo


def _scan_opts(a) -> scan.ScanOptions:
    steps = tuple(s.strip() for s in a.only.split(",")) if a.only else scan.ALL_STEPS
    cats = [c for c in (a.categories or "").split(",") if c]
    doms = list(a.domain or [])
    if a.domains_file:
        with open(a.domains_file, encoding="utf-8") as f:
            doms += [l.strip() for l in f if l.strip() and not l.startswith("#")]
    kw = dict(label=a.label, timeout=a.timeout, tor_timeout=a.tor_timeout, tor=not a.no_tor,
              steps=steps, categories=cats, domains=doms, speed=a.speed, workers=a.workers)
    if a.quick:
        return scan.ScanOptions.quick(**{k: v for k, v in kw.items() if k not in ("tor", "steps")})
    return scan.ScanOptions(**kw)


def add_scan_args(ap, tui=False):
    ap.add_argument("--label", help="network label (e.g. school, mobile)")
    ap.add_argument("--timeout", type=float, default=6, help="connection timeout (s)")
    ap.add_argument("--tor-timeout", type=float, default=60, help="tor bootstrap timeout (s)")
    ap.add_argument("--no-tor", action="store_true", help="skip the Tor test")
    ap.add_argument("--quick", action="store_true", help="sites+ports+udp+dns only, no Tor/ECH/blockpage")
    ap.add_argument("--only", help=f"comma list of steps: {','.join(scan.ALL_STEPS)}")
    ap.add_argument("--categories", help=f"comma list of site categories ({','.join(core.categories())})")
    ap.add_argument("--domain", action="append", help="extra domain to test (repeatable)")
    ap.add_argument("--domains-file", help="file with one extra domain per line")
    ap.add_argument("--speed", action="store_true", help="also measure downstream throughput")
    ap.add_argument("--workers", type=int, default=8, help="parallel probes")
    if not tui:
        ap.add_argument("--json", help="write the full report to a JSON file")
        ap.add_argument("--anon-json", help="write an anonymized (shareable) report")
        ap.add_argument("--html", help="write a self-contained HTML evidence report")
        ap.add_argument("--history", default=sysinfo.HISTORY_PATH, help="evidence history JSONL path")
        ap.add_argument("--no-history", action="store_true", help="don't append to history")
        ap.add_argument("--quiet", action="store_true", help="only the summary")


def cmd_scan(a) -> int:
    from .render import console, print_header, print_report, print_summary, verdict_text
    opts = _scan_opts(a)
    quiet = a.quiet

    def emit(ev, *x):
        if quiet:
            if ev == "net":
                print_header({"net": x[0], "ts": "", "version": __version__})
            return
        if ev == "net":
            print_header({"net": x[0], "ts": __import__("time").strftime("%Y-%m-%d %H:%M:%S"),
                          "version": __version__})
        elif ev == "section":
            titles = {"sites": "DNS / TLS-SNI / Block page / ECH", "ports": "Outbound TCP ports (portquiz.net)",
                      "udp": "UDP egress (STUN)", "quic": "QUIC / UDP-443", "ipv6": "IPv6",
                      "dns": "Encrypted DNS / interception", "proxy": "HTTP transparent proxy",
                      "ssh": "SSH egress", "speed": "Throughput", "tor": "Tor bootstrap (up to 60s)"}
            console.print(f"\n[bold blue]  ── {titles.get(x[0], x[0])} ──[/]")
        elif ev == "site":
            dom, r = x
            line = Text_row(dom, r)
            console.print(line)
        elif ev in ("port", "udp", "quic", "dns_enc"):
            console.print(f"  {x[0]:32} ", verdict_text(x[1]))
        elif ev in ("ipv6", "dns_int", "http_proxy", "tor"):
            r = x[0]
            label = {"ipv6": "IPv6 egress (TCP 443)", "dns_int": "port-53 interception",
                     "http_proxy": "transparent proxy headers", "tor": "Tor bootstrap"}[ev]
            console.print(f"  {label:32} ", verdict_text(r["verdict"]), f"[dim]{r.get('detail', '')}[/]")
        elif ev == "ssh":
            console.print(f"  {'ssh github.com:22':32} ", verdict_text(x[0]), f"[dim]{x[1]}[/]")
        elif ev == "speed":
            console.print(f"  {'downstream':32} {x[0].get('mbps', 0)} Mbit/s [dim]{x[0].get('detail', '')}[/]")

    try:
        report = scan.run_scan(opts, emit)
    except KeyboardInterrupt:
        console.print("\n[red]aborted[/]")
        return 130
    if quiet:
        print_summary(report)
    else:
        console.print()
        print_summary(report)
    written = scan.write_outputs(report, a.json, a.anon_json, a.html, a.history, not a.no_history)
    for what, path in written:
        console.print(f"[dim]  {what} → {path}[/]")
    return 2 if report["flagged"] else 0


def Text_row(dom, r):
    from rich.text import Text
    from .render import ech_text, verdict_text
    t = Text(f"  {r['cat']:30} ")
    for k in ("dns", "sni", "blockpage"):
        t.append_text(verdict_text(r[k]["verdict"]).copy())
        t.append(" " * max(1, 16 - len(r[k]["verdict"] or "")))
    t.append_text(ech_text(r.get("ech")))
    notes = []
    if r["sni"]["verdict"] == "SNI-DPI" and r.get("ech"):
        notes.append("ECH can bypass")
    for k in ("dns", "sni", "blockpage"):
        n = r[k].get("note") or r[k].get("detail")
        if n and r[k]["verdict"] != "ok" and n != "skipped":
            notes.append(f"{k}: {n}")
    if notes:
        t.append("  " + "; ".join(notes), style="dim")
    return t


def cmd_tui(a) -> int:
    from .tui import run_tui
    run_tui(_scan_opts(a), a.outdir)
    return 0


def cmd_compare(a) -> int:
    from .compare import compare
    return compare(a.a, a.b)


def cmd_history(a) -> int:
    from .history import show
    return show(a.path, a.network, a.last)


def cmd_report(a) -> int:
    from .render import print_report
    with open(a.json_file, encoding="utf-8") as f:
        report = json.load(f)
    report.setdefault("flagged", core.flagged(report))
    if a.html:
        from .htmlreport import render_html
        with open(a.html, "w", encoding="utf-8") as f:
            f.write(render_html(report))
        print(f"HTML report → {a.html}")
    else:
        print_report(report)
    return 2 if report["flagged"] else 0


def cmd_categories(a) -> int:
    for c in core.categories():
        doms = [d for k, d in core.SITES.items() if k.split("/")[0] == c]
        print(f"{c:16} {', '.join(doms)}")
    return 0


def build_parser():
    ap = argparse.ArgumentParser(prog="filterscope",
                                 description="Measure network filtering/censorship legitimately, "
                                             "with your own traffic and a clean allowlist.")
    ap.add_argument("--version", action="version", version=f"filterscope {__version__}")
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("tui", help="live dashboard (default)")
    add_scan_args(p, tui=True)
    p.add_argument("--outdir", help="where 's' saves reports (default: cwd)")
    p.set_defaults(fn=cmd_tui)

    p = sub.add_parser("scan", help="CLI scan; exit code 2 if interference was found")
    add_scan_args(p)
    p.set_defaults(fn=cmd_scan)

    p = sub.add_parser("compare", help="diff two JSON reports (school vs mobile)")
    p.add_argument("a")
    p.add_argument("b")
    p.set_defaults(fn=cmd_compare)

    p = sub.add_parser("history", help="evidence timeline + changes")
    p.add_argument("path", nargs="?", help="history JSONL (default ~/.filterscope/history.jsonl)")
    p.add_argument("--network", help="only this network id/label")
    p.add_argument("--last", type=int, help="only the last N records per network")
    p.set_defaults(fn=cmd_history)

    p = sub.add_parser("report", help="re-render a saved JSON report (console or --html)")
    p.add_argument("json_file")
    p.add_argument("--html")
    p.set_defaults(fn=cmd_report)

    p = sub.add_parser("categories", help="list site categories and domains")
    p.set_defaults(fn=cmd_categories)

    sub.add_parser("wg", help="real WireGuard handshake test (args passed through)", add_help=False)
    sub.add_parser("warp", help="Cloudflare WARP tunnel manager, Linux (args passed through)", add_help=False)
    return ap


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    # pass-through subcommands keep their own argparse
    if argv and argv[0] == "wg":
        from .wgcheck import main as wg_main
        return wg_main(argv[1:])
    if argv and argv[0] == "warp":
        from .warp import main as warp_main
        return warp_main(argv[1:])
    ap = build_parser()
    if not argv:
        argv = ["tui"]
    a = ap.parse_args(argv)
    if not getattr(a, "fn", None):
        ap.print_help()
        return 0
    try:
        rc = a.fn(a) or 0
    except KeyboardInterrupt:
        rc = 130
    sys.exit(rc)


if __name__ == "__main__":
    main()

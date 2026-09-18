"""filterscope command line.

  filterscope                          live TUI
  filterscope gui                      desktop window (Tkinter)
  filterscope scan [opts]              CLI scan with progress; exit 2 on interference
  filterscope scan --watch 30          re-scan every 30 min, print what changed
  filterscope compare A.json B.json    diff two reports (school vs mobile)
  filterscope diff                     this network: latest stored report vs the one before
  filterscope history [--html out]     evidence timeline
  filterscope report scan.json         re-render a saved JSON (or --html out.html)
  filterscope config [set K V]         show / edit ~/.filterscope/config.json
  filterscope wg --config wg0.conf     real WireGuard handshake test
  filterscope warp ...                 Cloudflare WARP tunnel manager (Linux)
"""
from __future__ import annotations

import argparse
import json
import sys
import time

from . import __version__, analysis, config, core, scan, sysinfo


def _scan_opts(a) -> scan.ScanOptions:
    cfg = config.load()
    doms = list(a.domain or [])
    if a.domains_file:
        with open(a.domains_file, encoding="utf-8") as f:
            doms += [l.strip() for l in f if l.strip() and not l.startswith("#")]
    cats = [c for c in (a.categories or "").split(",") if c] or None
    profile = "quick" if getattr(a, "quick", False) else a.profile
    opts = scan.ScanOptions.from_config(
        cfg, profile, label=a.label, timeout=a.timeout, tor_timeout=a.tor_timeout,
        categories=cats, speed=a.speed or None, workers=a.workers,
        verify=False if a.no_verify else None)
    if doms:
        opts.domains = list(cfg.get("domains") or []) + doms
    if a.no_tor:
        opts.tor = False
    if a.only:
        opts.steps = tuple(s.strip() for s in a.only.split(",") if s.strip())
    if a.skip:
        skip = {s.strip() for s in a.skip.split(",")}
        opts.steps = tuple(s for s in opts.steps if s not in skip)
    if getattr(a, "quick", False):
        opts.ech, opts.blockpage = False, False
    return opts


def add_scan_args(ap, tui=False):
    ap.add_argument("--label", help="network label (e.g. school, mobile)")
    ap.add_argument("--profile", choices=sorted(config.PROFILES), help="full | quick | school | isp | vpn")
    ap.add_argument("--quick", action="store_true", help="= --profile quick, minus ECH/block-page fetches")
    ap.add_argument("--timeout", type=float, help="connection timeout (s), default 6")
    ap.add_argument("--tor-timeout", type=float, help="tor bootstrap timeout (s), default 60")
    ap.add_argument("--no-tor", action="store_true", help="skip the Tor test")
    ap.add_argument("--no-verify", action="store_true", help="don't re-check positives")
    ap.add_argument("--only", help=f"comma list of steps: {','.join(scan.ALL_STEPS)}")
    ap.add_argument("--skip", help="comma list of steps to skip")
    ap.add_argument("--categories", help=f"comma list of site categories ({','.join(core.categories())})")
    ap.add_argument("--domain", action="append", help="extra domain to test (repeatable)")
    ap.add_argument("--domains-file", help="file with one extra domain per line")
    ap.add_argument("--speed", action="store_true", help="also measure downstream throughput")
    ap.add_argument("--workers", type=int, help="parallel probes (default 12)")
    if not tui:
        ap.add_argument("--json", help="write the full report to a JSON file")
        ap.add_argument("--anon-json", help="write an anonymized (shareable) report")
        ap.add_argument("--html", help="write a self-contained HTML evidence report")
        ap.add_argument("--format", choices=["rich", "json", "summary"], default="rich",
                        help="rich (default) | json (report to stdout) | summary (analysis only)")
        ap.add_argument("--flagged-only", action="store_true", help="site table: only affected sites")
        ap.add_argument("--history", default=sysinfo.HISTORY_PATH, help="evidence history JSONL path")
        ap.add_argument("--no-history", action="store_true", help="don't append to history / store report")
        ap.add_argument("--watch", type=float, metavar="MIN", help="repeat every MIN minutes, print changes")
        ap.add_argument("--quiet", action="store_true", help="alias of --format summary")


def _run_with_progress(opts, quiet=False):
    """Scan with a live progress bar; findings are printed as they land."""
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    from .render import console, escape, verdict_text
    prog = Progress(SpinnerColumn(), TextColumn("[bold blue]{task.description}"), BarColumn(),
                    TextColumn("{task.completed}/{task.total}"), TimeElapsedColumn(),
                    console=console, transient=True)
    task = prog.add_task("probing", total=1)
    state = {"tor": False}

    def emit(ev, *x):
        if ev == "progress":
            done, total = x
            prog.update(task, completed=done, total=total,
                        description="waiting for Tor" if state["tor"] and done == total - 1 else "probing")
        elif ev == "site" and not quiet:
            dom, r = x
            for k in ("dns", "sni", "blockpage"):
                v = r[k]["verdict"]
                if v not in core.NEUTRAL:
                    prog.console.print(f"  [red]⚑[/] {escape(dom):28} {k}=", verdict_text(v),
                                       f"[dim]{escape(r[k].get('detail', '') or '')}[/]")
        elif ev in ("port", "udp", "quic", "dns_enc") and not quiet:
            if x[1].startswith("BLOCKED"):
                prog.console.print(f"  [red]⚑[/] {escape(x[0]):28} ", verdict_text(x[1]))
        elif ev in ("dns_int", "http_proxy", "nxdomain", "url_filter", "ipv6") and not quiet:
            if x[0]["verdict"] not in core.NEUTRAL and x[0]["verdict"] not in ("open",):
                prog.console.print(f"  [red]⚑[/] {ev:28} ", verdict_text(x[0]["verdict"]), f"[dim]{escape(x[0].get('detail', ''))}[/]")
        elif ev == "mitm" and not quiet and x[1]["verdict"].startswith("TLS-MITM"):
            prog.console.print(f"  [red]⚑[/] TLS interception {x[0]:11} ", verdict_text(x[1]["verdict"]), f"[dim]{escape(x[1].get('detail', ''))}[/]")
        elif ev == "verify_start":
            prog.update(task, description=f"re-checking {x[0]} positives")
        elif ev == "verify" and not quiet:
            dom, ok, r = x
            if not ok:
                prog.console.print(f"  [yellow]↺[/] {escape(dom):28} transient, dropped")
        elif ev == "tor":
            state["tor"] = False
        elif ev == "net":
            state["tor"] = "tor" in opts.steps and opts.tor
    with prog:
        return scan.run_scan(opts, emit)


def cmd_scan(a) -> int:
    from .render import console, print_diff, print_header, print_report, print_summary
    opts = _scan_opts(a)
    fmt = "summary" if a.quiet else a.format
    prev = None

    while True:
        if fmt == "json":
            report = scan.run_scan(opts)
            print(json.dumps(report, ensure_ascii=False, indent=2))
        else:
            print_header({"net": sysinfo.net_fingerprint(opts.label), "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                          "version": __version__})
            report = _run_with_progress(opts, quiet=(fmt == "summary"))
            console.print()
            if fmt == "summary":
                print_summary(report)
            else:
                print_report(report, only_flagged=a.flagged_only)
        if prev is not None and fmt != "json":
            print_diff(analysis.diff(prev, report), prev["ts"], report["ts"])
        elif a.watch and fmt != "json":
            older = config.previous_report(report["net"]["id"], before_ts=report["ts"])
            if older:
                print_diff(analysis.diff(older, report), older["ts"], report["ts"])
        written = scan.write_outputs(report, a.json, a.anon_json, a.html, a.history, not a.no_history)
        if fmt != "json":
            for what, path in written:
                console.print(f"[dim]  {what} → {escape(str(path))}[/]")
        if not a.watch:
            return 2 if report["flagged"] else 0
        prev = report
        try:
            console.print(f"[dim]  next scan in {a.watch:g} min (Ctrl-C to stop)[/]")
            time.sleep(a.watch * 60)
        except KeyboardInterrupt:
            return 0


def cmd_gui(a) -> int:
    from .gui import main as gui_main
    gui_main()
    return 0


def cmd_tui(a) -> int:
    from .tui import run_tui
    run_tui(_scan_opts(a), a.outdir)
    return 0


def cmd_compare(a) -> int:
    from .compare import compare
    return compare(a.a, a.b)


def cmd_diff(a) -> int:
    from .render import console, print_diff
    net_id = a.network or sysinfo.net_fingerprint(None)["id"]
    files = config.list_reports(net_id)
    if len(files) < 2:
        console.print(f"[yellow]need at least two stored reports for network {net_id} "
                      f"(have {len(files)}; run `filterscope scan` twice)[/]")
        return 1
    old, new = config.load_report(files[-2]), config.load_report(files[-1])
    print_diff(analysis.diff(old, new), old["ts"], new["ts"])
    return 0


def cmd_history(a) -> int:
    from .history import load_runs, show
    if a.html:
        from .htmlreport import render_history_html
        runs = load_runs(a.path)
        with open(a.html, "w", encoding="utf-8") as f:
            f.write(render_history_html(runs))
        print(f"history HTML → {a.html}")
        return 0
    return show(a.path, a.network, a.last)


def cmd_report(a) -> int:
    from .render import print_report
    with open(a.json_file, encoding="utf-8") as f:
        report = json.load(f)
    report.setdefault("flagged", core.flagged(report))
    report.setdefault("analysis", analysis.analyze(report))
    if a.html:
        from .htmlreport import render_html
        with open(a.html, "w", encoding="utf-8") as f:
            f.write(render_html(report))
        print(f"HTML report → {a.html}")
    else:
        print_report(report, only_flagged=a.flagged_only)
    return 2 if report["flagged"] else 0


def cmd_config(a) -> int:
    from .render import console
    if a.action == "set":
        if not a.key or a.value is None:
            console.print("[red]usage: filterscope config set KEY VALUE[/]")
            return 2
        try:
            cfg = config.set_value(a.key, a.value)
        except (KeyError, ValueError) as e:
            console.print(f"[red]{e}[/]")
            return 2
        console.print(f"[green]{a.key} = {cfg[a.key]!r}[/]  [dim]({config.CONFIG_PATH})[/]")
        return 0
    if a.action == "path":
        print(config.CONFIG_PATH)
        return 0
    cfg = config.load()
    console.print(f"[dim]{config.CONFIG_PATH}[/]")
    for k, v in cfg.items():
        console.print(f"  {k:14} {v!r}")
    console.print(f"[dim]profiles: {', '.join(config.PROFILES)}   stored reports: {len(config.list_reports())} in {config.REPORTS_DIR}[/]")
    return 0


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

    p = sub.add_parser("gui", help="desktop window (no terminal needed)")
    p.set_defaults(fn=cmd_gui)

    p = sub.add_parser("scan", help="CLI scan; exit code 2 if interference was found")
    add_scan_args(p)
    p.set_defaults(fn=cmd_scan)

    p = sub.add_parser("compare", help="diff two JSON reports (school vs mobile)")
    p.add_argument("a")
    p.add_argument("b")
    p.set_defaults(fn=cmd_compare)

    p = sub.add_parser("diff", help="latest two stored reports of this network")
    p.add_argument("--network", help="network id (default: current)")
    p.set_defaults(fn=cmd_diff)

    p = sub.add_parser("history", help="evidence timeline + changes")
    p.add_argument("path", nargs="?", help="history JSONL (default ~/.filterscope/history.jsonl)")
    p.add_argument("--network", help="only this network id/label")
    p.add_argument("--last", type=int, help="only the last N records per network")
    p.add_argument("--html", help="write an HTML timeline")
    p.set_defaults(fn=cmd_history)

    p = sub.add_parser("report", help="re-render a saved JSON report (console or --html)")
    p.add_argument("json_file")
    p.add_argument("--html")
    p.add_argument("--flagged-only", action="store_true")
    p.set_defaults(fn=cmd_report)

    p = sub.add_parser("config", help="show or set persistent defaults")
    p.add_argument("action", nargs="?", choices=["show", "set", "path"], default="show")
    p.add_argument("key", nargs="?")
    p.add_argument("value", nargs="?")
    p.set_defaults(fn=cmd_config)

    p = sub.add_parser("categories", help="list site categories and domains")
    p.set_defaults(fn=cmd_categories)

    sub.add_parser("wg", help="real WireGuard handshake test (args passed through)", add_help=False)
    sub.add_parser("warp", help="Cloudflare WARP tunnel manager, Linux (args passed through)", add_help=False)
    return ap


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
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

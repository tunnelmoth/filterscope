"""Console rendering (rich) — works on Linux, macOS and the Windows console."""
from __future__ import annotations

from rich import box
from rich.console import Console, Group
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import analysis, core, sysinfo
from .i18n import level_name, t

console = Console(highlight=False)

NEUTRAL_YELLOW = ("?", "no-dns", "unreachable", "unavailable", "skipped", "refused", "tor-missing")
LEVEL_STYLE = {"clean": "bold green", "light": "yellow", "moderate": "bold yellow",
               "heavy": "bold red", "severe": "bold white on red"}
LEVEL_BORDER = {"clean": "green", "light": "yellow", "moderate": "yellow", "heavy": "red", "severe": "red"}


def verdict_text(v, good=("ok", "open")) -> Text:
    v = v or "—"
    if v.endswith("Mbit/s"):
        return Text(v, style="cyan")
    if v in good or v.startswith("open") or v.startswith("passed"):
        return Text(v, style="bold green")
    if v in NEUTRAL_YELLOW or v.startswith(("error", "tls-error", "bad-reply", "responded", "testing")):
        return Text(v, style="yellow")
    return Text(v, style="bold red")


def ech_text(e) -> Text:
    if e is True:
        return Text("yes", style="green")
    if e is False:
        return Text("no", style="yellow")
    return Text("?", style="dim")


def site_flagged(d) -> bool:
    return any(d[k]["verdict"] not in core.NEUTRAL for k in ("dns", "sni", "blockpage"))


def site_notes(d) -> str:
    notes = []
    if d["sni"]["verdict"] == "SNI-DPI" and d.get("ech"):
        notes.append("ECH can bypass this")
    if d["sni"].get("injected"):
        notes.append("RST injected in-path")
    if d.get("confirmed"):
        notes.append("confirmed on retry")
    for tag, r in (("dns", d["dns"]), ("sni", d["sni"]), ("bp", d["blockpage"])):
        note = r.get("note") or r.get("detail")
        if note and r.get("verdict") != "ok" and note != "skipped":
            notes.append(f"{tag}: {note}")
    return "; ".join(notes)


def score_bar(score: int, width=30) -> Text:
    filled = int(round(width * score / 100))
    style = LEVEL_STYLE[analysis.level(score)]
    t = Text()
    t.append("█" * filled, style=style)
    t.append("░" * (width - filled), style="dim")
    return t


def analysis_panel(report) -> Panel:
    an = report.get("analysis") or analysis.analyze(report)
    lvl = an["level"]
    head = Text()
    head.append(f" {an['score']:>3}/100 ", style=LEVEL_STYLE[lvl])
    head.append("  ")
    head.append_text(score_bar(an["score"]))
    head.append(f"   {level_name(lvl, up=True)}", style=LEVEL_STYLE[lvl])
    head.append(f"   {t('html.confidence')} {t('conf.' + an['confidence'])}", style="dim")
    lines = [head, Text(""), Text(an["summary"])]
    if an["techniques"]:
        tt = Text("\ntechniques: ", style="dim")
        for i, k in enumerate(an["techniques"]):
            tt.append(k, style="bold red")
            tt.append(f" ({an['technique_labels'][k]})", style="dim")
            if i < len(an["techniques"]) - 1:
                tt.append(" · ", style="dim")
        lines.append(tt)
    if an["vendor"]:
        lines.append(Text(f"vendor signature: {an['vendor']}", style="magenta"))
    geo = report.get("geo") or {}
    if geo.get("country"):
        lines.append(Text(f"vantage: {geo['country']} via Cloudflare {geo.get('colo', '?')}"
                          + ("  (WARP on)" if geo.get("warp") in ("on", "plus") else ""), style="dim"))
    return Panel(Group(*lines), title="[bold]filtering analysis[/]", border_style=LEVEL_BORDER[lvl], box=box.ROUNDED)


def category_table(report) -> Table:
    an = report.get("analysis") or analysis.analyze(report)
    t = Table(title="impact by category", title_style="bold blue", box=box.SIMPLE_HEAD, pad_edge=False)
    t.add_column("category", style="cyan")
    t.add_column("blocked", justify="right")
    t.add_column("of", justify="right", style="dim")
    t.add_column("bar")
    t.add_column("domains", style="dim")
    for r in an["categories"]:
        if not r["blocked"]:
            continue
        n = int(round(10 * r["blocked"] / max(r["total"], 1)))
        bar = Text("▮" * n, style="red") + Text("▯" * (10 - n), style="dim")
        t.add_row(r["category"], str(r["blocked"]), str(r["total"]), bar, ", ".join(r["domains"][:4]))
    if t.row_count == 0:
        t.add_row("—", "0", str(sum(r["total"] for r in an["categories"])), Text("▯" * 10, style="dim"), "nothing blocked")
    return t


def site_table(sites: dict, only_flagged=False) -> Table:
    t = Table(title="sites — DNS / TLS-SNI / block page / ECH", title_style="bold blue",
              box=box.SIMPLE_HEAD, pad_edge=False)
    t.add_column("category/site", style="cyan", no_wrap=True)
    t.add_column("DNS")
    t.add_column("TLS/SNI")
    t.add_column("block")
    t.add_column("ECH")
    t.add_column("ms", justify="right", style="dim")
    t.add_column("note", style="dim")
    rows = sorted(sites.items(), key=lambda kv: (not site_flagged(kv[1]), kv[1]["cat"]))
    for dom, d in rows:
        if only_flagged and not site_flagged(d):
            continue
        t.add_row(d["cat"], verdict_text(d["dns"]["verdict"]), verdict_text(d["sni"]["verdict"]),
                  verdict_text(d["blockpage"]["verdict"]), ech_text(d.get("ech")),
                  str(d.get("ms", "")), Text(site_notes(d)))
    return t


def kv_table(title, rows, key_hdr="probe", val_hdr="status") -> Table:
    t = Table(title=title, title_style="bold blue", box=box.SIMPLE_HEAD, pad_edge=False)
    t.add_column(key_hdr, style="cyan", no_wrap=True)
    t.add_column(val_hdr)
    t.add_column("detail", style="dim")
    for k, v, d in rows:
        t.add_row(k, verdict_text(v), Text(d or ""))
    return t


def egress_rows(report):
    misc = [(f"UDP STUN {k}", v, "") for k, v in sorted(report.get("udp_detail", {}).items())]
    misc += [(f"QUIC {k}", v, "") for k, v in sorted(report.get("quic_detail", {}).items())]
    if report.get("ipv6"):
        misc.append(("IPv6 egress", report["ipv6"]["verdict"], report["ipv6"]["detail"]))
    if report.get("ssh"):
        misc.append(("SSH egress (22)", report["ssh"], ""))
    return misc


def dns_rows(report):
    rows = [(k, v, "") for k, v in sorted(report.get("dns_encrypted", {}).items())]
    if report.get("dns_intercept"):
        rows.append(("port-53 interception", report["dns_intercept"]["verdict"], report["dns_intercept"]["detail"]))
    if report.get("nxdomain"):
        rows.append(("NXDOMAIN hijack", report["nxdomain"]["verdict"], report["nxdomain"]["detail"]))
    return rows


def http_rows(report):
    rows = []
    if report.get("http_proxy"):
        rows.append(("transparent HTTP proxy", report["http_proxy"]["verdict"], report["http_proxy"]["detail"]))
    if report.get("url_filter"):
        rows.append(("URL keyword filter", report["url_filter"]["verdict"], report["url_filter"]["detail"]))
    for dom, r in sorted(report.get("tls_intercept", {}).items()):
        rows.append((f"TLS chain {dom}", r["verdict"], r.get("detail") or f"issuer {r.get('issuer', '?')}"))
    if report.get("speed"):
        sp = report["speed"]
        rows.append(("downstream", f"{sp.get('mbps', 0)} Mbit/s", sp.get("detail", "")))
    th = report.get("throttle") or {}
    for k, v in th.get("targets", {}).items():
        rows.append((f"{t('ui.throttle')} {k}", f"{v.get('mbps', 0)} Mbit/s" if not v.get("error") else f"error ({v['error']})", ""))
    if th:
        rows.append(("throttling", th.get("verdict", "?"), th.get("detail", "")))
    if report.get("tor"):
        rows.append(("Tor bootstrap", report["tor"]["verdict"], report["tor"]["detail"]))
    return rows


def print_header(report):
    fp = report["net"]
    console.print(f"\n[bold]  {t('ui.title')}[/] [dim]({report.get('ts', '')})  filterscope {report.get('version', '')}[/]")
    console.print(f"[dim]  {t('ui.network')}: {escape(sysinfo.net_name(fp))}  [id {fp['id']}]  gw {escape(fp.get('gateway') or '?')}  "
                  f"resolver {escape(fp.get('resolver') or '?')}  {escape(fp.get('os', ''))}[/]")
    console.print("[dim]  your own traffic, clean allowlist — no inappropriate sites pinged[/]\n")


def print_report(report, only_flagged=False):
    """Full static rendering of a finished report."""
    print_header(report)
    console.print(analysis_panel(report))
    console.print()
    if report.get("sites"):
        console.print(category_table(report))
        console.print(site_table(report["sites"], only_flagged))
        console.print()
    if report.get("ports"):
        console.print(kv_table("outbound TCP ports (portquiz.net)",
                               [(l, s, "") for l, s in sorted(report["ports"].items())], "port"))
    if egress_rows(report):
        console.print(kv_table("UDP / QUIC / IPv6 / SSH egress", egress_rows(report)))
    if dns_rows(report):
        console.print(kv_table("DNS integrity", dns_rows(report)))
    if http_rows(report):
        console.print(kv_table("HTTP / TLS / Tor", http_rows(report)))
    print_summary(report, with_analysis=False)


def print_summary(report, with_analysis=True):
    if with_analysis:
        console.print(analysis_panel(report))
    fl = report.get("flagged") or core.flagged(report)
    if fl:
        console.print(f"\n[bold red]  ⚑ {t('ui.signals', n=len(fl))}[/]")
        for f in fl:
            console.print(f"     {escape(f)}")
    else:
        console.print(f"\n[bold green]  {t('ui.no_interference')}[/]")
    ech_bypass = [dom for dom, d in report.get("sites", {}).items()
                  if d["sni"]["verdict"] == "SNI-DPI" and d.get("ech")]
    if ech_bypass:
        console.print(f"[green]  ⓘ {t('ui.ech_bypass')}[/] " + ", ".join(ech_bypass))
    transient = [dom for dom, d in report.get("sites", {}).items() if d.get("transient")]
    if transient:
        console.print(f"[yellow]  ⓘ {t('ui.transient')}[/] " + ", ".join(transient))
    console.print(f"\n[bold]  ── {t('ui.vpn_diag').upper()} ──[/]")
    for c, line in core.vpn_advice(report):
        console.print(_c(c, "  " + line))
    console.print(f"\n[bold]  ── {t('ui.tunnel').upper()} ──[/]")
    for c, line in core.tunnel_advice(report):
        console.print(_c(c, "  " + line))
    tm = report.get("timings", {})
    if tm.get("total_ms"):
        console.print(f"\n[dim]  scan {tm['total_ms'] / 1000:.1f}s "
                      f"(probes {tm.get('probes_ms', 0) / 1000:.1f}s, verify {tm.get('verify_ms', 0) / 1000:.1f}s"
                      + (f", tor {tm['tor_ms'] / 1000:.0f}s" if tm.get("tor_ms") else "") + ")[/]")
    console.print()


def print_diff(d: dict, old_ts: str, new_ts: str):
    console.print(f"\n[bold]  CHANGES[/] [dim]{old_ts} → {new_ts}[/]  score {d['score_old']} → {d['score_new']}")
    for x in d["added"]:
        console.print(f"     [red]+ new block: {escape(x)}[/]")
    for x in d["removed"]:
        console.print(f"     [green]- lifted:    {escape(x)}[/]")
    if not d["added"] and not d["removed"]:
        console.print("     [dim](no change)[/]")


_STYLE = {"g": "green", "r": "red", "y": "yellow", "d": "dim", "b": "blue"}


def _c(c, s) -> Text:
    return Text(s, style=_STYLE.get(c, ""))

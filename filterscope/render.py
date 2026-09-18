"""Console rendering (rich) — works on Linux, macOS and the Windows console."""
from __future__ import annotations

from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from . import core, sysinfo

console = Console(highlight=False)

NEUTRAL_YELLOW = ("?", "no-dns", "unreachable", "unavailable", "skipped", "refused")


def verdict_text(v, good=("ok", "open")) -> Text:
    v = v or "—"
    if v in good or v.startswith("open") or v.startswith("passed"):
        return Text(v, style="bold green")
    if v in NEUTRAL_YELLOW or v.startswith(("error", "tls-error", "bad-reply", "responded")):
        return Text(v, style="yellow")
    return Text(v, style="bold red")


def ech_text(e) -> Text:
    if e is True:
        return Text("yes", style="green")
    if e is False:
        return Text("no", style="yellow")
    return Text("?", style="dim")


def site_table(sites: dict) -> Table:
    t = Table(title="DNS / TLS-SNI / Block page / ECH", title_style="bold blue",
              show_lines=False, pad_edge=False)
    t.add_column("category/site", style="cyan", no_wrap=True)
    t.add_column("DNS")
    t.add_column("TLS/SNI")
    t.add_column("block")
    t.add_column("ECH")
    t.add_column("note", style="dim")
    for dom, d in sorted(sites.items(), key=lambda kv: kv[1]["cat"]):
        notes = []
        if d["sni"]["verdict"] == "SNI-DPI" and d.get("ech"):
            notes.append("[green]ECH can bypass this[/]")
        for tag, r in (("dns", d["dns"]), ("sni", d["sni"]), ("bp", d["blockpage"])):
            note = r.get("note") or r.get("detail")
            if note and r.get("verdict") != "ok" and note != "skipped":
                notes.append(escape(f"{tag}: {note}"))
        t.add_row(d["cat"], verdict_text(d["dns"]["verdict"]), verdict_text(d["sni"]["verdict"]),
                  verdict_text(d["blockpage"]["verdict"]), ech_text(d.get("ech")),
                  Text.from_markup("; ".join(notes)))
    return t


def kv_table(title, rows, key_hdr="probe", val_hdr="status") -> Table:
    t = Table(title=title, title_style="bold blue", pad_edge=False)
    t.add_column(key_hdr, style="cyan", no_wrap=True)
    t.add_column(val_hdr)
    t.add_column("detail", style="dim")
    for k, v, d in rows:
        t.add_row(k, verdict_text(v), Text(d or ""))
    return t


def print_header(report):
    fp = report["net"]
    console.print(f"\n[bold]  NETWORK FILTERING TEST[/] [dim]({report['ts']})  filterscope {report.get('version', '')}[/]")
    console.print(f"[dim]  network: {sysinfo.net_name(fp)}  [id {fp['id']}]  gw {fp.get('gateway') or '?'}  "
                  f"resolver {fp.get('resolver') or '?'}  {fp.get('os', '')}[/]")
    console.print("[dim]  your own traffic, clean allowlist — no inappropriate sites pinged[/]\n")


def print_report(report):
    """Full static rendering of a finished report."""
    print_header(report)
    if report["sites"]:
        console.print(site_table(report["sites"]))
        console.print()
    if report["ports"]:
        rows = [(l, s, "") for l, s in sorted(report["ports"].items())]
        console.print(kv_table("Outbound TCP ports (portquiz.net)", rows, "port"))
        console.print()
    misc = []
    for k, v in sorted(report.get("udp_detail", {}).items()):
        misc.append((f"UDP STUN {k}", v, ""))
    for k, v in sorted(report.get("quic_detail", {}).items()):
        misc.append((f"QUIC {k}", v, ""))
    if report.get("ipv6"):
        misc.append(("IPv6 egress", report["ipv6"]["verdict"], report["ipv6"]["detail"]))
    if misc:
        console.print(kv_table("UDP / QUIC / IPv6 egress", misc))
        console.print()
    dnsrows = [(k, v, "") for k, v in sorted(report.get("dns_encrypted", {}).items())]
    if report.get("dns_intercept"):
        di = report["dns_intercept"]
        dnsrows.append(("port-53 interception", di["verdict"], di["detail"]))
    if dnsrows:
        console.print(kv_table("Encrypted DNS / interception", dnsrows))
        console.print()
    other = []
    if report.get("http_proxy"):
        hp = report["http_proxy"]
        other.append(("HTTP transparent proxy", hp["verdict"], hp["detail"]))
    if report.get("ssh"):
        other.append(("SSH egress (22)", report["ssh"], ""))
    if report.get("speed"):
        sp = report["speed"]
        other.append(("downstream", f"{sp.get('mbps', 0)} Mbit/s", sp.get("detail", "")))
    if report.get("tor"):
        other.append(("Tor bootstrap", report["tor"]["verdict"], report["tor"]["detail"]))
    if other:
        console.print(kv_table("Proxy / SSH / Tor", other))
        console.print()
    print_summary(report)


def print_summary(report):
    console.print("[bold]  ── SUMMARY ──[/]")
    fl = report.get("flagged") or core.flagged(report)
    if fl:
        console.print(f"[bold red]  ⚑ {len(fl)} interference signals:[/]")
        for f in fl:
            console.print(f"     {escape(f)}")
    else:
        console.print("[bold green]  No clear interference detected.[/]")
    ech_bypass = [dom for dom, d in report["sites"].items()
                  if d["sni"]["verdict"] == "SNI-DPI" and d.get("ech")]
    if ech_bypass:
        console.print("[green]  ⓘ Reachable via ECH (SNI-DPI bypassed):[/] " + ", ".join(ech_bypass))
    injected = [dom for dom, d in report["sites"].items() if d["sni"].get("injected")]
    if injected:
        console.print("[yellow]  ⓘ RST injected by an in-path middlebox (faster than server RTT):[/] "
                      + ", ".join(injected))

    console.print("\n[bold]  ── VPN DIAGNOSIS ──[/]")
    for c, line in core.vpn_advice(report):
        console.print(_c(c, "  " + line))
    console.print("\n[bold]  ── TUNNEL / CIRCUMVENTION ──[/]")
    for c, line in core.tunnel_advice(report):
        console.print(_c(c, "  " + line))
    console.print()


_STYLE = {"g": "green", "r": "red", "y": "yellow", "d": "dim", "b": "blue"}


def _c(c, s) -> Text:
    return Text(s, style=_STYLE.get(c, ""))

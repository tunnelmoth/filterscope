"""filterscope TUI — live network filtering dashboard (Textual).

Runs the scan engine in a background thread and fills the tables in real time.
Keys:  r=rescan   t=toggle Tor   s=save JSON+HTML   q=quit
"""
from __future__ import annotations

import os
import time

from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Footer, Header, RichLog, Static
from textual.worker import get_current_worker

from . import __version__, core, scan, sysinfo
from .render import ech_text, verdict_text

EXTRA_ROWS = ["UDP egress (STUN)", "QUIC/UDP-443", "IPv6", "DoH cloudflare", "DoH google",
              "DoH adguard", "DoT cloudflare", "DoT google", "DoT quad9", "DNS-53 interception",
              "HTTP proxy", "SSH banner", "Tor bootstrap"]


class FilterScope(App):
    TITLE = f"filterscope {__version__}"
    CSS = """
    #net { height: 1; color: $text-muted; padding: 0 1; }
    .panel { border: round $primary; }
    #sites { width: 2fr; }
    #right { width: 1fr; }
    #ports { height: 65%; }
    #log { height: 35%; border: round $accent; }
    DataTable { height: 1fr; }
    """
    BINDINGS = [
        ("r", "rescan", "Rescan"),
        ("t", "toggle_tor", "Toggle Tor"),
        ("s", "save", "Save report"),
        ("q", "quit", "Quit"),
    ]

    def __init__(self, opts: scan.ScanOptions, outdir: str | None = None):
        super().__init__()
        self.opts = opts
        self.outdir = outdir or os.getcwd()
        self.report = None
        self.flags = 0
        self._touched = set()

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("network: scanning…", id="net")
        with Horizontal():
            t = DataTable(id="sites", classes="panel")
            t.border_title = "Sites — DNS / TLS-SNI / Block / ECH"
            yield t
            with Vertical(id="right"):
                p = DataTable(id="ports", classes="panel")
                p.border_title = "Ports / Protocols / DNS"
                yield p
                yield RichLog(id="log", highlight=False, markup=True)
        yield Footer()

    def on_mount(self):
        st = self.query_one("#sites", DataTable)
        st.add_column("category/site", key="cat")
        for c in ("DNS", "TLS/SNI", "block", "ECH"):
            st.add_column(c, key=c)
        st.cursor_type = "row"
        self.sites = core.select_sites(self.opts.categories, self.opts.domains)
        for cat, dom in sorted(self.sites.items()):
            st.add_row(cat, Text("…", style="dim"), "", "", "", key=dom)
        pt = self.query_one("#ports", DataTable)
        pt.add_column("probe", key="probe")
        pt.add_column("status", key="status")
        for label in list(core.PORTS) + EXTRA_ROWS:
            pt.add_row(label, Text("…", style="dim"), key=label)
        self.action_rescan()

    # ── UI helpers (main thread) ──
    def set_net(self, fp):
        self.query_one("#net", Static).update(
            f"network: {sysinfo.net_name(fp)}   [id {fp['id']}]   gw {fp['gateway'] or '?'}   "
            f"resolver {fp['resolver'] or '?'}   {fp.get('os', '')}")

    def update_site(self, dom, res):
        t = self.query_one("#sites", DataTable)
        t.update_cell(dom, "DNS", verdict_text(res["dns"]["verdict"]))
        t.update_cell(dom, "TLS/SNI", verdict_text(res["sni"]["verdict"]))
        t.update_cell(dom, "block", verdict_text(res["blockpage"]["verdict"]))
        t.update_cell(dom, "ECH", ech_text(res.get("ech")))
        for k in ("dns", "sni", "blockpage"):
            v = res[k]["verdict"]
            if v not in core.NEUTRAL:
                self.flags += 1
                note = ""
                if k == "sni" and v == "SNI-DPI" and res.get("ech"):
                    note = "(bypassable via ECH)"
                if res[k].get("injected"):
                    note += " (RST injected in-path)"
                self.log_write(f"[red]⚑ {dom}: {k}={v}[/] {note}")

    def update_row(self, label, status):
        self._touched.add(label)
        self.query_one("#ports", DataTable).update_cell(label, "status", verdict_text(status))
        if status.startswith(("BLOCKED", "INTERCEPTED", "PROXY")):
            self.flags += 1
            self.log_write(f"[red]⚑ {label}: {status}[/]")

    def log_write(self, msg):
        self.query_one("#log", RichLog).write(msg)

    def finish(self, report):
        self.report = report
        for label in list(core.PORTS) + EXTRA_ROWS:
            if label not in self._touched:
                self.query_one("#ports", DataTable).update_cell(label, "status", Text("skipped", style="dim"))
        n = len(report.get("flagged", []))
        self.log_write(f"[green]✓ scan done — {n} interference signals[/]" if n
                       else "[green]✓ scan done — no clear interference[/]")
        self.log_write("[dim]press s to save JSON + HTML[/]")

    # ── actions ──
    def action_rescan(self):
        self.flags = 0
        self.report = None
        self._touched = set()
        self.query_one("#log", RichLog).clear()
        self.log_write("[dim]scan started…[/]")
        self.run_worker(self._scan, thread=True, exclusive=True, group="scan")

    def action_toggle_tor(self):
        self.opts.tor = not self.opts.tor
        self.log_write(f"[yellow]Tor test: {'on' if self.opts.tor else 'off'} (takes effect on rescan)[/]")

    def action_save(self):
        if not self.report:
            self.log_write("[yellow]no finished report yet[/]")
            return
        stamp = time.strftime("%Y%m%d-%H%M%S")
        base = os.path.join(self.outdir, f"filterscope-{self.report['net'].get('label') or self.report['net']['id']}-{stamp}")
        scan.write_outputs(self.report, json_path=base + ".json", html_path=base + ".html", history=False)
        self.log_write(f"[green]saved {base}.json / .html[/]")

    # ── worker thread ──
    def _scan(self):
        worker = get_current_worker()

        def emit(ev, *a):
            if worker.is_cancelled:
                return
            if ev == "net":
                self.call_from_thread(self.set_net, a[0])
            elif ev == "site":
                self.call_from_thread(self.update_site, a[0], a[1])
            elif ev == "port":
                self.call_from_thread(self.update_row, a[0], a[1])
            elif ev == "udp_done":
                self.call_from_thread(self.update_row, "UDP egress (STUN)", a[0])
            elif ev == "quic_done":
                self.call_from_thread(self.update_row, "QUIC/UDP-443", a[0])
            elif ev == "ipv6":
                self.call_from_thread(self.update_row, "IPv6", a[0]["verdict"])
            elif ev == "dns_enc":
                self.call_from_thread(self.update_row, a[0], a[1])
            elif ev == "dns_int":
                self.call_from_thread(self.update_row, "DNS-53 interception", a[0]["verdict"])
            elif ev == "http_proxy":
                self.call_from_thread(self.update_row, "HTTP proxy", a[0]["verdict"])
            elif ev == "ssh":
                self.call_from_thread(self.update_row, "SSH banner", a[0])
            elif ev == "section" and a[0] == "tor":
                self.call_from_thread(self.update_row, "Tor bootstrap", "testing…")
                self.call_from_thread(self.log_write, "[dim]Tor bootstrap (up to 60s)…[/]")
            elif ev == "tor":
                v = a[0]["verdict"]
                self.call_from_thread(self.update_row, "Tor bootstrap",
                                      "open" if v == "ok" else ("tor-missing" if v == "tor-missing" else f"BLOCKED ({v})"))
            elif ev == "done":
                if not self.opts.tor:
                    self.call_from_thread(self.update_row, "Tor bootstrap", "skipped")
                self.call_from_thread(self.finish, a[0])

        scan.run_scan(self.opts, emit, cancelled=lambda: worker.is_cancelled)


def run_tui(opts: scan.ScanOptions, outdir=None):
    FilterScope(opts, outdir).run()

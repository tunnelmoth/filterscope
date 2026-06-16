#!/usr/bin/env python3
"""filterscope TUI — live network filtering dashboard (Textual).

Runs the test functions from filtertest.py in the background and renders the
results into tables in real time.

Keys:  r=rescan   t=toggle Tor   q=quit

Usage:
  ./tui.py                ./tui.py --label school --no-tor
"""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Footer, Header, RichLog, Static
from textual.worker import get_current_worker

import filtertest as ft


def vcol(v, good="ok"):
    if v == good:
        return Text(v, style="bold green")
    if v in ("?", "no-dns", "unreachable", ""):
        return Text(v or "—", style="yellow")
    return Text(v, style="bold red")


def echcol(e):
    if e is True:
        return Text("yes", style="green")
    if e is False:
        return Text("no", style="yellow")
    return Text("?", style="dim")


def portcol(st):
    if st.startswith("BLOCKED"):
        return Text(st, style="bold red")
    if st == "open":
        return Text(st, style="green")
    return Text(st, style="yellow")


class FilterScope(App):
    CSS = """
    #net { height: 1; color: $text-muted; padding: 0 1; }
    .panel { border: round $primary; }
    #sites { width: 2fr; }
    #right { width: 1fr; }
    #ports { height: 60%; }
    #log { height: 40%; border: round $accent; }
    DataTable { height: 1fr; }
    """
    BINDINGS = [
        ("r", "rescan", "Rescan"),
        ("t", "toggle_tor", "Toggle Tor"),
        ("q", "quit", "Quit"),
    ]

    def __init__(self, label, do_tor, timeout, tor_timeout):
        super().__init__()
        self.label = label
        self.do_tor = do_tor
        self.timeout = timeout
        self.tor_timeout = tor_timeout
        self.flags = 0

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("network: scanning…", id="net")
        with Horizontal():
            t = DataTable(id="sites", classes="panel")
            t.border_title = "Sites — DNS / TLS-SNI / Block / ECH"
            yield t
            with Vertical(id="right"):
                p = DataTable(id="ports", classes="panel")
                p.border_title = "Port / Protocol"
                yield p
                yield RichLog(id="log", highlight=False, markup=True)
        yield Footer()

    def on_mount(self):
        st = self.query_one("#sites", DataTable)
        st.add_column("category/site", key="cat")
        for c in ("DNS", "TLS/SNI", "block", "ECH"):
            st.add_column(c, key=c)
        st.cursor_type = "row"
        for cat, dom in sorted(ft.SITES.items()):
            st.add_row(cat, Text("…", style="dim"), "", "", "", key=dom)
        pt = self.query_one("#ports", DataTable)
        pt.add_column("port", key="port")
        pt.add_column("status", key="status")
        for label in list(ft.PORTS) + ["UDP egress (STUN)", "Tor bootstrap"]:
            pt.add_row(label, Text("…", style="dim"), key=label)
        self.action_rescan()

    # ── worker → UI updates (called via call_from_thread) ──
    def set_net(self, fp):
        name = fp.get("label") or fp["ssid"] or fp["search"] or "?"
        self.query_one("#net", Static).update(
            f"network: {name}   [id {fp['id']}]   gw {fp['gateway'] or '?'}   "
            f"resolver {fp['resolver'] or '?'}")

    def update_site(self, dom, dns_r, sni, bp, ech):
        t = self.query_one("#sites", DataTable)
        t.update_cell(dom, "DNS", vcol(dns_r["verdict"]))
        t.update_cell(dom, "TLS/SNI", vcol(sni["verdict"]))
        t.update_cell(dom, "block", vcol(bp["verdict"]))
        t.update_cell(dom, "ECH", echcol(ech))
        v = sni["verdict"]
        if v not in ("ok", "?", "no-dns"):
            self.flags += 1
            note = "bypassable via ECH" if (v == "SNI-DPI" and ech) else ""
            self.log_write(f"[red]⚑ {dom}: {v}[/] {note}")

    def update_port(self, label, status):
        self.query_one("#ports", DataTable).update_cell(label, "status", portcol(status))
        if status.startswith("BLOCKED"):
            self.log_write(f"[red]⚑ port {label}: {status}[/]")

    def log_write(self, msg):
        self.query_one("#log", RichLog).write(msg)

    def finish(self):
        msg = (f"[green]✓ scan done — {self.flags} interference[/]"
               if self.flags else "[green]✓ scan done — no clear interference[/]")
        self.log_write(msg)

    # ── actions ──
    def action_rescan(self):
        self.flags = 0
        self.query_one("#log", RichLog).clear()
        self.log_write("[dim]scan started…[/]")
        self.scan()

    def action_toggle_tor(self):
        self.do_tor = not self.do_tor
        self.log_write(f"[yellow]Tor test: {'on' if self.do_tor else 'off'}[/]")

    def scan(self):
        """thread worker — run tests, update the UI via call_from_thread."""
        self.run_worker(self._scan, thread=True, exclusive=True, group="scan")

    def _scan(self):
        worker = get_current_worker()
        fp = ft.net_fingerprint(self.label)
        self.call_from_thread(self.set_net, fp)

        def job(cat, dom):
            dns_r = ft.dns_test(dom, self.timeout)
            ip = (dns_r["truth"] or dns_r["system"] or [None])[0]
            sni = ft.sni_test(dom, ip, self.timeout) if ip else {"verdict": "no-dns", "detail": ""}
            bp = ft.blockpage_test(dom, self.timeout)
            ech = ft.ech_test(dom, self.timeout)
            return dom, dns_r, sni, bp, ech

        with ThreadPoolExecutor(max_workers=8) as ex:
            futs = [ex.submit(job, c, d) for c, d in ft.SITES.items()]
            for f in as_completed(futs):
                if worker.is_cancelled:
                    return
                dom, dns_r, sni, bp, ech = f.result()
                self.call_from_thread(self.update_site, dom, dns_r, sni, bp, ech)

        with ThreadPoolExecutor(max_workers=8) as ex:
            futs = [ex.submit(ft.port_test, l, p, self.timeout) for l, p in ft.PORTS.items()]
            for f in as_completed(futs):
                label, status = f.result()
                self.call_from_thread(self.update_port, label, status)
        udp = ft.stun_udp_test(timeout=self.timeout)
        self.call_from_thread(self.update_port, "UDP egress (STUN)", udp)

        if self.do_tor:
            self.call_from_thread(self.update_port, "Tor bootstrap", "testing…")
            self.call_from_thread(self.log_write, "[dim]Tor bootstrap (up to 60s)…[/]")
            tr = ft.tor_test(self.tor_timeout)
            self.call_from_thread(self.update_port, "Tor bootstrap",
                                  "open" if tr["verdict"] == "ok" else f"BLOCKED ({tr['verdict']})")
        else:
            self.call_from_thread(self.update_port, "Tor bootstrap", "skipped")
        self.call_from_thread(self.finish)


def main():
    ap = argparse.ArgumentParser(description="filterscope live TUI")
    ap.add_argument("--label", help="network label")
    ap.add_argument("--no-tor", action="store_true")
    ap.add_argument("--timeout", type=float, default=6)
    ap.add_argument("--tor-timeout", type=float, default=60)
    a = ap.parse_args()
    FilterScope(a.label, not a.no_tor, a.timeout, a.tor_timeout).run()


if __name__ == "__main__":
    main()

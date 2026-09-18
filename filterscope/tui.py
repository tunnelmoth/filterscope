"""filterscope TUI — live network filtering dashboard (Textual).

Tabs:   Overview · Sites · Egress · History · Help
Keys:   r rescan   t toggle Tor   s save JSON+HTML   / filter sites   f flagged only
        c compare with previous scan of this network   1-5 tabs   q quit
"""
from __future__ import annotations

import os
import time

from rich.markup import escape
from rich.text import Text
from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import (DataTable, Footer, Header, Input, Label, ProgressBar, RichLog, Static,
                             TabbedContent, TabPane)
from textual.worker import get_current_worker

from . import __version__, analysis, config, core, scan, sysinfo
from .i18n import level_name, t
from .render import (LEVEL_STYLE, analysis_panel, category_table, ech_text, score_bar, site_flagged,
                     verdict_text)

EGRESS_ROWS = ["UDP egress (STUN)", "QUIC/UDP-443", "IPv6", "SSH banner",
               "DoH cloudflare", "DoH google", "DoH adguard", "DoT cloudflare", "DoT google", "DoT quad9",
               "DNS-53 interception", "NXDOMAIN hijack", "HTTP proxy", "URL keyword filter",
               "TLS chain wikipedia.org", "TLS chain github.com", "TLS chain duckduckgo.com", "TLS chain bbc.com",
               "throttling", "Tor bootstrap"]

HELP = """\
[b]filterscope[/b] measures the filtering behaviour of the network you are on, using only your
own traffic and a clean allowlist of well-known sites.

[b]Keys[/b]
  r  rescan                 t  toggle the Tor test (applies on next rescan)
  s  save JSON + HTML       c  compare with the previous stored scan of this network
  /  filter the site table  f  show only affected sites
  1-5  switch tabs          q  quit

[b]Verdicts[/b]
  [red]SNI-DPI[/red]           TLS server name is inspected; the site is reset only with its real name
  [red]HIJACK-blockpage[/red]  DNS answers with a private IP (block-page server)
  [red]DNS-BLOCK[/red]         resolver withholds the answer while DoH resolves
  [red]BLOCKPAGE[/red]         HTTP fetch returns a known filter page
  [red]TLS-MITM[/red]          HTTPS is decrypted by the network with its own CA
  [red]INTERCEPTED[/red]       port-53 DNS is transparently proxied; "use 8.8.8.8" is ignored
  [red]BLOCKED[/red]           packets to that port/protocol are dropped
  [yellow]?[/yellow]                 undecided (no reference, or a positive that did not reproduce)

[b]Score[/b]  share of affected sites (max 50) + a weight per technique + 2 per blocked port.
         0 clean · 1-19 light · 20-44 moderate · 45-69 heavy · 70+ severe
[b]Verification[/b]  every positive site result is re-tested once; non-reproducible ones are dropped.

Evidence: run the same scan on another network (mobile data) and use [i]compare[/i].
"""

ADV_STYLE = {"g": "green", "r": "red", "y": "yellow"}


class FilterScope(App):
    TITLE = f"filterscope {__version__}"
    CSS = """
    Screen { layout: vertical; }
    #top { height: 4; padding: 0 1; }
    #net { color: $text-muted; height: 1; }
    #scoreline { height: 1; }
    #progress { height: 1; }
    ProgressBar Bar { width: 40; }
    TabbedContent { height: 1fr; }
    .panel { border: round $primary; }
    #ovl { width: 3fr; }
    #ovr { width: 2fr; }
    #findings { height: 1fr; min-height: 8; border: round $accent; }
    #advice { height: 1fr; border: round $secondary; padding: 0 1; }
    #analysis { height: auto; }
    #cats { height: auto; }
    #sitebar { height: 3; }
    #filter { width: 1fr; }
    #sites { height: 1fr; }
    #detail { height: 8; border: round $secondary; padding: 0 1; }
    #egress_tbl { width: 1fr; }
    #ports_tbl { width: 1fr; }
    #help_text { padding: 1 2; }
    """
    BINDINGS = [
        Binding("r", "rescan", "Rescan"),
        Binding("t", "toggle_tor", "Tor"),
        Binding("s", "save", "Save"),
        Binding("c", "compare_prev", "Compare prev"),
        Binding("slash", "focus_filter", "Filter", key_display="/"),
        Binding("f", "toggle_flagged", "Flagged only"),
        Binding("1", "tab('overview')", "Overview", show=False),
        Binding("2", "tab('sites_tab')", "Sites", show=False),
        Binding("3", "tab('egress')", "Egress", show=False),
        Binding("4", "tab('history')", "History", show=False),
        Binding("5", "tab('help')", "Help", show=False),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, opts: scan.ScanOptions, outdir: str | None = None):
        super().__init__()
        self.opts = opts
        self.outdir = outdir or os.getcwd()
        self.report = None
        self.live = {"sites": {}}
        self.sites_expected = {}
        self._touched = set()
        self._filter = ""
        self._flagged_only = False

    # ── layout ──
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="top"):
            yield Static("network: detecting…", id="net")
            yield Static("", id="scoreline")
            yield ProgressBar(total=100, show_eta=False, id="progress")
        with TabbedContent(initial="overview"):
            with TabPane("Overview", id="overview"):
                with Horizontal():
                    with VerticalScroll(id="ovl"):
                        yield Static("", id="analysis")
                        yield Static("", id="cats")
                        yield RichLog(id="findings", highlight=False, markup=True)
                    with Vertical(id="ovr"):
                        yield Static("", id="advice")
            with TabPane("Sites", id="sites_tab"):
                with Horizontal(id="sitebar"):
                    yield Input(placeholder="filter: category, domain or verdict (e.g. ai, discord, SNI-DPI)", id="filter")
                    yield Label("", id="sitecount")
                yield DataTable(id="sites", classes="panel")
                yield Static("select a row for details", id="detail")
            with TabPane("Egress", id="egress"):
                with Horizontal():
                    yield DataTable(id="ports_tbl", classes="panel")
                    yield DataTable(id="egress_tbl", classes="panel")
            with TabPane("History", id="history"):
                yield DataTable(id="history_tbl", classes="panel")
            with TabPane("Help", id="help"):
                yield Static(Text.from_markup(HELP), id="help_text")
        yield Footer()

    def on_mount(self):
        st = self.query_one("#sites", DataTable)
        st.add_column("category/site", key="cat")
        for c in ("DNS", "TLS/SNI", "block", "ECH", "ms"):
            st.add_column(c, key=c)
        st.cursor_type = "row"
        st.zebra_stripes = True
        st.border_title = "sites"
        pt = self.query_one("#ports_tbl", DataTable)
        pt.border_title = "TCP ports (portquiz.net)"
        pt.add_column("port", key="port")
        pt.add_column("status", key="status")
        for label in core.PORTS:
            pt.add_row(label, Text("…", style="dim"), key=label)
        et = self.query_one("#egress_tbl", DataTable)
        et.border_title = "UDP / QUIC / DNS / HTTP / TLS / Tor"
        et.add_column("probe", key="probe")
        et.add_column("status", key="status")
        for label in EGRESS_ROWS:
            et.add_row(label, Text("…", style="dim"), key=label)
        self.query_one("#findings", RichLog).border_title = "findings"
        self.query_one("#advice", Static).border_title = "diagnosis & advice"
        self.load_history()
        self.action_rescan()
        self.run_worker(self._check_update, thread=True, group="update")

    def _check_update(self):
        if not config.load().get("update_check", True):
            return
        u = core.check_update(timeout=5)
        if u and u.get("newer"):
            self.call_from_thread(self.notify, f"{t('ui.update', latest=u['latest'])}: {u['url']}", title="filterscope", timeout=12)

    # ── header ──
    def set_net(self, fp):
        self.query_one("#net", Static).update(Text(
            f"network: {sysinfo.net_name(fp)}   [id {fp['id']}]   gw {fp['gateway'] or '?'}   "
            f"resolver {fp['resolver'] or '?'}   {fp.get('os', '')}"))

    def set_progress(self, done, total):
        self.query_one("#progress", ProgressBar).update(total=max(total, 1), progress=done)

    def set_scoreline(self, text: Text):
        self.query_one("#scoreline", Static).update(text)

    # ── sites tab ──
    def rebuild_sites(self):
        t = self.query_one("#sites", DataTable)
        t.clear()
        sites = self.live["sites"]
        rows = sorted(sites.items(), key=lambda kv: (not site_flagged(kv[1]), kv[1]["cat"]))
        f = self._filter.lower()
        shown = 0
        for dom, d in rows:
            if self._flagged_only and not site_flagged(d):
                continue
            if f and not (f in d["cat"].lower() or f in dom.lower() or
                          any(f in (d[k]["verdict"] or "").lower() for k in ("dns", "sni", "blockpage"))):
                continue
            t.add_row(d["cat"], verdict_text(d["dns"]["verdict"]), verdict_text(d["sni"]["verdict"]),
                      verdict_text(d["blockpage"]["verdict"]), ech_text(d.get("ech")),
                      Text(str(d.get("ms", "")), style="dim"), key=dom)
            shown += 1
        pending = len(self.sites_expected) - len(sites)
        self.query_one("#sitecount", Label).update(
            f" {shown} shown · {sum(site_flagged(d) for d in sites.values())} affected"
            + (f" · {pending} pending" if pending > 0 else ""))

    def update_site(self, dom, res):
        self.live["sites"][dom] = res
        self.rebuild_sites()
        for k in ("dns", "sni", "blockpage"):
            v = res[k]["verdict"]
            if v not in core.NEUTRAL:
                note = ""
                if k == "sni" and v == "SNI-DPI" and res.get("ech"):
                    note = " (bypassable via ECH)"
                if res[k].get("injected"):
                    note += " (RST injected in-path)"
                self.log_write(f"[red]⚑ {escape(dom)}: {k}={escape(v)}[/]{note}")

    def update_site_silent(self, dom, res):
        self.live["sites"][dom] = res
        self.rebuild_sites()

    @on(DataTable.RowHighlighted, "#sites")
    def show_detail(self, ev: DataTable.RowHighlighted):
        dom = ev.row_key.value if ev.row_key else None
        d = self.live["sites"].get(dom)
        if not d:
            return
        t = Text()
        t.append(f"{dom}", style="bold")
        t.append(f"  [{d['cat']}]  {d.get('ms', '?')} ms", style="dim")
        if d.get("confirmed"):
            t.append("  confirmed on retry", style="green")
        if d.get("transient"):
            t.append("  transient (dropped)", style="yellow")
        t.append("\nDNS: ", style="dim")
        t.append_text(verdict_text(d["dns"]["verdict"]))
        t.append(f"  ref {', '.join(d['dns'].get('truth', [])[:3]) or '—'} · system {', '.join(d['dns'].get('system', [])[:3]) or '—'}"
                 f" · @8.8.8.8 {', '.join(d['dns'].get('udp53', [])[:3]) or '—'}", style="dim")
        if d["dns"].get("note"):
            t.append(f"  {d['dns']['note']}", style="yellow")
        t.append("\nTLS/SNI: ", style="dim")
        t.append_text(verdict_text(d["sni"]["verdict"]))
        s = d["sni"]
        t.append(f"  {s.get('detail', '')}"
                 + (f"  rtt {s['rtt_ms']} ms" if s.get("rtt_ms") else "")
                 + (f"  rst {s['rst_ms']} ms" if s.get("rst_ms") else ""), style="dim")
        t.append("\nblock page: ", style="dim")
        t.append_text(verdict_text(d["blockpage"]["verdict"]))
        t.append(f"  {d['blockpage'].get('detail', '')}", style="dim")
        t.append("\nECH: ", style="dim")
        t.append_text(ech_text(d.get("ech")))
        if d["sni"]["verdict"] == "SNI-DPI" and d.get("ech"):
            t.append("  → this block can be bypassed with ECH (Firefox/Chrome + DoH)", style="green")
        self.query_one("#detail", Static).update(t)

    @on(Input.Changed, "#filter")
    def filter_changed(self, ev: Input.Changed):
        self._filter = ev.value
        self.rebuild_sites()

    @on(Input.Submitted, "#filter")
    def filter_submitted(self, ev):
        self.query_one("#sites", DataTable).focus()

    # ── egress tab ──
    def update_row(self, label, status, table="#egress_tbl"):
        self._touched.add(label)
        try:
            self.query_one(table, DataTable).update_cell(label, "status", verdict_text(status))
        except Exception:
            return
        if status.startswith(("BLOCKED", "INTERCEPTED", "PROXY", "TLS-MITM", "NXDOMAIN", "URL-")):
            self.log_write(f"[red]⚑ {escape(label)}: {escape(status)}[/]")

    # ── overview ──
    def log_write(self, msg):
        self.query_one("#findings", RichLog).write(msg)

    def finish(self, report):
        self.report = report
        an = report["analysis"]
        for label in core.PORTS:
            if label not in self._touched:
                self.query_one("#ports_tbl", DataTable).update_cell(label, "status", Text("skipped", style="dim"))
        for label in EGRESS_ROWS:
            if label not in self._touched:
                self.query_one("#egress_tbl", DataTable).update_cell(label, "status", Text("skipped", style="dim"))
        self.live["sites"] = report["sites"]
        self.rebuild_sites()
        self.query_one("#analysis", Static).update(analysis_panel(report))
        self.query_one("#cats", Static).update(category_table(report))
        adv = Text()
        adv.append(t("ui.vpn_diag") + "\n", style="bold")
        for c, line in core.vpn_advice(report):
            adv.append(line + "\n", style=ADV_STYLE.get(c, "dim"))
        adv.append("\n" + t("ui.tunnel") + "\n", style="bold")
        for c, line in core.tunnel_advice(report):
            adv.append(line + "\n", style=ADV_STYLE.get(c, "dim"))
        self.query_one("#advice", Static).update(adv)
        sl = Text()
        sl.append(f" {an['score']:>3}/100 ", style=LEVEL_STYLE[an["level"]])
        sl.append(" ")
        sl.append_text(score_bar(an["score"], 30))
        sl.append(f"  {level_name(an['level'], up=True)}", style=LEVEL_STYLE[an["level"]])
        sl.append(f"  {t('ui.signals', n=len(report['flagged']))} · {t('html.confidence')} {t('conf.' + an['confidence'])}", style="dim")
        if an["vendor"]:
            sl.append(f" · {an['vendor']}", style="magenta")
        tm = report.get("timings", {})
        sl.append(f" · {tm.get('total_ms', 0) / 1000:.0f}s", style="dim")
        self.set_scoreline(sl)
        n = len(report["flagged"])
        self.log_write(f"[green]✓ scan done — {n} interference signals · score {an['score']} ({an['level']})[/]"
                       if n else f"[green]✓ scan done — no clear interference · score {an['score']}[/]")
        transient = [d for d, r in report["sites"].items() if r.get("transient")]
        if transient:
            self.log_write(f"[yellow]↺ transient, dropped: {escape(', '.join(transient))}[/]")
        self.notify(f"score {an['score']}/100 · {an['level']} · {n} signals", title="scan done",
                    severity="error" if an["level"] in ("heavy", "severe") else ("warning" if n else "information"))
        self.load_history()

    # ── history tab ──
    def load_history(self):
        from .history import blocked_of, load_runs
        t = self.query_one("#history_tbl", DataTable)
        t.clear(columns=True)
        for c in ("time", "network", "score", "blocks", "changes"):
            t.add_column(c)
        runs = load_runs()
        prev = {}
        rows = []
        for r in runs:
            key = r.get("net")
            b = blocked_of(r)
            p = prev.get(key)
            if p is None:
                ch = ""
            else:
                ch = " ".join([f"+{x}" for x in sorted(b - p)] + [f"−{x}" for x in sorted(p - b)]) or "no change"
            rows.append((r.get("ts", ""), r.get("label") or key, r.get("score"), len(b), ch))
            prev[key] = b
        for ts, net, sc, nb, ch in rows[-200:][::-1]:
            style = "red" if ch.startswith("+") else ("green" if ch.startswith("−") else "dim")
            t.add_row(ts, net, "" if sc is None else Text(str(sc), style=LEVEL_STYLE[analysis.level(sc)]),
                      str(nb), Text(ch, style=style))
        t.border_title = f"history — {len(runs)} runs"

    # ── actions ──
    def action_tab(self, name):
        self.query_one(TabbedContent).active = name

    def action_focus_filter(self):
        self.query_one(TabbedContent).active = "sites_tab"
        self.query_one("#filter", Input).focus()

    def action_toggle_flagged(self):
        self._flagged_only = not self._flagged_only
        self.rebuild_sites()
        self.notify("showing affected sites only" if self._flagged_only else "showing all sites")

    def action_rescan(self):
        self.report = None
        self.live = {"sites": {}}
        self._touched = set()
        self.sites_expected = core.select_sites(self.opts.categories, self.opts.domains)
        self.query_one("#findings", RichLog).clear()
        self.set_scoreline(Text("scanning…", style="dim"))
        self.set_progress(0, 1)
        for label in core.PORTS:
            self.query_one("#ports_tbl", DataTable).update_cell(label, "status", Text("…", style="dim"))
        for label in EGRESS_ROWS:
            self.query_one("#egress_tbl", DataTable).update_cell(label, "status", Text("…", style="dim"))
        self.rebuild_sites()
        self.log_write("[dim]scan started…[/]")
        self.run_worker(self._scan, thread=True, exclusive=True, group="scan")

    def action_toggle_tor(self):
        self.opts.tor = not self.opts.tor
        self.notify(f"Tor test {'on' if self.opts.tor else 'off'} — applies on rescan")

    def action_save(self):
        if not self.report:
            self.notify("no finished report yet", severity="warning")
            return
        stamp = time.strftime("%Y%m%d-%H%M%S")
        base = os.path.join(self.outdir, f"filterscope-{core.safe_name(self.report['net'].get('label') or self.report['net']['id'])}-{stamp}")
        scan.write_outputs(self.report, json_path=base + ".json", html_path=base + ".html", history=False)
        self.log_write(f"[green]saved {escape(base)}.json / .html[/]")
        self.notify(f"saved {os.path.basename(base)}.json / .html")

    def action_compare_prev(self):
        if not self.report:
            self.notify("no finished report yet", severity="warning")
            return
        older = config.previous_report(self.report["net"]["id"], before_ts=self.report["ts"])
        if not older:
            self.notify("no earlier stored scan of this network", severity="warning")
            return
        d = analysis.diff(older, self.report)
        self.log_write(f"[bold]vs {older['ts']}[/] score {d['score_old']} → {d['score_new']}")
        for x in d["added"]:
            self.log_write(f"  [red]+ new block: {escape(x)}[/]")
        for x in d["removed"]:
            self.log_write(f"  [green]- lifted: {escape(x)}[/]")
        if not d["added"] and not d["removed"]:
            self.log_write("  [dim]no change[/]")
        self.query_one(TabbedContent).active = "overview"

    # ── worker thread ──
    def _scan(self):
        worker = get_current_worker()
        cft = self.call_from_thread

        def emit(ev, *a):
            if worker.is_cancelled:
                return
            if ev == "net":
                cft(self.set_net, a[0])
            elif ev == "progress":
                cft(self.set_progress, a[0], a[1])
            elif ev == "site":
                cft(self.update_site, a[0], a[1])
            elif ev == "port":
                cft(self.update_row, a[0], a[1], "#ports_tbl")
            elif ev == "udp_done":
                cft(self.update_row, "UDP egress (STUN)", a[0])
            elif ev == "quic_done":
                cft(self.update_row, "QUIC/UDP-443", a[0])
            elif ev == "ipv6":
                cft(self.update_row, "IPv6", a[0]["verdict"])
            elif ev == "dns_enc":
                cft(self.update_row, a[0], a[1])
            elif ev == "dns_int":
                cft(self.update_row, "DNS-53 interception", a[0]["verdict"])
            elif ev == "nxdomain":
                cft(self.update_row, "NXDOMAIN hijack", a[0]["verdict"])
            elif ev == "http_proxy":
                cft(self.update_row, "HTTP proxy", a[0]["verdict"])
            elif ev == "url_filter":
                cft(self.update_row, "URL keyword filter", a[0]["verdict"])
            elif ev == "mitm":
                cft(self.update_row, f"TLS chain {a[0]}", a[1]["verdict"])
            elif ev == "ssh":
                cft(self.update_row, "SSH banner", a[0])
            elif ev == "throttle":
                cft(self.update_row, "throttling", a[0].get("verdict", "?"))
            elif ev == "verify_start":
                cft(self.log_write, f"[dim]re-checking {a[0]} positives…[/]")
            elif ev == "verify":
                dom, ok, res = a
                cft(self.update_site_silent, dom, res)
                if not ok:
                    cft(self.log_write, f"[yellow]↺ {escape(dom)}: not reproduced on retry — dropped[/]")
            elif ev == "tor":
                v = a[0]["verdict"]
                cft(self.update_row, "Tor bootstrap",
                    "open" if v == "ok" else ("tor-missing" if v == "tor-missing" else f"BLOCKED ({v})"))
            elif ev == "done":
                cft(self.finish, a[0])

        if "tor" in self.opts.steps and self.opts.tor:
            cft(self.update_row, "Tor bootstrap", "testing…")
        scan.run_scan(self.opts, emit, cancelled=lambda: worker.is_cancelled)


def run_tui(opts: scan.ScanOptions, outdir=None):
    FilterScope(opts, outdir).run()

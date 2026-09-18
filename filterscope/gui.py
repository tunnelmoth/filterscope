"""filterscope desktop GUI — Tkinter/ttk, no terminal needed.

Double-click friendly: one window, a Scan button, a score gauge, tabs for sites /
egress / history, and one-click HTML report. Runs the same engine as the CLI/TUI.
"""
from __future__ import annotations

import os
import queue
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
except ImportError:  # pragma: no cover
    tk = None

from . import __version__, analysis, config, core, scan, sysinfo
from .i18n import get_lang, level_name, set_lang, t
from .render import site_flagged, site_notes

LEVEL_COLOR = {"clean": "#1a7f37", "light": "#b26a00", "moderate": "#d97706",
               "heavy": "#c62828", "severe": "#8b0000"}
BG, CARD, FG, MUTED, LINE = "#f4f5f7", "#ffffff", "#1a1a1a", "#666666", "#dfe2e6"
ACCENT = "#2b5fd9"
RED_BG, YEL_BG, GREEN_FG, RED_FG, YEL_FG = "#fde8e8", "#fff4d6", "#1a7f37", "#c62828", "#b26a00"

def asset(name: str) -> str:
    base = getattr(sys, "_MEIPASS", None) or os.path.dirname(os.path.abspath(__file__))
    for p in (os.path.join(base, "filterscope", "assets", name), os.path.join(base, "assets", name)):
        if os.path.exists(p):
            return p
    return ""


def open_path(path: str):
    try:
        if sys.platform.startswith("win"):
            os.startfile(path)  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
    except Exception:
        pass


class App:
    def __init__(self, root: "tk.Tk", opts: scan.ScanOptions | None = None, autoscan: bool = False):
        self.root = root
        self.opts = opts or scan.ScanOptions.from_config(config.load())
        self.q: queue.Queue = queue.Queue()
        self.report = None
        self.live_sites: dict = {}
        self.scanning = False
        self._cancel = False
        self._filter = tk.StringVar()
        self._flagged_only = tk.BooleanVar(value=False)
        self._label = tk.StringVar(value=self.opts.label or "")
        self._profile = tk.StringVar(value="full")
        self._tor = tk.BooleanVar(value=self.opts.tor)
        self._status = tk.StringVar(value="ready")
        self._build()
        self.root.after(80, self._pump)
        self.root.after(200, self.load_history)
        self.root.after(1500, self.check_update_async)
        if autoscan:
            self.root.after(400, self.start_scan)

    # ── layout ──────────────────────────────────────────────────────────────
    def _build(self):
        r = self.root
        r.title(f"filterscope {__version__}")
        r.geometry("1080x720")
        r.minsize(900, 600)
        r.configure(bg=BG)
        ico = asset("filterscope.ico")
        png = asset("filterscope.png")
        try:
            if sys.platform.startswith("win") and ico:
                r.iconbitmap(ico)
            elif png:
                self._icon_img = tk.PhotoImage(file=png)
                r.iconphoto(True, self._icon_img)
        except Exception:
            pass
        st = ttk.Style()
        for theme in ("vista", "aqua", "clam"):
            if theme in st.theme_names():
                st.theme_use(theme)
                break
        base_font = ("Segoe UI", 10) if sys.platform.startswith("win") else ("TkDefaultFont", 10)
        st.configure(".", background=BG, foreground=FG, font=base_font)
        st.configure("Card.TFrame", background=CARD)
        st.configure("Card.TLabel", background=CARD)
        st.configure("Muted.TLabel", foreground=MUTED, background=CARD)
        st.configure("H.TLabel", font=(base_font[0], 15, "bold"), background=CARD)
        st.configure("Big.TLabel", font=(base_font[0], 26, "bold"), background=CARD)
        st.configure("Accent.TButton", font=(base_font[0], 10, "bold"))
        st.configure("Treeview", rowheight=24, background=CARD, fieldbackground=CARD)
        st.configure("Treeview.Heading", font=(base_font[0], 10, "bold"))
        st.map("Treeview", background=[("selected", "#dbe4ff")], foreground=[("selected", FG)])

        # toolbar
        tb = ttk.Frame(r, padding=(12, 10, 12, 4))
        tb.pack(fill="x")
        self.btn_scan = ttk.Button(tb, text="▶  " + t("ui.scan"), style="Accent.TButton", command=self.start_scan)
        self.btn_scan.pack(side="left")
        self.btn_stop = ttk.Button(tb, text=t("ui.stop"), command=self.stop_scan, state="disabled")
        self.btn_stop.pack(side="left", padx=(6, 14))
        ttk.Label(tb, text=t("ui.label")).pack(side="left")
        ttk.Entry(tb, textvariable=self._label, width=14).pack(side="left", padx=(4, 12))
        ttk.Label(tb, text=t("ui.profile")).pack(side="left")
        cb = ttk.Combobox(tb, textvariable=self._profile, values=sorted(config.PROFILES), width=8, state="readonly")
        cb.pack(side="left", padx=(4, 12))
        ttk.Checkbutton(tb, text=t("ui.tor"), variable=self._tor).pack(side="left", padx=(0, 8))
        ttk.Button(tb, text=t("ui.sites"), command=self.sites_dialog).pack(side="left", padx=(0, 6))
        lang_btn = ttk.Button(tb, text="TR" if get_lang() == "en" else "EN", width=3, command=self.toggle_lang)
        lang_btn.pack(side="left", padx=(0, 12))
        ttk.Button(tb, text=t("ui.folder"), width=7, command=lambda: open_path(config.DIR if os.path.isdir(config.DIR) else os.getcwd())).pack(side="right")
        ttk.Button(tb, text=t("ui.compare"), width=10, command=self.compare_prev).pack(side="right", padx=4)
        mb = ttk.Menubutton(tb, text=t("ui.save") + " ▾", width=10)
        menu = tk.Menu(mb, tearoff=False)
        menu.add_command(label=t("ui.html"), command=self.save_html)
        menu.add_command(label=t("ui.json"), command=self.save_json)
        menu.add_command(label=t("ui.card"), command=self.save_card)
        mb["menu"] = menu
        mb.pack(side="right", padx=4)
        self.btn_view = ttk.Button(tb, text=t("ui.report"), width=13, style="Accent.TButton",
                                   command=self.view_report, state="disabled")
        self.btn_view.pack(side="right", padx=(12, 4))

        pb = ttk.Frame(r, padding=(12, 0, 12, 6))
        pb.pack(fill="x")
        self.progress = ttk.Progressbar(pb, mode="determinate", maximum=100)
        self.progress.pack(fill="x", side="left", expand=True)
        ttk.Label(pb, textvariable=self._status, foreground=MUTED, width=42, anchor="e").pack(side="right", padx=(10, 0))
        self.update_lbl = tk.Label(r, text="", fg="#ffffff", bg=ACCENT, cursor="hand2", font=("TkDefaultFont", 10, "bold"))
        self.update_lbl.bind("<Button-1>", lambda e: webbrowser.open(getattr(self, "_update_url", core.RELEASES_URL)))

        # header card: gauge + summary
        hc = ttk.Frame(r, style="Card.TFrame", padding=12)
        hc.pack(fill="x", padx=12, pady=(0, 8))
        self.gauge = tk.Canvas(hc, width=130, height=120, bg=CARD, highlightthickness=0)
        self.gauge.pack(side="left")
        right = ttk.Frame(hc, style="Card.TFrame")
        right.pack(side="left", fill="both", expand=True, padx=(14, 0))
        self.net_lbl = ttk.Label(right, text=t("ui.network") + ": —", style="Muted.TLabel")
        self.net_lbl.pack(anchor="w")
        self.level_lbl = ttk.Label(right, text=t("ui.press_scan"), style="H.TLabel")
        self.level_lbl.pack(anchor="w", pady=(2, 2))
        self.summary_lbl = ttk.Label(right, text=t("ui.intro"), style="Card.TLabel", wraplength=800, justify="left")
        self.summary_lbl.pack(anchor="w")
        self.tech_lbl = ttk.Label(right, text="", style="Card.TLabel", foreground=RED_FG, wraplength=800, justify="left")
        self.tech_lbl.pack(anchor="w", pady=(4, 0))
        self.draw_gauge(0, "clean", blank=True)

        # tabs
        self.nb = ttk.Notebook(r)
        self.nb.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self._build_overview()
        self._build_sites()
        self._build_egress()
        self._build_history()
        self._build_about()
        r.bind("<F5>", lambda e: self.start_scan())
        r.bind("<Control-s>", lambda e: self.save_html())

    def _build_overview(self):
        f = ttk.Frame(self.nb, padding=8)
        self.nb.add(f, text=t("ui.tab.overview"))
        left = ttk.Labelframe(f, text=t("ui.findings"), padding=6)
        left.pack(side="left", fill="both", expand=True, padx=(0, 6))
        self.findings = tk.Listbox(left, bg=CARD, fg=FG, highlightthickness=0, borderwidth=0,
                                   selectbackground="#dbe4ff", selectforeground=FG, activestyle="none")
        self.findings.pack(fill="both", expand=True)
        right = ttk.Labelframe(f, text=t("ui.advice"), padding=6)
        right.pack(side="left", fill="both", expand=True)
        self.advice = tk.Text(right, bg=CARD, fg=FG, wrap="word", borderwidth=0, highlightthickness=0,
                              padx=6, pady=4, state="disabled", font="TkDefaultFont")
        self.advice.pack(fill="both", expand=True)
        for tag, col in (("g", GREEN_FG), ("r", RED_FG), ("y", YEL_FG), ("d", MUTED)):
            self.advice.tag_configure(tag, foreground=col)
        self.advice.tag_configure("h", font=("TkDefaultFont", 10, "bold"))

    def _build_sites(self):
        f = ttk.Frame(self.nb, padding=8)
        self.nb.add(f, text=t("ui.tab.sites"))
        bar = ttk.Frame(f)
        bar.pack(fill="x", pady=(0, 6))
        ttk.Label(bar, text=t("ui.filter")).pack(side="left")
        e = ttk.Entry(bar, textvariable=self._filter, width=30)
        e.pack(side="left", padx=(4, 12))
        e.bind("<KeyRelease>", lambda ev: self.rebuild_sites())
        ttk.Checkbutton(bar, text=t("ui.affected_only"), variable=self._flagged_only, command=self.rebuild_sites).pack(side="left")
        self.site_count = ttk.Label(bar, text="", foreground=MUTED)
        self.site_count.pack(side="right")
        self.detail = tk.Text(f, height=5, bg=CARD, fg=FG, wrap="word", borderwidth=1, relief="solid",
                              highlightthickness=0, padx=6, pady=4, state="disabled", font="TkDefaultFont")
        self.detail.pack(side="bottom", fill="x", pady=(6, 0))
        for tag, kw in (("b", {"font": ("TkDefaultFont", 10, "bold")}), ("d", {"foreground": MUTED}),
                        ("g", {"foreground": GREEN_FG}), ("r", {"foreground": RED_FG})):
            self.detail.tag_configure(tag, **kw)
        tf = ttk.Frame(f)
        tf.pack(fill="both", expand=True)
        cols = ("category", "domain", "dns", "sni", "block", "ech", "ms")
        self.sites = ttk.Treeview(tf, columns=cols, show="headings", selectmode="browse")
        widths = {"category": 170, "domain": 200, "dns": 130, "sni": 110, "block": 110, "ech": 50, "ms": 60}
        for c in cols:
            self.sites.heading(c, text={"dns": "DNS", "sni": "TLS/SNI", "ech": "ECH"}.get(c, c))
            self.sites.column(c, width=widths[c], anchor="w", stretch=(c in ("category", "domain")))
        self.sites.tag_configure("bad", background=RED_BG)
        self.sites.tag_configure("warn", background=YEL_BG)
        sb = ttk.Scrollbar(tf, orient="vertical", command=self.sites.yview)
        self.sites.configure(yscrollcommand=sb.set)
        self.sites.pack(side="left", fill="both", expand=True)
        sb.pack(side="left", fill="y")
        self.sites.bind("<<TreeviewSelect>>", self.show_detail)

    def _build_egress(self):
        f = ttk.Frame(self.nb, padding=8)
        self.nb.add(f, text=t("ui.tab.egress"))
        cols = ("probe", "status", "detail")
        self.egress = ttk.Treeview(f, columns=cols, show="headings")
        for c, w in zip(cols, (240, 160, 600)):
            self.egress.heading(c, text=c)
            self.egress.column(c, width=w, anchor="w", stretch=(c == "detail"))
        self.egress.tag_configure("bad", background=RED_BG)
        self.egress.tag_configure("warn", background=YEL_BG)
        self.egress.tag_configure("ok", foreground=GREEN_FG)
        sb = ttk.Scrollbar(f, orient="vertical", command=self.egress.yview)
        self.egress.configure(yscrollcommand=sb.set)
        self.egress.pack(side="left", fill="both", expand=True)
        sb.pack(side="left", fill="y")

    def _build_history(self):
        f = ttk.Frame(self.nb, padding=8)
        self.nb.add(f, text=t("ui.tab.history"))
        cols = ("time", "network", "score", "blocks", "changes")
        self.hist = ttk.Treeview(f, columns=cols, show="headings")
        for c, w in zip(cols, (150, 140, 60, 60, 600)):
            self.hist.heading(c, text=c)
            self.hist.column(c, width=w, anchor="w", stretch=(c == "changes"))
        self.hist.tag_configure("bad", foreground=RED_FG)
        self.hist.tag_configure("good", foreground=GREEN_FG)
        sb = ttk.Scrollbar(f, orient="vertical", command=self.hist.yview)
        self.hist.configure(yscrollcommand=sb.set)
        self.hist.pack(side="left", fill="both", expand=True)
        sb.pack(side="left", fill="y")
        bb = ttk.Frame(f)
        bb.pack(side="bottom", fill="x", pady=(6, 0))
        ttk.Button(bb, text=t("ui.export_timeline"), command=self.export_history).pack(side="left")

    def _build_about(self):
        f = ttk.Frame(self.nb, padding=16)
        self.nb.add(f, text=t("ui.tab.about"))
        txt = (f"filterscope {__version__} — GPL-3.0 — github.com/tunnelmoth/filterscope\n\n"
               "Measures filtering / censorship on the network you are connected to, legitimately: "
               "only your own traffic, only a clean allowlist of well-known sites.\n\n"
               "Verdicts\n"
               "  SNI-DPI            the TLS server name is inspected; the site is reset only with its real name\n"
               "  TLS-MITM           HTTPS is decrypted by the network with its own certificate authority\n"
               "  HIJACK-blockpage   DNS answers with a private IP (block-page server)\n"
               "  DNS-BLOCK          the resolver withholds the answer while DoH resolves\n"
               "  INTERCEPTED        port-53 DNS is transparently proxied; 'use 8.8.8.8' is ignored\n"
               "  BLOCKED            packets to that port / protocol are dropped\n"
               "  ?                  undecided (no reference, or a positive that did not reproduce)\n\n"
               "Score: share of affected sites (max 50) + a weight per technique + 2 per blocked port.\n"
               "  0 clean · 1-19 light · 20-44 moderate · 45-69 heavy · 70+ severe\n\n"
               "Verification: every positive site result is re-tested once; non-reproducible ones are dropped.\n\n"
               "Evidence: scan here, scan again on mobile data, then compare the two saved JSON files "
               "(filterscope compare A.json B.json) — anything blocked only here is filtering specific to this network.\n\n"
               f"Data folder: {config.DIR}\n"
               "The Tor test needs a tor / tor.exe binary (Tor Expert Bundle) on PATH or next to this program.")
        w = tk.Text(f, bg=BG, fg=FG, wrap="word", borderwidth=0, highlightthickness=0, font="TkDefaultFont")
        w.insert("1.0", txt)
        w.configure(state="disabled")
        w.pack(fill="both", expand=True)

    # ── gauge ────────────────────────────────────────────────────────────────
    def draw_gauge(self, score: int, level: str, blank=False):
        c = self.gauge
        c.delete("all")
        x0, y0, x1, y1 = 10, 8, 120, 118
        c.create_arc(x0, y0, x1, y1, start=225, extent=-270, style="arc", width=12, outline=LINE)
        if not blank and score > 0:
            c.create_arc(x0, y0, x1, y1, start=225, extent=-270 * score / 100, style="arc", width=12,
                         outline=LEVEL_COLOR[level])
        c.create_text(65, 60, text="—" if blank else str(score), font=("TkDefaultFont", 24, "bold"),
                      fill=MUTED if blank else LEVEL_COLOR[level])
        c.create_text(65, 84, text="" if blank else level.upper(), font=("TkDefaultFont", 9, "bold"),
                      fill=MUTED if blank else LEVEL_COLOR[level])

    # ── sites dialog: categories + custom domains (saved to ~/.filterscope/config.json) ──
    def sites_dialog(self):
        cfg = config.load()
        win = tk.Toplevel(self.root)
        win.title("Sites to test")
        win.transient(self.root)
        win.geometry("760x520")
        win.configure(bg=BG)
        left = ttk.Labelframe(win, text="categories (none checked = all)", padding=8)
        left.pack(side="left", fill="both", expand=True, padx=(12, 6), pady=12)
        cats = core.categories()
        counts = {c: sum(1 for k in core.SITES if k.split("/")[0] == c) for c in cats}
        chosen = set(cfg.get("categories") or [])
        vars_ = {}
        grid = ttk.Frame(left)
        grid.pack(fill="both", expand=True)
        for i, c in enumerate(cats):
            v = tk.BooleanVar(value=(c in chosen))
            vars_[c] = v
            ttk.Checkbutton(grid, text=f"{c} ({counts[c]})", variable=v).grid(row=i % 14, column=i // 14, sticky="w", padx=4, pady=1)
        bb = ttk.Frame(left)
        bb.pack(fill="x", pady=(8, 0))
        ttk.Button(bb, text="all", command=lambda: [v.set(False) for v in vars_.values()]).pack(side="left")
        ttk.Button(bb, text="school preset", command=lambda: [v.set(c in config.PROFILES["school"]["categories"]) for c, v in vars_.items()]).pack(side="left", padx=6)
        ttk.Label(bb, text=f"{len(core.SITES)} sites total", foreground=MUTED).pack(side="right")
        right = ttk.Labelframe(win, text="your own domains (one per line, e.g. example.org)", padding=8)
        right.pack(side="left", fill="both", expand=True, padx=(6, 12), pady=12)
        txt = tk.Text(right, bg=CARD, fg=FG, height=18, font="TkFixedFont", highlightthickness=0, borderwidth=1, relief="solid")
        txt.pack(fill="both", expand=True)
        txt.insert("1.0", "\n".join(cfg.get("domains") or []))
        ttk.Label(right, text="Added under category 'custom'. Only test domains you have a reason to test.",
                  foreground=MUTED, wraplength=320, justify="left").pack(anchor="w", pady=(6, 0))
        btns = ttk.Frame(right)
        btns.pack(fill="x", pady=(8, 0))

        def save():
            import re as _re
            doms = []
            for line in txt.get("1.0", "end").splitlines():
                d = line.strip().lower().strip(".")
                d = _re.sub(r"^https?://", "", d).split("/")[0]
                if d and _re.match(r"^([a-z0-9-]+\.)+[a-z]{2,}$", d) and d not in doms:
                    doms.append(d)
            cfg2 = config.load()
            cfg2["categories"] = [c for c, v in vars_.items() if v.get()]
            cfg2["domains"] = doms
            config.save(cfg2)
            n = len(core.select_sites(cfg2["categories"], doms))
            self._status.set(f"sites saved: {n} to test ({len(doms)} custom)")
            win.destroy()
        ttk.Button(btns, text="Save", style="Accent.TButton", command=save).pack(side="right")
        ttk.Button(btns, text="Cancel", command=win.destroy).pack(side="right", padx=6)

    # ── scanning ─────────────────────────────────────────────────────────────
    def build_opts(self) -> scan.ScanOptions:
        cfg = config.load()
        o = scan.ScanOptions.from_config(cfg, self._profile.get(), label=self._label.get().strip() or None)
        o.tor = self._tor.get() and "tor" in o.steps
        return o

    def start_scan(self):
        if self.scanning:
            return
        self.opts = self.build_opts()
        self.scanning, self._cancel = True, False
        self.report = None
        self.live_sites = {}
        self.btn_scan.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.btn_view.configure(state="disabled")
        self.findings.delete(0, "end")
        self.egress.delete(*self.egress.get_children())
        self.sites.delete(*self.sites.get_children())
        self._set_text(self.advice, [])
        self.level_lbl.configure(text=t("ui.scanning"), foreground=FG)
        self.summary_lbl.configure(text="")
        self.tech_lbl.configure(text="")
        self.draw_gauge(0, "clean", blank=True)
        self.progress.configure(value=0)
        self._status.set(t("ui.scanning"))
        self.sites_expected = core.select_sites(self.opts.categories, self.opts.domains)
        threading.Thread(target=self._worker, daemon=True).start()

    def stop_scan(self):
        self._cancel = True
        self._status.set("stopping…")

    def _worker(self):
        try:
            scan.run_scan(self.opts, lambda ev, *a: self.q.put((ev, a)), cancelled=lambda: self._cancel)
        except Exception as e:  # pragma: no cover
            self.q.put(("error", (f"{type(e).__name__}: {e}",)))
        finally:
            self.q.put(("finished", ()))

    def _pump(self):
        try:
            while True:
                ev, a = self.q.get_nowait()
                self._handle(ev, a)
        except queue.Empty:
            pass
        self.root.after(80, self._pump)

    def _handle(self, ev, a):
        if ev == "net":
            fp = a[0]
            self.net_lbl.configure(text=f"{t('ui.network')}: {sysinfo.net_name(fp)}   [id {fp['id']}]   gw {fp.get('gateway') or '?'}   "
                                        f"resolver {fp.get('resolver') or '?'}   {fp.get('os', '')}")
        elif ev == "progress":
            done, total = a
            self.progress.configure(maximum=max(total, 1), value=done)
            self._status.set(t("ui.probing", done=done, total=total))
        elif ev == "site":
            dom, res = a
            self.live_sites[dom] = res
            self.rebuild_sites()
            for k in ("dns", "sni", "blockpage"):
                v = res[k]["verdict"]
                if v not in core.NEUTRAL:
                    self._finding(f"{dom}: {k}={v}" + ("  (bypassable via ECH)" if k == "sni" and v == "SNI-DPI" and res.get("ech") else ""))
        elif ev == "verify":
            dom, ok, res = a
            self.live_sites[dom] = res
            self.rebuild_sites()
            if not ok:
                self._finding(f"↺ {dom}: not reproduced on retry — dropped", warn=True)
        elif ev == "verify_start":
            self._status.set(t("ui.recheck", n=a[0]))
        elif ev == "port":
            self._egress_row(a[0], a[1], "")
        elif ev in ("udp", "quic"):
            self._egress_row(f"{'UDP STUN' if ev == 'udp' else 'QUIC'} {a[0]}", a[1], "")
        elif ev == "dns_enc":
            self._egress_row(a[0], a[1], "")
        elif ev in ("ipv6", "dns_int", "http_proxy", "nxdomain", "url_filter", "tor"):
            label = {"ipv6": "IPv6 egress", "dns_int": "port-53 interception", "http_proxy": "transparent HTTP proxy",
                     "nxdomain": "NXDOMAIN hijack", "url_filter": "URL keyword filter", "tor": "Tor bootstrap"}[ev]
            self._egress_row(label, a[0]["verdict"], a[0].get("detail", ""))
        elif ev == "mitm":
            self._egress_row(f"TLS chain {a[0]}", a[1]["verdict"], a[1].get("detail") or f"issuer {a[1].get('issuer', '?')}")
        elif ev == "throttle":
            th = a[0]
            for k, v in th.get("targets", {}).items():
                self._egress_row(f"{t('ui.throttle')} {k}", f"{v.get('mbps', 0)} Mbit/s" if not v.get("error") else f"error ({v['error']})", "")
            self._egress_row("throttling", th["verdict"], th.get("detail", ""))
        elif ev == "ssh":
            self._egress_row("SSH egress (22)", a[0], a[1])
        elif ev == "speed":
            self._egress_row("downstream", f"{a[0].get('mbps', 0)} Mbit/s", a[0].get("detail", ""))
        elif ev == "done":
            self.finish(a[0])
        elif ev == "error":
            messagebox.showerror("filterscope", f"scan failed:\n{a[0]}")
        elif ev == "finished":
            self.scanning = False
            self.btn_scan.configure(state="normal")
            self.btn_stop.configure(state="disabled")
            if self.report is None:
                self._status.set(t("ui.stopped"))
                self.level_lbl.configure(text=t("ui.stopped"))

    def _finding(self, text, warn=False):
        self.findings.insert("end", ("  " if warn else "⚑ ") + text)
        self.findings.itemconfigure("end", foreground=YEL_FG if warn else RED_FG)

    def _egress_row(self, label, status, detail):
        tag = "ok" if (status in ("ok", "open") or str(status).startswith(("open", "passed")) or str(status).endswith("Mbit/s")) else (
            "warn" if status in ("?", "unavailable", "refused", "tor-missing", "skipped") or str(status).startswith(("error", "tls-error", "bad-reply")) else "bad")
        for iid in self.egress.get_children():
            if self.egress.set(iid, "probe") == label:
                self.egress.item(iid, values=(label, status, detail), tags=(tag,))
                break
        else:
            self.egress.insert("", "end", values=(label, status, detail), tags=(tag,))
        if tag == "bad":
            self._finding(f"{label}: {status}")

    def rebuild_sites(self):
        self.sites.delete(*self.sites.get_children())
        f = self._filter.get().lower()
        rows = sorted(self.live_sites.items(), key=lambda kv: (not site_flagged(kv[1]), kv[1]["cat"]))
        shown = 0
        for dom, d in rows:
            if self._flagged_only.get() and not site_flagged(d):
                continue
            if f and not (f in d["cat"].lower() or f in dom.lower() or
                          any(f in (d[k]["verdict"] or "").lower() for k in ("dns", "sni", "blockpage"))):
                continue
            tag = "bad" if site_flagged(d) else ("warn" if d.get("transient") else "")
            self.sites.insert("", "end", iid=dom, values=(
                d["cat"], dom, d["dns"]["verdict"], d["sni"]["verdict"], d["blockpage"]["verdict"],
                {True: "yes", False: "no"}.get(d.get("ech"), "?"), d.get("ms", "")), tags=(tag,))
            shown += 1
        pending = len(getattr(self, "sites_expected", {})) - len(self.live_sites)
        self.site_count.configure(text=f"{shown} shown · {sum(site_flagged(d) for d in self.live_sites.values())} affected"
                                       + (f" · {pending} pending" if pending > 0 else ""))

    def show_detail(self, _ev=None):
        sel = self.sites.selection()
        if not sel:
            return
        d = self.live_sites.get(sel[0])
        if not d:
            return
        dom = sel[0]
        parts = [(f"{dom}", "b"), (f"   [{d['cat']}]   {d.get('ms', '?')} ms", "d")]
        if d.get("confirmed"):
            parts.append(("   confirmed on retry", "g"))
        if d.get("transient"):
            parts.append(("   transient (dropped)", "r"))
        parts.append((f"\nDNS: {d['dns']['verdict']}   ref {', '.join(d['dns'].get('truth', [])[:3]) or '—'} · "
                      f"system {', '.join(d['dns'].get('system', [])[:3]) or '—'} · @8.8.8.8 {', '.join(d['dns'].get('udp53', [])[:3]) or '—'}"
                      + (f"   {d['dns']['note']}" if d['dns'].get('note') else ""), ""))
        s = d["sni"]
        parts.append((f"\nTLS/SNI: {s['verdict']}   {s.get('detail', '')}"
                      + (f"   rtt {s['rtt_ms']} ms" if s.get('rtt_ms') else "") + (f"   rst {s['rst_ms']} ms" if s.get('rst_ms') else ""), ""))
        parts.append((f"\nblock page: {d['blockpage']['verdict']}   {d['blockpage'].get('detail', '')}", ""))
        ech = {True: "yes", False: "no"}.get(d.get("ech"), "?")
        parts.append((f"\nECH: {ech}", ""))
        if s["verdict"] == "SNI-DPI" and d.get("ech"):
            parts.append(("   → this block can be bypassed with ECH (Firefox/Chrome + DoH)", "g"))
        self._set_text(self.detail, parts)

    def _set_text(self, widget, parts):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        for text, tag in parts:
            widget.insert("end", text, tag or ())
        widget.configure(state="disabled")

    def finish(self, report):
        self.report = report
        an = report["analysis"]
        self.live_sites = report["sites"]
        self.rebuild_sites()
        self.draw_gauge(an["score"], an["level"])
        self.level_lbl.configure(text=t("ui.verdict", level=level_name(an["level"], up=True), score=an["score"],
                                        n=len(report["flagged"]), conf=t("conf." + an["confidence"])),
                                 foreground=LEVEL_COLOR[an["level"]])
        self.summary_lbl.configure(text=an["summary"])
        tech = "  ·  ".join(f"{t} ({an['technique_labels'][t]})" for t in an["techniques"])
        if an["vendor"]:
            tech += "\n" + t("ui.vendor", vendor=an["vendor"])
        self.tech_lbl.configure(text=tech)
        parts = [(t("ui.vpn_diag") + "\n", "h")]
        parts += [(line + "\n", c) for c, line in core.vpn_advice(report)]
        parts.append(("\n" + t("ui.tunnel") + "\n", "h"))
        parts += [(line + "\n", c) for c, line in core.tunnel_advice(report)]
        self._set_text(self.advice, parts)
        tm = report.get("timings", {})
        self.progress.configure(value=self.progress.cget("maximum"))
        self._status.set(t("ui.done", s=f"{tm.get('total_ms', 0) / 1000:.0f}", n=len(report["flagged"])))
        self.findings.insert("end", f"✓ scan done — score {an['score']} ({an['level']})")
        self.findings.itemconfigure("end", foreground=GREEN_FG)
        try:
            scan.write_outputs(report, history=True)
        except Exception:
            pass
        self.btn_view.configure(state="normal")
        self.load_history()
        self.root.bell()

    # ── history ──────────────────────────────────────────────────────────────
    def load_history(self):
        from .history import blocked_of, load_runs
        self.hist.delete(*self.hist.get_children())
        runs = load_runs()
        prev, rows = {}, []
        for r in runs:
            key = r.get("net")
            b = blocked_of(r)
            p = prev.get(key)
            ch = "" if p is None else (" ".join([f"+{x}" for x in sorted(b - p)] + [f"−{x}" for x in sorted(p - b)]) or "no change")
            rows.append((r.get("ts", ""), r.get("label") or key, "" if r.get("score") is None else r["score"], len(b), ch))
            prev[key] = b
        for row in rows[-300:][::-1]:
            tag = "bad" if row[4].startswith("+") else ("good" if row[4].startswith("−") else "")
            self.hist.insert("", "end", values=row, tags=(tag,))

    # ── actions ──────────────────────────────────────────────────────────────
    def _need_report(self):
        if not self.report:
            messagebox.showinfo("filterscope", t("ui.no_report"))
            return False
        return True

    def _default_name(self, ext):
        return f"filterscope-{core.safe_name(self.report['net'].get('label') or self.report['net']['id'])}-{time.strftime('%Y%m%d-%H%M%S')}.{ext}"

    def save_html(self):
        if not self._need_report():
            return
        p = filedialog.asksaveasfilename(defaultextension=".html", initialfile=self._default_name("html"),
                                         filetypes=[("HTML report", "*.html")])
        if p:
            scan.write_outputs(self.report, html_path=p, history=False)
            self._status.set(f"saved {os.path.basename(p)}")

    def save_card(self):
        if not self._need_report():
            return
        p = filedialog.asksaveasfilename(defaultextension=".png", initialfile=self._default_name("png"),
                                         filetypes=[("PNG image", "*.png")])
        if p:
            from .card import render_card
            render_card(self.report, p, show_network=messagebox.askyesno("filterscope", "Include the network name on the card?"))
            self._status.set(t("ui.saved", name=os.path.basename(p)))
            open_path(p)

    def toggle_lang(self):
        cfg = config.load()
        cfg["lang"] = "tr" if get_lang() == "en" else "en"
        config.save(cfg)
        set_lang(cfg["lang"])
        messagebox.showinfo("filterscope", {"tr": "Dil Türkçe olarak kaydedildi — yeniden başlatınca uygulanır.",
                                            "en": "Language saved as English — restart to apply."}[cfg["lang"]])

    def check_update_async(self):
        if not config.load().get("update_check", True):
            return
        def worker():
            u = core.check_update()
            if u and u.get("newer"):
                self._update_url = u["url"]
                self.root.after(0, lambda: self.update_lbl.configure(text="  " + t("ui.update", latest=u["latest"]) + "  ") or
                                self.update_lbl.pack(fill="x", padx=12, pady=(0, 6), after=self.root.winfo_children()[1]))
        threading.Thread(target=worker, daemon=True).start()

    def save_json(self):
        if not self._need_report():
            return
        p = filedialog.asksaveasfilename(defaultextension=".json", initialfile=self._default_name("json"),
                                         filetypes=[("JSON report", "*.json")])
        if p:
            scan.write_outputs(self.report, json_path=p, history=False)
            self._status.set(f"saved {os.path.basename(p)}")

    def view_report(self):
        if not self._need_report():
            return
        from .htmlreport import render_html
        d = os.path.join(tempfile.gettempdir(), "filterscope")
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, self._default_name("html"))
        with open(p, "w", encoding="utf-8") as f:
            f.write(render_html(self.report))
        webbrowser.open("file://" + p.replace("\\", "/"))

    def export_history(self):
        from .history import load_runs
        from .htmlreport import render_history_html
        runs = load_runs()
        if not runs:
            messagebox.showinfo("filterscope", "No history yet.")
            return
        p = filedialog.asksaveasfilename(defaultextension=".html", initialfile="filterscope-timeline.html",
                                         filetypes=[("HTML", "*.html")])
        if p:
            with open(p, "w", encoding="utf-8") as f:
                f.write(render_history_html(runs))
            webbrowser.open("file://" + p.replace("\\", "/"))

    def compare_prev(self):
        if not self._need_report():
            return
        older = config.previous_report(self.report["net"]["id"], before_ts=self.report["ts"])
        if not older:
            messagebox.showinfo("filterscope", "No earlier stored scan of this network.")
            return
        d = analysis.diff(older, self.report)
        self.findings.insert("end", f"vs {older['ts']}: score {d['score_old']} → {d['score_new']}")
        self.findings.itemconfigure("end", foreground=FG)
        for x in d["added"]:
            self.findings.insert("end", f"  + new block: {x}")
            self.findings.itemconfigure("end", foreground=RED_FG)
        for x in d["removed"]:
            self.findings.insert("end", f"  − lifted: {x}")
            self.findings.itemconfigure("end", foreground=GREEN_FG)
        if not d["added"] and not d["removed"]:
            self.findings.insert("end", "  no change")
            self.findings.itemconfigure("end", foreground=MUTED)
        self.nb.select(0)
        self.findings.see("end")


def main(argv=None):
    if tk is None:
        sys.exit("tkinter is not available in this Python build")
    argv = sys.argv[1:] if argv is None else list(argv)
    if "--lang" in argv:
        set_lang(argv[argv.index("--lang") + 1])
    root = tk.Tk()
    App(root, autoscan=("--autoscan" in argv or "--scan" in argv))
    root.mainloop()


if __name__ == "__main__":
    main()

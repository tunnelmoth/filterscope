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
PALETTES = {
    "light": dict(BG="#f4f5f7", CARD="#ffffff", FG="#1a1a1a", MUTED="#666666", LINE="#dfe2e6", ACCENT="#2b5fd9",
                  RED_BG="#fde8e8", YEL_BG="#fff4d6", GREEN_FG="#1a7f37", RED_FG="#c62828", YEL_FG="#b26a00", SEL="#dbe4ff", CYAN="#1e6fb3"),
    "dark": dict(BG="#17232f", CARD="#1f2c3b", FG="#eef2f7", MUTED="#a3adbd", LINE="#2d3c4e", ACCENT="#8b5cf6",
                 RED_BG="#3a1f24", YEL_BG="#3a3018", GREEN_FG="#3ddc84", RED_FG="#ff6b6b", YEL_FG="#ffb74d", SEL="#2d3c5e", CYAN="#8ab4f8"),
    "light-hc": dict(BG="#ffffff", CARD="#ffffff", FG="#000000", MUTED="#222222", LINE="#000000", ACCENT="#0000cc",
                     RED_BG="#ffd6d6", YEL_BG="#fff0b3", GREEN_FG="#006400", RED_FG="#b00000", YEL_FG="#7a4a00", SEL="#ffff00", CYAN="#00457c"),
    "dark-hc": dict(BG="#000000", CARD="#000000", FG="#ffffff", MUTED="#e6e6e6", LINE="#ffffff", ACCENT="#ffff00",
                    RED_BG="#5a0000", YEL_BG="#4a3a00", GREEN_FG="#00ff66", RED_FG="#ff5252", YEL_FG="#ffd54f", SEL="#0044aa", CYAN="#66ccff"),
}


def resolve_palette(cfg=None):
    cfg = cfg or config.load()
    theme = cfg.get("theme", "system")
    dark = sysinfo.system_dark() if theme == "system" else theme == "dark"
    key = ("dark" if dark else "light") + ("-hc" if cfg.get("high_contrast") else "")
    return key, PALETTES[key]


_PK, _P = resolve_palette()
BG, CARD, FG, MUTED, LINE, ACCENT = _P["BG"], _P["CARD"], _P["FG"], _P["MUTED"], _P["LINE"], _P["ACCENT"]
RED_BG, YEL_BG, GREEN_FG, RED_FG, YEL_FG = _P["RED_BG"], _P["YEL_BG"], _P["GREEN_FG"], _P["RED_FG"], _P["YEL_FG"]
SEL, CYAN = _P["SEL"], _P["CYAN"]
FONT_SCALE = max(75, min(200, int(config.load().get("font_scale", 100) or 100))) / 100.0

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
        themes = ("clam",) if _PK != "light" else ("vista", "aqua", "clam")
        for theme in themes:
            if theme in st.theme_names():
                st.theme_use(theme)
                break
        fs = int(round(10 * FONT_SCALE))
        base_font = ("Segoe UI", fs) if sys.platform.startswith("win") else ("TkDefaultFont", fs)
        try:
            import tkinter.font as tkfont
            for fn in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont", "TkFixedFont"):
                f = tkfont.nametofont(fn)
                f.configure(size=int(round(abs(f.cget("size")) * FONT_SCALE)) * (-1 if f.cget("size") < 0 else 1))
        except Exception:
            pass
        st.configure(".", background=BG, foreground=FG, font=base_font, fieldbackground=CARD, bordercolor=LINE,
                     lightcolor=LINE, darkcolor=LINE, troughcolor=LINE, insertcolor=FG)
        st.configure("TButton", background=CARD, foreground=FG)
        st.map("TButton", background=[("active", SEL)])
        st.configure("Accent.TButton", background=ACCENT, foreground="#ffffff" if _PK != "dark-hc" else "#000000")
        st.map("Accent.TButton", background=[("active", ACCENT)])
        st.configure("TEntry", fieldbackground=CARD, foreground=FG)
        st.configure("TCombobox", fieldbackground=CARD, foreground=FG, background=CARD, arrowcolor=FG)
        st.map("TCombobox", fieldbackground=[("readonly", CARD)], foreground=[("readonly", FG)], selectbackground=[("readonly", CARD)], selectforeground=[("readonly", FG)])
        st.configure("TCheckbutton", background=BG, foreground=FG)
        st.configure("TNotebook", background=BG)
        st.configure("TNotebook.Tab", background=CARD, foreground=FG, padding=(10, 4))
        st.map("TNotebook.Tab", background=[("selected", BG)], foreground=[("selected", FG)])
        st.configure("TLabelframe", background=BG, foreground=FG)
        st.configure("TLabelframe.Label", background=BG, foreground=FG)
        st.configure("TMenubutton", background=CARD, foreground=FG)
        st.configure("Horizontal.TProgressbar", background=ACCENT, troughcolor=LINE)
        st.configure("TScrollbar", background=CARD, troughcolor=BG, arrowcolor=FG)
        r.option_add("*Menu.background", CARD); r.option_add("*Menu.foreground", FG)
        r.option_add("*Menu.activeBackground", SEL); r.option_add("*Menu.activeForeground", FG)
        r.option_add("*Listbox.background", CARD); r.option_add("*Listbox.foreground", FG)
        r.option_add("*Text.background", CARD); r.option_add("*Text.foreground", FG); r.option_add("*Text.insertBackground", FG)
        st.configure("Card.TFrame", background=CARD)
        st.configure("Card.TLabel", background=CARD)
        st.configure("Muted.TLabel", foreground=MUTED, background=CARD)
        st.configure("H.TLabel", font=(base_font[0], int(round(15 * FONT_SCALE)), "bold"), background=CARD)
        st.configure("Big.TLabel", font=(base_font[0], int(round(26 * FONT_SCALE)), "bold"), background=CARD)
        st.configure("Accent.TButton", font=(base_font[0], fs, "bold"))
        st.configure("Treeview", rowheight=24, background=CARD, fieldbackground=CARD)
        st.configure("Treeview.Heading", font=(base_font[0], 10, "bold"))
        st.configure("Treeview", foreground=FG, rowheight=int(round(24 * FONT_SCALE)))
        st.configure("Treeview.Heading", background=CARD, foreground=FG)
        st.map("Treeview", background=[("selected", SEL)], foreground=[("selected", FG)])

        # toolbar
        tb = ttk.Frame(r, padding=(12, 10, 12, 4))
        tb.pack(fill="x")
        rt = tb
        if FONT_SCALE >= 1.25:            # big text: export/report buttons get their own row
            rt = ttk.Frame(r, padding=(12, 0, 12, 4))
            rt.pack(fill="x")
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
        ttk.Button(tb, text=t("ui.sites"), command=self.sites_dialog).pack(side="left", padx=(0, 4))
        ttk.Button(tb, text=t("chk.go") + "…", command=self.check_dialog).pack(side="left", padx=(0, 6))
        lang_btn = ttk.Button(tb, text="TR" if get_lang() == "en" else "EN", width=3, command=self.toggle_lang)
        lang_btn.pack(side="left", padx=(0, 4))
        vb = ttk.Menubutton(tb, text=t("ui.view") + " ▾", width=9)
        vm = tk.Menu(vb, tearoff=False)
        cfg0 = config.load()
        self._theme_var = tk.StringVar(value=cfg0.get("theme", "system"))
        self._hc_var = tk.BooleanVar(value=bool(cfg0.get("high_contrast")))
        self._fs_var = tk.IntVar(value=int(cfg0.get("font_scale", 100) or 100))
        tm = tk.Menu(vm, tearoff=False)
        for key in ("system", "light", "dark"):
            tm.add_radiobutton(label=t("ui.theme." + key), value=key, variable=self._theme_var, command=self._save_view)
        vm.add_cascade(label=t("ui.theme"), menu=tm)
        vm.add_checkbutton(label=t("ui.contrast"), variable=self._hc_var, command=self._save_view)
        sm = tk.Menu(vm, tearoff=False)
        for pct in (100, 125, 150, 175):
            sm.add_radiobutton(label=f"{pct}%", value=pct, variable=self._fs_var, command=self._save_view)
        vm.add_cascade(label=t("ui.textsize"), menu=sm)
        vb["menu"] = vm
        vb.pack(side="left", padx=(0, 12))
        ttk.Button(rt, text=t("ui.folder"), width=7, command=lambda: open_path(config.DIR if os.path.isdir(config.DIR) else os.getcwd())).pack(side="right")
        ttk.Button(rt, text=t("ui.compare"), width=10, command=self.compare_prev).pack(side="right", padx=4)
        mb = ttk.Menubutton(rt, text=t("ui.save") + " ▾", width=10)
        menu = tk.Menu(mb, tearoff=False)
        menu.add_command(label=t("ui.html"), command=self.save_html)
        menu.add_command(label=t("ui.json"), command=self.save_json)
        menu.add_command(label=t("ui.card"), command=self.save_card)
        mb["menu"] = menu
        mb.pack(side="right", padx=4)
        self.btn_view = ttk.Button(rt, text=t("ui.report"), width=13, style="Accent.TButton",
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
                                   selectbackground=SEL, selectforeground=FG, activestyle="none")
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
        txt = (f"filterscope {__version__}. GPL-3.0. github.com/tunnelmoth/filterscope\n\n"
               "filterscope measures filtering and censorship on the network you are connected to. It uses only your own "
               "traffic and a clean allowlist of well-known sites.\n\n"
               "Verdicts\n"
               "  SNI-DPI            the TLS server name is inspected. The site is reset only with its real name.\n"
               "  TLS-MITM           the network decrypts HTTPS with its own certificate authority.\n"
               "  HIJACK-blockpage   DNS answers with a private IP (a block-page server).\n"
               "  DNS-BLOCK          the resolver withholds the answer while DoH resolves.\n"
               "  INTERCEPTED        port-53 DNS is proxied. A change to 8.8.8.8 has no effect.\n"
               "  BLOCKED            packets to that port or protocol are dropped.\n"
               "  ?                  undecided. No reference, or a positive that did not repeat.\n\n"
               "Score: the share of affected sites (up to 50) plus a weight per technique plus 2 per blocked port.\n"
               "  0 clean, 1-19 light, 20-44 moderate, 45-69 heavy, 70 and above severe.\n\n"
               "Verification: every positive site result is tested a second time. Results that do not repeat are dropped.\n\n"
               "Evidence: scan here, scan again on mobile data, then compare the two saved JSON files "
               "(filterscope compare A.json B.json). Anything blocked only here is filtering specific to this network.\n\n"
               f"Data folder: {config.DIR}\n"
               "The Tor test needs a tor or tor.exe binary (Tor Expert Bundle) on PATH or next to this program.")
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

    # ── service check dialog ("is Valorant blocked here?") ──
    def check_dialog(self):
        from . import services
        win = tk.Toplevel(self.root)
        win.title(t("chk.title"))
        win.transient(self.root)
        win.geometry("760x560")
        win.configure(bg=BG)
        top = ttk.Frame(win, padding=10)
        top.pack(fill="x")
        q = tk.StringVar()
        ent = ttk.Entry(top, textvariable=q, width=28)
        ent.pack(side="left")
        ent.focus_set()
        status = tk.StringVar(value=t("chk.hint"))
        out = tk.Text(win, bg=CARD, fg=FG, wrap="word", borderwidth=1, relief="solid", highlightthickness=0,
                      padx=8, pady=6, state="disabled", font="TkDefaultFont")
        for tag, col in (("ok", GREEN_FG), ("bad", RED_FG), ("warn", YEL_FG), ("dim", MUTED), ("cyan", CYAN)):
            out.tag_configure(tag, foreground=col)
        out.tag_configure("h", font=("TkDefaultFont", 13, "bold"))
        out.tag_configure("b", font=("TkDefaultFont", 10, "bold"))
        sugg = ttk.Frame(win)
        sugg.pack(fill="x", padx=10)
        for k, name in services.suggestions("", limit=12):
            ttk.Button(sugg, text=k, width=9, command=lambda k=k: (q.set(k), run())).pack(side="left", padx=1, pady=(0, 6))
        ttk.Label(win, textvariable=status, foreground=MUTED).pack(anchor="w", padx=12)
        out.pack(fill="both", expand=True, padx=10, pady=(4, 10))

        def render(res):
            v = res["verdict"]
            tagv = {"OK": "ok", "BLOCKED": "bad", "PARTIAL": "warn", "THROTTLED": "cyan"}[v.split("+")[0]]
            key = {"OK": "chk.ok", "BLOCKED": "chk.blocked", "PARTIAL": "chk.partial", "THROTTLED": "chk.throttled"}[v.split("+")[0]]
            parts = [(res["name"] + "  ", "h"), (v + "\n", tagv), (t(key, name=res["name"]) + "\n\n", "")]
            if res["reasons"]:
                parts.append((t("chk.reasons") + ":\n", "b"))
                parts += [("  • " + r + "\n", "bad") for r in res["reasons"]]
                parts.append(("\n", ""))
            parts.append((t("chk.endpoints") + ":\n", "b"))
            for h in res["hosts"]:
                st = h["sni"] or h["tcp"] or h["dns"] or "?"
                tg = "ok" if h["verdict"] == "ok" else ("dim" if h["verdict"] == "?" else "bad")
                parts += [(f"  {h['kind']:6} {h['host']:44} ", "dim"), (st + ("  " + h["detail"] if h.get("detail") else "") + "\n", tg)]
            if res["ports"]:
                parts.append(("\n" + t("chk.ports") + ": ", "b"))
                parts += [(f"{k} {v2}   ", "ok" if not v2.startswith("BLOCKED") else "bad") for k, v2 in sorted(res["ports"].items())]
                parts.append(("\n", ""))
            if res.get("udp"):
                parts += [(t("chk.udp") + ": ", "b"), (res["udp"] + "\n", "ok" if res["udp"] == "open" else "bad"), ("  " + t("chk.udp_note") + "\n", "dim")]
            d = res.get("download") or {}
            if d:
                if d.get("error"):
                    parts += [(t("chk.download") + ": ", "b"), (f"error ({d['error']})\n", "bad")]
                else:
                    parts += [(t("chk.download") + ": ", "b"), (f"{d.get('mbps', 0)} Mbit/s", "cyan"), (f"   {t('chk.baseline')}: {d.get('baseline', '?')} Mbit/s", "dim"),
                              ((f"   ({d['note']})" if d.get("note") else "") + "\n", "dim")]
            self._set_text(out, parts)

        def run(*_):
            key = services.find(q.get())
            if not key:
                status.set(t("chk.unknown", q=q.get(), known=", ".join(sorted(services.SERVICES))))
                return
            status.set(f"{services.SERVICES[key]['name']} …")
            self._set_text(out, [])

            def worker():
                try:
                    res = core.check_service(key, timeout=6)
                except Exception as e:  # pragma: no cover
                    self.ui(lambda: status.set(f"error: {e}"))
                    return
                self.ui(lambda: (render(res), status.set(res["name"] + " — " + res["verdict"])))
            threading.Thread(target=worker, daemon=True).start()

        ttk.Button(top, text=t("chk.go"), style="Accent.TButton", command=run).pack(side="left", padx=8)
        ent.bind("<Return>", run)

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

    def ui(self, fn):
        """Run fn on the Tk thread (Tk is not thread-safe; worker threads use this)."""
        self.q.put(("call", (fn,)))

    def _handle(self, ev, a):
        if ev == "call":
            try:
                a[0]()
            except Exception:
                pass
        elif ev == "net":
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

    def _save_view(self):
        cfg = config.load()
        cfg["theme"] = self._theme_var.get()
        cfg["high_contrast"] = bool(self._hc_var.get())
        cfg["font_scale"] = int(self._fs_var.get())
        config.save(cfg)
        self._status.set(t("ui.restart_note"))

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
                self.ui(lambda: (self.update_lbl.configure(text="  " + t("ui.update", latest=u["latest"]) + "  "),
                                 self.update_lbl.pack(fill="x", padx=12, pady=(0, 6), after=self.root.winfo_children()[1])))
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
    if "--tray" in argv:
        from .tray import main as tray_main
        return tray_main([a for a in argv if a != "--tray"])
    root = tk.Tk()
    App(root, autoscan=("--autoscan" in argv or "--scan" in argv))
    root.mainloop()


if __name__ == "__main__":
    main()

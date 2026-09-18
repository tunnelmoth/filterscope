"""System-tray / background mode.

Sits in the tray, watches for network changes (gateway/resolver/SSID fingerprint),
runs a quick scan when the network changes, and notifies: "Discord, Roblox blocked on
this network". Menu: Open window · Scan now · Check ▸ · Auto-scan on/off · Quit.

The window is a separate process (filterscope-gui), so the tray never blocks."""
from __future__ import annotations

import os
import subprocess
import sys
import threading
import time

from . import __version__, config, core, scan, sysinfo
from .i18n import t

QUICK_CATEGORIES = ["chat", "games", "video", "social", "messaging", "vpn-api", "ai", "webproxy"]


def _icon_image(level="clean"):
    from PIL import Image, ImageDraw
    col = {"clean": (61, 220, 132), "light": (255, 183, 77), "moderate": (255, 152, 0),
           "heavy": (255, 107, 107), "severe": (229, 57, 53), "idle": (139, 92, 246), "busy": (160, 160, 160)}[level]
    im = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    d.rounded_rectangle((2, 2, 62, 62), radius=16, fill=(23, 35, 47, 255))
    d.ellipse((14, 14, 50, 50), outline=col, width=6)
    d.line((32, 6, 32, 20), fill=col, width=5)
    d.line((32, 44, 32, 58), fill=col, width=5)
    d.line((6, 32, 20, 32), fill=col, width=5)
    d.line((44, 32, 58, 32), fill=col, width=5)
    d.ellipse((27, 27, 37, 37), fill=(255, 90, 90, 255))
    return im


def gui_command(*args):
    """How to launch the window from the tray, frozen or not."""
    if getattr(sys, "frozen", False):
        exe = sys.executable
        if os.path.basename(exe).lower().startswith("filterscope-gui"):
            return [exe, *args]
        sib = os.path.join(os.path.dirname(exe), "filterscope-gui" + (".exe" if sys.platform.startswith("win") else ""))
        if os.path.exists(sib):
            return [sib, *args]
        return [exe, "gui", *args]
    return [sys.executable, "-m", "filterscope.gui", *args]


class Tray:
    def __init__(self, interval=30, autoscan=True):
        import pystray
        self.pystray = pystray
        self.interval = interval
        self.autoscan = autoscan
        self.last_id = None
        self.last_report = None
        self.busy = False
        self._stop = threading.Event()
        self.icon = pystray.Icon("filterscope", _icon_image("idle"), f"filterscope {__version__}", menu=self._menu())

    # ── menu ──
    def _menu(self):
        ps = self.pystray
        from . import services
        checks = [ps.MenuItem(services.SERVICES[k]["name"], self._mk_check(k))
                  for k in ("discord", "roblox", "valorant", "youtube", "whatsapp", "instagram", "steam", "minecraft") if k in services.SERVICES]
        return ps.Menu(
            ps.MenuItem(t("tray.open"), self.open_window, default=True),
            ps.MenuItem(t("tray.scan"), self.scan_now),
            ps.MenuItem(t("chk.title"), ps.Menu(*checks)),
            ps.MenuItem(t("tray.autoscan"), self.toggle_autoscan, checked=lambda item: self.autoscan),
            ps.Menu.SEPARATOR,
            ps.MenuItem(t("tray.quit"), self.quit),
        )

    def _mk_check(self, key):
        def run(icon=None, item=None):
            threading.Thread(target=self._check, args=(key,), daemon=True).start()
        return run

    # ── actions ──
    def open_window(self, icon=None, item=None):
        try:
            subprocess.Popen(gui_command(), close_fds=True)
        except Exception as e:
            self.notify("filterscope", f"cannot open window: {e}")

    def scan_now(self, icon=None, item=None):
        threading.Thread(target=self._scan, args=(True,), daemon=True).start()

    def toggle_autoscan(self, icon=None, item=None):
        self.autoscan = not self.autoscan

    def quit(self, icon=None, item=None):
        self._stop.set()
        self.icon.stop()

    def notify(self, title, msg):
        try:
            self.icon.notify(msg[:250], title)
        except Exception:
            pass

    # ── work ──
    def _scan(self, manual=False):
        if self.busy:
            return
        self.busy = True
        self.icon.icon = _icon_image("busy")
        try:
            cfg = config.load()
            opts = scan.ScanOptions.from_config(cfg, "quick", categories=QUICK_CATEGORIES)
            opts.ech, opts.blockpage = False, False
            report = scan.run_scan(opts)
            self.last_report = report
            an = report["analysis"]
            self.icon.icon = _icon_image(an["level"])
            self.icon.title = f"filterscope · {an['score']}/100 {an['level']} · {sysinfo.net_name(report['net'])}"
            blocked = sorted({d for d, r in report["sites"].items() if any(r[k]["verdict"] not in core.NEUTRAL for k in ("dns", "sni", "blockpage"))})
            try:
                scan.write_outputs(report, history=True)
            except Exception:
                pass
            if blocked:
                self.notify(t("tray.blocked_title", name=sysinfo.net_name(report["net"])),
                            ", ".join(blocked[:8]) + (" …" if len(blocked) > 8 else ""))
            elif manual:
                self.notify("filterscope", t("ui.no_interference"))
        except Exception as e:
            self.icon.icon = _icon_image("idle")
            self.notify("filterscope", f"scan failed: {e}")
        finally:
            self.busy = False

    def _check(self, key):
        from . import services
        try:
            res = core.check_service(key, timeout=6)
            self.notify(res["name"] + " — " + res["verdict"], (res["reasons"][0] if res["reasons"] else t("chk.ok", name=res["name"]))[:200])
        except Exception as e:
            self.notify("filterscope", f"check failed: {e}")

    def _watch(self):
        """Network-change watcher: fingerprint every `interval` seconds."""
        while not self._stop.is_set():
            try:
                fp = sysinfo.net_fingerprint(None)
                nid = fp["id"] if (fp.get("gateway") or fp.get("resolver")) else None
                if nid and nid != self.last_id:
                    first = self.last_id is None
                    self.last_id = nid
                    if self.autoscan and not first:
                        self.notify("filterscope", t("tray.net_changed", name=sysinfo.net_name(fp)))
                        self._scan()
                    elif self.autoscan and first:
                        self._scan()
            except Exception:
                pass
            self._stop.wait(self.interval)

    def run(self):
        threading.Thread(target=self._watch, daemon=True).start()
        self.icon.run()


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    try:
        import pystray  # noqa: F401
    except Exception as e:
        sys.exit(f"tray mode needs the 'pystray' package ({e}). On Linux also python-xlib or PyGObject/AppIndicator.")
    interval = 30
    if "--interval" in argv:
        interval = int(argv[argv.index("--interval") + 1])
    Tray(interval=interval, autoscan="--no-autoscan" not in argv).run()


if __name__ == "__main__":
    main()

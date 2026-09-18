"""Share card — a 1200×630 PNG summarising a report (score gauge, level, techniques,
affected categories). Pillow only; fonts bundled in assets/."""
from __future__ import annotations

import math
import os
import sys

from . import __version__, analysis, core, sysinfo
from .i18n import level_name, t, tech_label

LEVEL_RGB = {"clean": (61, 220, 132), "light": (255, 183, 77), "moderate": (255, 152, 0),
             "heavy": (255, 107, 107), "severe": (229, 57, 53)}
BG, CARD, FG, MUT, LINE, ACC = (23, 35, 47), (31, 44, 59), (238, 242, 247), (163, 173, 189), (45, 60, 78), (139, 92, 246)


def _asset_dir():
    for base in (getattr(sys, "_MEIPASS", None), os.path.dirname(os.path.abspath(__file__))):
        if not base:
            continue
        for p in (os.path.join(base, "filterscope", "assets"), os.path.join(base, "assets")):
            if os.path.isdir(p):
                return p
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")


def _font(size: int, bold=False):
    from PIL import ImageFont
    name = "DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf"
    p = os.path.join(_asset_dir(), name)
    try:
        return ImageFont.truetype(p, size)
    except Exception:
        return ImageFont.load_default()


def render_card(report: dict, path: str, show_network=True) -> str:
    from PIL import Image, ImageDraw
    an = report.get("analysis") or analysis.analyze(report)
    W, H = 1200, 630
    im = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(im)
    d.rounded_rectangle((32, 32, W - 32, H - 32), radius=28, fill=CARD, outline=LINE, width=2)

    # gauge
    cx, cy, r = 190, 300, 120
    col = LEVEL_RGB[an["level"]]
    d.arc((cx - r, cy - r, cx + r, cy + r), 135, 405, fill=LINE, width=22)
    if an["score"] > 0:
        d.arc((cx - r, cy - r, cx + r, cy + r), 135, 135 + 270 * an["score"] / 100, fill=col, width=22)
    f_big, f_lvl = _font(84, True), _font(24, True)
    s = str(an["score"])
    w = d.textlength(s, font=f_big)
    d.text((cx - w / 2, cy - 62), s, font=f_big, fill=col)
    lv = level_name(an["level"], up=True)
    w = d.textlength(lv, font=f_lvl)
    d.text((cx - w / 2, cy + 34), lv, font=f_lvl, fill=col)
    d.text((cx - d.textlength("/100", font=_font(20)) / 2, cy + 74), "/100", font=_font(20), fill=MUT)

    # right column
    x = 370
    d.text((x, 70), t("card.title"), font=_font(30, True), fill=FG)
    net = sysinfo.net_name(report.get("net", {})) if show_network else ""
    line2 = f"{net + '  ·  ' if net and net != '?' else ''}{report.get('ts', '')[:16]}"
    d.text((x, 116), line2, font=_font(20), fill=MUT)

    n = len(report.get("sites", {}))
    blocked = sum(r["blocked"] for r in an["categories"])
    d.text((x, 172), t("card.affected", b=blocked, n=n) if blocked else t("card.clean"), font=_font(28, True), fill=FG)

    # technique chips
    y = 226
    cx2 = x
    f_chip = _font(20, True)
    for tech in an["techniques"][:6]:
        label = f"{tech}"
        tw = d.textlength(label, font=f_chip) + 28
        if cx2 + tw > W - 60:
            cx2, y = x, y + 46
        d.rounded_rectangle((cx2, y, cx2 + tw, y + 36), radius=18, fill=(58, 28, 40), outline=(120, 50, 70))
        d.text((cx2 + 14, y + 6), label, font=f_chip, fill=(255, 140, 140))
        cx2 += tw + 10
    if not an["techniques"]:
        d.rounded_rectangle((x, y, x + 260, y + 36), radius=18, fill=(22, 60, 40), outline=(40, 110, 70))
        d.text((x + 14, y + 6), t("html.badge_clean")[:28], font=f_chip, fill=(120, 230, 160))
    y += 60

    # category bars (top 5 affected)
    f_cat = _font(19)
    rows = [r for r in an["categories"] if r["blocked"]][:5]
    for r in rows:
        frac = r["blocked"] / max(r["total"], 1)
        d.text((x, y), f"{r['category']}", font=f_cat, fill=FG)
        bx = x + 190
        d.rounded_rectangle((bx, y + 6, bx + 420, y + 18), radius=6, fill=LINE)
        d.rounded_rectangle((bx, y + 6, bx + int(420 * frac), y + 18), radius=6, fill=col)
        d.text((bx + 432, y), f"{r['blocked']}/{r['total']}", font=f_cat, fill=MUT)
        y += 32
    if an.get("vendor"):
        d.text((x, y + 6), t("ui.vendor", vendor=an["vendor"]), font=_font(19), fill=(200, 160, 255))

    # footer
    d.text((60, H - 84), t("card.footer"), font=_font(19), fill=MUT)
    d.text((W - 60 - d.textlength(f"v{__version__}", font=_font(17)), H - 82), f"v{__version__}", font=_font(17), fill=MUT)
    # brand icon
    try:
        ico = Image.open(os.path.join(_asset_dir(), "filterscope.png")).convert("RGBA").resize((44, 44))
        im.paste(ico, (W - 60 - 44 - 90, H - 96), ico)
    except Exception:
        pass
    im.save(path, "PNG", optimize=True)
    return path

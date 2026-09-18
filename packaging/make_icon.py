"""Generate filterscope/assets/filterscope.{png,ico} (dev-time only; needs Pillow)."""
import os
from PIL import Image, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "filterscope", "assets")


def render(size):
    s = size * 4  # supersample
    im = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    r = s * 0.22
    d.rounded_rectangle((0, 0, s - 1, s - 1), radius=r, fill=(43, 95, 217, 255))
    cx = cy = s / 2
    R = s * 0.30
    d.ellipse((cx - R, cy - R, cx + R, cy + R), outline=(255, 255, 255, 255), width=int(s * 0.07))
    w = int(s * 0.055)
    g = s * 0.10
    for (x0, y0, x1, y1) in ((cx - R - g, cy, cx - R * 0.45, cy), (cx + R * 0.45, cy, cx + R + g, cy),
                             (cx, cy - R - g, cx, cy - R * 0.45), (cx, cy + R * 0.45, cx, cy + R + g)):
        d.line((x0, y0, x1, y1), fill=(255, 255, 255, 255), width=w)
    d.ellipse((cx - s * 0.05, cy - s * 0.05, cx + s * 0.05, cy + s * 0.05), fill=(255, 90, 90, 255))
    return im.resize((size, size), Image.LANCZOS)


os.makedirs(OUT, exist_ok=True)
big = render(256)
big.save(os.path.join(OUT, "filterscope.png"))
big.save(os.path.join(OUT, "filterscope.ico"), sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
print("ok", OUT)

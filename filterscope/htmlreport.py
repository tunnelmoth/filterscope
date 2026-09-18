"""Self-contained HTML evidence report (no external assets, prints cleanly)."""
from __future__ import annotations

import html
import json

from . import __version__, analysis, core, sysinfo
from .i18n import level_name, t

CSS = """
:root{--bg:#fff;--fg:#1a1a1a;--mut:#666;--ok:#1a7f37;--bad:#c62828;--warn:#b26a00;--line:#e3e3e3;--card:#fafafa;--acc:#3452a4}
@media(prefers-color-scheme:dark){:root{--bg:#121212;--fg:#eee;--mut:#9a9a9a;--ok:#4caf50;--bad:#ef5350;--warn:#ffb74d;--line:#2a2a2a;--card:#1b1b1b;--acc:#8ab4f8}}
*{box-sizing:border-box}body{margin:0;padding:24px;font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg);max-width:1100px;margin:auto}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 8px;border-bottom:1px solid var(--line);padding-bottom:4px}
.meta{color:var(--mut);font-size:13px}table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:5px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--mut);font-weight:600}
.ok{color:var(--ok);font-weight:600}.bad{color:var(--bad);font-weight:600}.warn{color:var(--warn)}.dim{color:var(--mut)}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 18px;margin:12px 0}
ul{margin:6px 0;padding-left:20px}code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
.badge{display:inline-block;padding:2px 9px;border-radius:12px;font-size:12px;font-weight:600;margin:2px 4px 2px 0;border:1px solid transparent}
.badge.bad{background:rgba(198,40,40,.12);color:var(--bad)}.badge.ok{background:rgba(26,127,55,.12);color:var(--ok)}.badge.warn{background:rgba(178,106,0,.12);color:var(--warn)}
.hero{display:flex;gap:24px;align-items:center;flex-wrap:wrap}.gauge{width:150px;height:150px;flex:none}
.hero .txt{flex:1;min-width:260px}.hero .txt p{margin:6px 0}
.cats{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:10px}
.cat{border:1px solid var(--line);border-radius:8px;padding:8px 10px;background:var(--card)}.cat b{display:block;font-size:13px}
.bar{height:6px;background:var(--line);border-radius:3px;margin:6px 0 4px;overflow:hidden}.bar i{display:block;height:100%;background:var(--bad)}
.cat.clean .bar i{background:var(--ok)}
details summary{cursor:pointer;color:var(--acc)}
@media print{body{padding:0}.card{break-inside:avoid}details{display:block}details>summary{display:none}details>*{display:block}}
"""

LEVEL_COLOR = {"clean": "var(--ok)", "light": "var(--warn)", "moderate": "var(--warn)",
               "heavy": "var(--bad)", "severe": "var(--bad)"}


def cls(v: str) -> str:
    v = v or ""
    if v in ("ok", "open") or v.startswith(("open", "passed")):
        return "ok"
    if v in ("?", "no-dns", "unreachable", "unavailable", "skipped", "refused", "tor-missing") or \
            v.startswith(("error", "tls-error", "bad-reply")):
        return "warn"
    return "bad"


def td(v: str) -> str:
    return f'<td class="{cls(v)}">{html.escape(v or "—")}</td>'


def gauge_svg(score: int, lvl: str) -> str:
    # 3/4 arc gauge
    import math
    r, cx, cy = 60, 75, 80
    start, sweep = 135, 270
    def pt(deg):
        a = math.radians(deg)
        return cx + r * math.cos(a), cy + r * math.sin(a)
    def arc(deg_from, deg_to, color, width):
        x1, y1 = pt(deg_from); x2, y2 = pt(deg_to)
        large = 1 if deg_to - deg_from > 180 else 0
        return (f'<path d="M{x1:.1f},{y1:.1f} A{r},{r} 0 {large},1 {x2:.1f},{y2:.1f}" '
                f'fill="none" stroke="{color}" stroke-width="{width}" stroke-linecap="round"/>')
    bg = arc(start, start + sweep, "var(--line)", 12)
    fg = arc(start, start + sweep * max(score, 1) / 100, LEVEL_COLOR[lvl], 12) if score else ""
    return (f'<svg class="gauge" viewBox="0 0 150 150">{bg}{fg}'
            f'<text x="75" y="86" text-anchor="middle" font-size="34" font-weight="700" fill="{LEVEL_COLOR[lvl]}">{score}</text>'
            f'<text x="75" y="106" text-anchor="middle" font-size="12" fill="var(--mut)">{html.escape(level_name(lvl, up=True))}</text></svg>')


def render_html(report: dict) -> str:
    e = html.escape
    fp = report["net"]
    an = report.get("analysis") or analysis.analyze(report)
    fl = report.get("flagged") or core.flagged(report)
    geo = report.get("geo") or {}
    out = [f"<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
           f"<title>filterscope report — {e(sysinfo.net_name(fp))}</title><style>{CSS}</style><body>",
           f"<h1>{e(t('html.title'))}</h1>",
           f'<div class=meta>{e(report["ts"])} · network <b>{e(sysinfo.net_name(fp))}</b> [id {e(fp["id"])}] · '
           f'gw {e(fp.get("gateway") or "?")} · resolver {e(fp.get("resolver") or "?")} · {e(fp.get("os", ""))}'
           + (f' · vantage {e(geo.get("country", ""))}/{e(geo.get("colo", ""))}' if geo.get("country") else "")
           + f' · filterscope {e(report.get("version", __version__))}</div>']

    # hero
    out.append('<div class=card><div class=hero>' + gauge_svg(an["score"], an["level"]) + '<div class=txt>')
    out.append(f"<p><b>{e(an['summary'])}</b></p>")
    if an["techniques"]:
        out.append("<p>" + "".join(f'<span class="badge bad" title="{e(an["technique_labels"][t])}">{e(t)}</span>'
                                   for t in an["techniques"]) + "</p>")
    else:
        out.append(f'<p><span class="badge ok">{e(t("html.badge_clean"))}</span></p>')
    out.append(f'<p class=dim>{e(t("html.confidence"))}: {e(t("conf." + an["confidence"]))}'
               + (f' · vendor signature: <b>{e(an["vendor"])}</b>' if an["vendor"] else "")
               + (" · positives re-checked" if report.get("verified") else "") + "</p>")
    out.append("</div></div></div>")

    # categories
    if an["categories"]:
        out.append(f"<h2>{e(t('html.impact'))}</h2><div class=cats>")
        for r in an["categories"]:
            pct = int(100 * r["blocked"] / max(r["total"], 1))
            out.append(f'<div class="cat {"clean" if not r["blocked"] else ""}"><b>{e(r["category"])}</b>'
                       f'<div class=bar><i style="width:{pct}%"></i></div>'
                       f'<span class=dim>{e(t("html.blocked_of", b=r["blocked"], t=r["total"]))}</span>'
                       + (f'<div class=dim style="font-size:11px">{e(", ".join(r["domains"][:3]))}</div>' if r["domains"] else "")
                       + "</div>")
        out.append("</div>")

    # findings
    out.append(f"<h2>{e(t('html.findings'))}</h2><div class=card>")
    if fl:
        out.append("<ul>" + "".join(f"<li>{e(x)}</li>" for x in fl) + "</ul>")
    else:
        out.append(f"<p class=ok>{e(t('html.no_interference'))}</p>")
    transient = [d for d, r in report.get("sites", {}).items() if r.get("transient")]
    if transient:
        out.append(f"<p class=dim>Transient (not reproduced on retry, ignored): {e(', '.join(transient))}</p>")
    out.append("</div>")

    # sites
    if report.get("sites"):
        rows = sorted(report["sites"].items(),
                      key=lambda kv: (not any(kv[1][k]["verdict"] not in core.NEUTRAL for k in ("dns", "sni", "blockpage")), kv[1]["cat"]))
        out.append(f"<h2>{e(t('html.sites'))}</h2><table><tr><th>category</th><th>domain</th>"
                   "<th>DNS</th><th>TLS/SNI</th><th>block page</th><th>ECH</th><th>ms</th><th>notes</th></tr>")
        for dom, d in rows:
            from .render import site_notes
            ech = {True: "yes", False: "no"}.get(d.get("ech"), "?")
            out.append(f"<tr><td>{e(d['cat'])}</td><td><code>{e(dom)}</code></td>{td(d['dns']['verdict'])}"
                       f"{td(d['sni']['verdict'])}{td(d['blockpage']['verdict'])}<td class=dim>{ech}</td>"
                       f"<td class=dim>{d.get('ms', '')}</td><td class=dim>{e(site_notes(d))}</td></tr>")
        out.append("</table>")

    def section(title, rows):
        if not rows:
            return
        out.append(f"<h2>{e(title)}</h2><table><tr><th>probe</th><th>status</th><th>detail</th></tr>")
        for k, v, d in rows:
            out.append(f"<tr><td>{e(k)}</td>{td(v)}<td class=dim>{e(d or '')}</td></tr>")
        out.append("</table>")

    from .render import dns_rows, egress_rows, http_rows
    section("Outbound TCP ports (portquiz.net)", [(k, v, "") for k, v in sorted(report.get("ports", {}).items())])
    section("UDP / QUIC / IPv6 / SSH egress", egress_rows(report))
    section("DNS integrity", dns_rows(report))
    section("HTTP / TLS / Tor", http_rows(report))

    def advice(title, items):
        out.append(f"<h2>{e(title)}</h2><div class=card><ul>")
        out.extend(f"<li class={ {'g': 'ok', 'r': 'bad', 'y': 'warn'}.get(c, 'dim') }>{e(t.strip())}</li>" for c, t in items)
        out.append("</ul></div>")
    advice(t("ui.vpn_diag"), core.vpn_advice(report))
    advice(t("ui.tunnel"), core.tunnel_advice(report))

    out.append(f"<h2>{e(t('html.method'))}</h2><details><summary>how each verdict is reached</summary><div class=card><ul>"
               "<li><b>DNS</b>: DoH is the reference; only private-IP redirection and NXDOMAIN injection are flagged (IP differences are treated as CDN).</li>"
               "<li><b>TLS/SNI</b>: handshake to the real IP with the real SNI vs. a harmless control SNI; reset/timeout only with the real SNI = SNI-based DPI. RST arriving faster than the TCP RTT = injected in-path.</li>"
               "<li><b>TLS interception</b>: a verified handshake against the Mozilla CA bundle for four large public sites; a chain signed by a non-public issuer = SSL inspection.</li>"
               "<li><b>Ports</b>: TCP connect to portquiz.net; timeout = dropped, refused/RST = the packet got out.</li>"
               "<li><b>UDP/QUIC</b>: STUN binding requests and a QUIC version-negotiation probe (RFC 9000 §6).</li>"
               "<li><b>DNS interception</b>: plain-53 query sent to 192.0.2.1 (TEST-NET-1); any answer means the network answers DNS on behalf of every address.</li>"
               "<li><b>NXDOMAIN hijack</b>: a random non-existent name under example.com must not resolve.</li>"
               "<li><b>URL keyword filter</b>: benign words (vpn, proxy, tor…) in a query string to example.com must be served identically to a control word.</li>"
               "<li><b>Verification</b>: every positive site result is re-tested once; a result that does not reproduce is marked transient and ignored.</li>"
               "<li><b>Score</b>: share of affected sites (max 50) + a weight per technique + 2 per blocked port, capped at 100.</li>"
               "</ul></div></details>")
    out.append("<details><summary>raw JSON</summary><pre style='font-size:11px;white-space:pre-wrap'>"
               + e(json.dumps(core.anonymize(report), ensure_ascii=False, indent=1)[:200000]) + "</pre></details>")
    out.append(f"<p class=dim>Generated by filterscope {e(__version__)} — GPL-3.0 — github.com/tunnelmoth/filterscope</p></body>")
    return "\n".join(out)


def render_history_html(runs: list[dict], title="filterscope history") -> str:
    """Timeline page from history.jsonl records (one network per section)."""
    from collections import defaultdict
    from .history import blocked_of
    e = html.escape
    by_net = defaultdict(list)
    for r in runs:
        by_net[(r.get("net", "?"), r.get("label", ""))].append(r)
    out = [f"<!doctype html><meta charset=utf-8><title>{e(title)}</title><style>{CSS}</style><body>",
           f"<h1>{e(title)}</h1><div class=meta>{len(runs)} runs · {len(by_net)} networks</div>"]
    for (net, label), items in by_net.items():
        items.sort(key=lambda r: r["ts"])
        out.append(f"<h2>{e(label or net)} <span class=dim>[id {e(net)}]</span></h2>")
        # sparkline of block counts
        counts = [len(blocked_of(r)) for r in items]
        mx = max(counts + [1])
        w, h = min(900, 12 * len(counts) + 20), 60
        bars = "".join(f'<rect x="{10 + i * 12}" y="{h - 5 - 45 * c / mx:.1f}" width="9" height="{45 * c / mx:.1f}" '
                       f'fill="{"var(--bad)" if c else "var(--ok)"}"><title>{e(items[i]["ts"])}: {c} blocks</title></rect>'
                       for i, c in enumerate(counts))
        out.append(f'<svg width="{w}" height="{h}" viewBox="0 0 {w} {h}">{bars}</svg>')
        out.append("<table><tr><th>time</th><th>score</th><th>blocks</th><th>changes</th></tr>")
        prev = None
        for r in items:
            b = blocked_of(r)
            ch = ""
            if prev is not None:
                ch = " ".join([f'<span class="badge bad">+ {e(x)}</span>' for x in sorted(b - prev)]
                              + [f'<span class="badge ok">− {e(x)}</span>' for x in sorted(prev - b)]) or "<span class=dim>no change</span>"
            else:
                ch = " ".join(f'<span class="badge bad">{e(x)}</span>' for x in sorted(b)) or "<span class=dim>clean</span>"
            sc = r.get("score")
            out.append(f"<tr><td>{e(r['ts'])}</td><td>{'' if sc is None else sc}</td><td>{len(b)}</td><td>{ch}</td></tr>")
            prev = b
        out.append("</table>")
    out.append(f"<p class=dim>Generated by filterscope {e(__version__)}</p></body>")
    return "\n".join(out)

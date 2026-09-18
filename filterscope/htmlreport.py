"""Self-contained HTML evidence report (no external assets)."""
from __future__ import annotations

import html

from . import __version__, core, sysinfo

CSS = """
:root{--bg:#fff;--fg:#1a1a1a;--mut:#666;--ok:#1a7f37;--bad:#c62828;--warn:#b26a00;--line:#e3e3e3;--card:#fafafa}
@media(prefers-color-scheme:dark){:root{--bg:#121212;--fg:#eee;--mut:#9a9a9a;--ok:#4caf50;--bad:#ef5350;--warn:#ffb74d;--line:#2a2a2a;--card:#1b1b1b}}
body{margin:0;padding:24px;font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg);max-width:1100px;margin:auto}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 8px;border-bottom:1px solid var(--line);padding-bottom:4px}
.meta{color:var(--mut);font-size:13px}table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:5px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--mut);font-weight:600}
.ok{color:var(--ok);font-weight:600}.bad{color:var(--bad);font-weight:600}.warn{color:var(--warn)}.dim{color:var(--mut)}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 16px;margin:12px 0}
ul{margin:6px 0;padding-left:20px}code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:12px;font-weight:600}
.badge.bad{background:rgba(198,40,40,.12)}.badge.ok{background:rgba(26,127,55,.12)}
"""


def cls(v: str) -> str:
    v = v or ""
    if v in ("ok", "open") or v.startswith(("open", "passed")):
        return "ok"
    if v in ("?", "no-dns", "unreachable", "unavailable", "skipped", "refused") or \
            v.startswith(("error", "tls-error", "bad-reply")):
        return "warn"
    return "bad"


def td(v: str) -> str:
    return f'<td class="{cls(v)}">{html.escape(v or "—")}</td>'


def render_html(report: dict) -> str:
    e = html.escape
    fp = report["net"]
    fl = report.get("flagged") or core.flagged(report)
    out = [f"<!doctype html><meta charset=utf-8><title>filterscope report — {e(sysinfo.net_name(fp))}</title>",
           f"<style>{CSS}</style><body>",
           f"<h1>filterscope report</h1>",
           f'<div class=meta>{e(report["ts"])} · network <b>{e(sysinfo.net_name(fp))}</b> [id {e(fp["id"])}] · '
           f'gw {e(fp.get("gateway") or "?")} · resolver {e(fp.get("resolver") or "?")} · {e(fp.get("os", ""))} · '
           f'filterscope {e(report.get("version", __version__))}</div>']
    badge = (f'<span class="badge bad">{len(fl)} interference signals</span>' if fl
             else '<span class="badge ok">no clear interference</span>')
    out.append(f"<div class=card><h2 style='margin-top:0;border:0'>Summary {badge}</h2>")
    if fl:
        out.append("<ul>" + "".join(f"<li>{e(x)}</li>" for x in fl) + "</ul>")
    out.append("<p class=dim>Measured with the device's own traffic against a clean allowlist of well-known sites. "
               "Compare with a run on another network (e.g. mobile data) to attribute filtering to this network.</p></div>")

    if report.get("sites"):
        out.append("<h2>Sites — DNS / TLS-SNI / block page / ECH</h2><table><tr><th>category/site</th><th>domain</th>"
                   "<th>DNS</th><th>TLS/SNI</th><th>block page</th><th>ECH</th><th>notes</th></tr>")
        for dom, d in sorted(report["sites"].items(), key=lambda kv: kv[1]["cat"]):
            notes = []
            if d["sni"]["verdict"] == "SNI-DPI" and d.get("ech"):
                notes.append("ECH can bypass this")
            if d["sni"].get("injected"):
                notes.append("RST injected in-path")
            for tag, r in (("dns", d["dns"]), ("sni", d["sni"]), ("bp", d["blockpage"])):
                n = r.get("note") or r.get("detail")
                if n and r.get("verdict") != "ok" and n != "skipped":
                    notes.append(f"{tag}: {n}")
            ech = {True: "yes", False: "no"}.get(d.get("ech"), "?")
            out.append(f"<tr><td>{e(d['cat'])}</td><td><code>{e(dom)}</code></td>{td(d['dns']['verdict'])}"
                       f"{td(d['sni']['verdict'])}{td(d['blockpage']['verdict'])}<td class=dim>{ech}</td>"
                       f"<td class=dim>{e('; '.join(notes))}</td></tr>")
        out.append("</table>")

    def section(title, rows):
        if not rows:
            return
        out.append(f"<h2>{e(title)}</h2><table><tr><th>probe</th><th>status</th><th>detail</th></tr>")
        for k, v, d in rows:
            out.append(f"<tr><td>{e(k)}</td>{td(v)}<td class=dim>{e(d or '')}</td></tr>")
        out.append("</table>")

    section("Outbound TCP ports (portquiz.net)", [(k, v, "") for k, v in sorted(report.get("ports", {}).items())])
    misc = [(f"UDP STUN {k}", v, "") for k, v in sorted(report.get("udp_detail", {}).items())]
    misc += [(f"QUIC {k}", v, "") for k, v in sorted(report.get("quic_detail", {}).items())]
    if report.get("ipv6"):
        misc.append(("IPv6 egress", report["ipv6"]["verdict"], report["ipv6"]["detail"]))
    section("UDP / QUIC / IPv6 egress", misc)
    dnsrows = [(k, v, "") for k, v in sorted(report.get("dns_encrypted", {}).items())]
    if report.get("dns_intercept"):
        dnsrows.append(("port-53 interception", report["dns_intercept"]["verdict"], report["dns_intercept"]["detail"]))
    section("Encrypted DNS / interception", dnsrows)
    other = []
    if report.get("http_proxy"):
        other.append(("HTTP transparent proxy", report["http_proxy"]["verdict"], report["http_proxy"]["detail"]))
    if report.get("ssh"):
        other.append(("SSH egress (22)", report["ssh"], ""))
    if report.get("speed"):
        other.append(("downstream", f"{report['speed'].get('mbps', 0)} Mbit/s", report["speed"].get("detail", "")))
    if report.get("tor"):
        other.append(("Tor bootstrap", report["tor"]["verdict"], report["tor"]["detail"]))
    section("Proxy / SSH / Tor", other)

    out.append("<h2>VPN diagnosis</h2><div class=card><ul>")
    out += [f"<li class={ {'g': 'ok', 'r': 'bad', 'y': 'warn'}.get(c, 'dim') }>{e(t.strip())}</li>"
            for c, t in core.vpn_advice(report)]
    out.append("</ul></div><h2>Tunnel / circumvention</h2><div class=card><ul>")
    out += [f"<li class={ {'g': 'ok', 'r': 'bad', 'y': 'warn'}.get(c, 'dim') }>{e(t.strip())}</li>"
            for c, t in core.tunnel_advice(report)]
    out.append("</ul></div>")
    out.append("<h2>Method</h2><div class=card class=dim><ul>"
               "<li><b>DNS</b>: DoH is the reference; only private-IP redirection and NXDOMAIN injection are flagged (IP differences are treated as CDN).</li>"
               "<li><b>TLS/SNI</b>: handshake to the real IP with the real SNI vs. a harmless control SNI; reset/timeout only with the real SNI = SNI-based DPI. RST arriving faster than the TCP RTT = injected in-path.</li>"
               "<li><b>Ports</b>: TCP connect to portquiz.net; timeout = dropped, refused/RST = the packet got out.</li>"
               "<li><b>UDP/QUIC</b>: STUN binding requests and a QUIC version-negotiation probe (RFC 9000 §6).</li>"
               "<li><b>DNS interception</b>: plain-53 query sent to 192.0.2.1 (TEST-NET-1); any answer means the network answers DNS on behalf of every address.</li>"
               "</ul></div>")
    out.append(f"<p class=dim>Generated by filterscope {e(__version__)} — GPL-3.0 — github.com/tunnelmoth/filterscope</p></body>")
    return "\n".join(out)

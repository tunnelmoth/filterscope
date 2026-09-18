"""Kotlin ↔ Python glue for the Android app. Runs the exact same engine as the
desktop builds; events are forwarded to a Java listener object with
onEvent(kind: String, payloadJson: String)."""
from __future__ import annotations

import json
import os
import sys
import threading

_cancel = False
_lock = threading.Lock()


def init(files_dir: str, lang: str = ""):
    """Point HOME at the app's private files dir so ~/.filterscope lands there."""
    os.environ["HOME"] = files_dir
    if lang:
        os.environ["FILTERSCOPE_LANG"] = lang
    os.makedirs(files_dir, exist_ok=True)
    for m in list(sys.modules):
        if m == "filterscope" or m.startswith("filterscope."):
            del sys.modules[m]
    import filterscope  # noqa: F401  (re-import with the new HOME)
    from filterscope import __version__, i18n
    i18n.set_lang(lang or None)
    return __version__


def set_net_hints(gateway: str, resolver: str, ssid: str, transport: str):
    from filterscope import sysinfo
    sysinfo.HINTS = {"gateway": gateway or "", "resolver": resolver or "",
                     "ssid": ssid or "", "search": transport or "", "os": "Android"}


def profiles() -> str:
    from filterscope import config
    return json.dumps(sorted(config.PROFILES))


def start(profile: str, label: str, listener, domains: str = "") -> str:
    """Blocking: run a scan, stream events to listener, return the report as JSON."""
    global _cancel
    from filterscope import config, scan
    with _lock:
        _cancel = False
        opts = scan.ScanOptions.from_config(config.load(), profile or "full", label=label or None)
        import re as _re
        extra = []
        for raw in _re.split(r"[\s,;]+", domains or ""):
            d = _re.sub(r"^https?://", "", raw.strip().lower()).split("/")[0].strip(".")
            if d and _re.match(r"^([a-z0-9-]+\.)+[a-z]{2,}$", d) and d not in extra:
                extra.append(d)
        opts.domains = list(opts.domains) + extra
        opts.tor = False                                   # no tor binary on Android
        opts.steps = tuple(s for s in opts.steps if s != "tor")

        def emit(ev, *a):
            try:
                listener.onEvent(ev, json.dumps(a, default=str, ensure_ascii=False))
            except Exception:
                pass

        report = scan.run_scan(opts, emit, cancelled=lambda: _cancel)
        if report.get("analysis"):
            try:
                scan.write_outputs(report, history=True)
            except Exception:
                pass
        return json.dumps(report, default=str, ensure_ascii=False)


def cancel():
    global _cancel
    _cancel = True


def render_html(report_json: str) -> str:
    from filterscope.htmlreport import render_html as rh
    return rh(json.loads(report_json))


def history() -> str:
    from filterscope.history import blocked_of, load_runs
    runs = load_runs()
    prev, rows = {}, []
    for r in runs:
        key = r.get("net")
        b = blocked_of(r)
        p = prev.get(key)
        if p is None:
            ch = ""
        else:
            ch = " ".join([f"+{x}" for x in sorted(b - p)] + [f"−{x}" for x in sorted(p - b)]) or "no change"
        rows.append({"ts": r.get("ts", ""), "net": r.get("label") or key, "score": r.get("score"),
                     "blocks": len(b), "changes": ch})
        prev[key] = b
    return json.dumps(rows[-200:][::-1], ensure_ascii=False)


def diff_prev(report_json: str) -> str:
    from filterscope import analysis, config
    rep = json.loads(report_json)
    older = config.previous_report(rep["net"]["id"], before_ts=rep["ts"])
    if not older:
        return json.dumps(None)
    d = analysis.diff(older, rep)
    d["old_ts"] = older["ts"]
    return json.dumps(d, ensure_ascii=False)


def check_update() -> str:
    from filterscope import core
    return json.dumps(core.check_update(timeout=6))


def render_card(report_json: str, path: str, show_network: bool = True) -> str:
    from filterscope.card import render_card as rc
    return rc(json.loads(report_json), path, show_network=show_network)


def advice(report_json: str) -> str:
    """Localized advice lines [[color, text], ...] (VPN block then tunnel block)."""
    from filterscope import core
    rep = json.loads(report_json)
    return json.dumps({"vpn": core.vpn_advice(rep), "tunnel": core.tunnel_advice(rep)}, ensure_ascii=False)


def last_summary() -> str:
    """For the home-screen widget: latest stored report's score/level/ts/label."""
    from filterscope import config
    files = config.list_reports()
    if not files:
        return json.dumps(None)
    try:
        r = config.load_report(files[-1])
        an = r.get("analysis") or {}
        return json.dumps({"score": an.get("score"), "level": an.get("level"), "ts": r.get("ts", ""),
                           "net": r.get("net", {}).get("label") or r.get("net", {}).get("ssid") or ""})
    except Exception:
        return json.dumps(None)


def services_list() -> str:
    from filterscope import services
    return json.dumps([[k, v["name"]] for k, v in services.SERVICES.items()])


def check_service(query: str) -> str:
    from filterscope import core, services
    from filterscope.i18n import t
    key = services.find(query)
    if not key:
        return json.dumps({"error": t("chk.unknown", q=query, known=", ".join(sorted(services.SERVICES)))}, ensure_ascii=False)
    res = core.check_service(key, timeout=6)
    v = res["verdict"].split("+")[0]
    res["sentence"] = t({"OK": "chk.ok", "BLOCKED": "chk.blocked", "PARTIAL": "chk.partial", "THROTTLED": "chk.throttled"}[v], name=res["name"])
    return json.dumps(res, ensure_ascii=False, default=str)

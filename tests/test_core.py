"""Offline unit tests — no network access needed."""
import json

from filterscope import core, htmlreport, scan
from filterscope.compare import blocked_set
from filterscope.history import blocked_of
from filterscope.wgcheck import build_initiation
import os


def test_is_private():
    assert core.is_private("10.0.0.1")
    assert core.is_private("127.0.0.1")
    assert core.is_private("0.0.0.0")
    assert not core.is_private("1.1.1.1")
    assert not core.is_private("not-an-ip")


def test_dns_verdict():
    assert core.dns_verdict([], ["1.2.3.4"], [])[0] == "?"
    assert core.dns_verdict(["1.2.3.4"], ["10.1.1.1"], [])[0] == "HIJACK-blockpage"
    assert core.dns_verdict(["1.2.3.4"], [], [])[0] == "DNS-BLOCK"
    v, note = core.dns_verdict(["1.2.3.4"], ["5.6.7.8"], [])
    assert v == "ok" and "CDN" in note
    assert core.dns_verdict(["1.2.3.4"], ["1.2.3.4"], ["1.2.3.4"]) == ("ok", "")
    # private answer everywhere (split-horizon site) is not a hijack
    assert core.dns_verdict(["10.0.0.5"], ["10.0.0.5"], [])[0] == "ok"


def test_select_sites():
    ai = core.select_sites(["ai"])
    assert ai and all(k.startswith("ai/") for k in ai)
    extra = core.select_sites(["ai"], ["Example.org "])
    assert extra["custom/example.org"] == "example.org"
    assert len(core.select_sites()) == len(core.SITES)
    assert "ai" in core.categories()


def test_quic_packet_shape():
    pkt, dcid = core.quic_vn_packet()
    assert len(pkt) == 1200
    assert pkt[0] & 0xC0 == 0xC0            # long header + fixed bit
    assert pkt[1:5] == b"\x1a\x2a\x3a\x4a"  # greased version → forces Version Negotiation
    assert pkt[5] == 8 and pkt[6:14] == dcid


def test_wireguard_initiation_length():
    priv = os.urandom(32)
    pub = os.urandom(32)
    pkt = build_initiation(pub, priv)
    assert len(pkt) == 148
    assert pkt[:4] == b"\x01\x00\x00\x00"
    assert pkt[-16:] == b"\x00" * 16        # mac2 empty


def _report():
    return {
        "schema": 2, "version": "test", "ts": "2026-01-01 00:00:00",
        "net": {"id": "abcd1234", "label": "school", "search": "lan", "gateway": "10.0.0.1",
                "resolver": "10.0.0.1", "ssid": "SCHOOL", "os": "test"},
        "sites": {
            "discord.com": {"cat": "chat/discord",
                            "dns": {"truth": ["1.2.3.4"], "system": ["1.2.3.4"], "udp53": [], "verdict": "ok", "note": ""},
                            "sni": {"tcp": True, "verdict": "SNI-DPI", "detail": "x", "injected": True},
                            "blockpage": {"verdict": "ok", "detail": ""}, "ech": True},
            "eff.org": {"cat": "digital-rights/eff",
                        "dns": {"truth": ["1.2.3.4"], "system": ["1.2.3.4"], "udp53": ["1.2.3.4"], "verdict": "ok", "note": ""},
                        "sni": {"tcp": True, "verdict": "ok", "detail": ""},
                        "blockpage": {"verdict": "ok", "detail": ""}, "ech": False},
        },
        "ports": {"HTTPS 443": "open", "SSH 22": "BLOCKED (timeout)"},
        "udp": "open", "udp_detail": {"stun.l.google.com:19302": "open"},
        "quic": "BLOCKED", "quic_detail": {"cloudflare.com:443": "BLOCKED (timeout)"},
        "ipv6": {"verdict": "unavailable", "detail": "no route"},
        "dns_encrypted": {"DoH cloudflare": "open (10 ms)", "DoT google": "BLOCKED (timeout)"},
        "dns_intercept": {"verdict": "INTERCEPTED", "detail": "answer"},
        "http_proxy": {"verdict": "PROXY", "detail": "via", "headers": {"via": "1.1 squid"}},
        "ssh": "BLOCKED (timeout)", "tor": {"verdict": "BLOCKED?", "detail": "never"}, "speed": {},
    }


def test_flagged_and_records():
    r = _report()
    fl = core.flagged(r)
    assert "discord.com: sni=SNI-DPI" in fl
    assert "port SSH 22" in fl
    assert "quic/udp-443" in fl
    assert "encrypted-dns DoT google" in fl
    assert "dns-53 intercepted" in fl
    assert "http transparent proxy" in fl
    assert "tor=BLOCKED?" in fl
    assert "eff.org" not in " ".join(fl)

    rec = core.history_record(r)
    assert rec["net"] == "abcd1234" and rec["dns_intercept"] == "INTERCEPTED"
    assert blocked_of(rec) >= {"udp egress"} - {"udp egress"}   # udp open → not present
    assert "udp egress" not in blocked_of(rec)
    assert "quic/udp-443" in blocked_of(rec)
    # compare and history agree on what is a block
    assert {x for x in blocked_set(r) if x.startswith("port")} == {"port SSH 22"}
    json.dumps(rec)


def test_anonymize_strips_identity():
    a = core.anonymize(_report())
    assert set(a["net"]) == {"id", "label"}
    assert "system" not in a["sites"]["discord.com"]["dns"]
    assert "headers" not in a["http_proxy"]
    assert a["sites"]["discord.com"]["sni"]["verdict"] == "SNI-DPI"


def test_advice_mentions_findings():
    r = _report()
    text = " ".join(t for _, t in core.vpn_advice(r) + core.tunnel_advice(r))
    assert "intercepted" in text
    assert "QUIC" in text
    assert "SSH (22) blocked" in text


def test_html_report_renders():
    r = _report()
    r["flagged"] = core.flagged(r)
    html = htmlreport.render_html(r)
    assert "<!doctype html>" in html
    assert "discord.com" in html and "SNI-DPI" in html
    assert "Findings" in html and "gauge" in html
    assert "<script" not in html


def test_scan_options_quick():
    o = scan.ScanOptions.quick(label="x")
    assert not o.tor and not o.ech and "tor" not in o.steps
    assert scan.ScanOptions().steps == scan.ALL_STEPS


# ── v3: analysis / config / verification ──────────────────────────────────────
from filterscope import analysis, config


def test_analysis_scoring_and_techniques():
    r = _report()
    an = analysis.analyze(r)
    assert "SNI-DPI" in an["techniques"] and "RST-injection" in an["techniques"]
    assert "DNS-intercept" in an["techniques"] and "HTTP-proxy" in an["techniques"]
    assert "QUIC-block" in an["techniques"] and "Tor-block" in an["techniques"]
    assert 0 < an["score"] <= 100
    assert an["level"] in ("light", "moderate", "heavy", "severe")
    assert an["vendor"] == "Squid proxy"
    assert an["categories"][0]["category"] == "chat" and an["categories"][0]["blocked"] == 1
    assert "filtering" in an["summary"]
    clean = {"sites": {}, "ports": {}, "net": {"label": "x"}}
    assert analysis.score(clean) == 0 and analysis.level(0) == "clean"
    assert analysis.level(19) == "light" and analysis.level(20) == "moderate" and analysis.level(70) == "severe"


def test_analysis_mitm_dominates():
    r = _report()
    r["tls_intercept"] = {"github.com": {"verdict": "TLS-MITM", "issuer": "FortiGate CA", "detail": "x"}}
    an = analysis.analyze(r)
    assert an["techniques"][0] == "TLS-MITM"
    assert an["vendor"] == "Fortinet FortiGate"
    assert "decrypted" in an["summary"]
    assert "tls-mitm github.com" in core.flagged(r)


def test_diff():
    a, b = _report(), _report()
    b["sites"]["eff.org"]["sni"]["verdict"] = "SNI-DPI"
    b["ports"]["SSH 22"] = "open"
    d = analysis.diff(a, b)
    assert d["added"] == ["eff.org: sni=SNI-DPI"]
    assert d["removed"] == ["port SSH 22"]


def test_config_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_PATH", str(tmp_path / "config.json"))
    monkeypatch.setattr(config, "REPORTS_DIR", str(tmp_path / "reports"))
    assert config.load()["timeout"] == 6.0
    cfg = config.set_value("timeout", "9")
    assert cfg["timeout"] == 9.0 and config.load()["timeout"] == 9.0
    cfg = config.set_value("categories", "ai, vpn-api")
    assert cfg["categories"] == ["ai", "vpn-api"]
    cfg = config.set_value("tor", "off")
    assert cfg["tor"] is False
    try:
        config.set_value("nope", "1")
        assert False
    except KeyError:
        pass
    r = _report()
    p = config.store_report(r)
    assert config.list_reports("abcd1234") == [p]
    assert config.previous_report("abcd1234")["ts"] == r["ts"]
    assert config.previous_report("abcd1234", before_ts=r["ts"]) is None


def test_scan_options_from_config_and_profiles():
    cfg = dict(config.DEFAULTS, categories=["ai"], steps_off=["tor"])
    o = scan.ScanOptions.from_config(cfg)
    assert o.categories == ["ai"] and "tor" not in o.steps and o.verify
    o = scan.ScanOptions.from_config(cfg, "quick")
    assert not o.tor and "mitm" not in o.steps
    o = scan.ScanOptions.from_config(cfg, "school", label="x", timeout=None)
    assert "video" in o.categories and o.label == "x" and o.timeout == 6.0


def test_recheck_job_only_reruns_positives(monkeypatch):
    calls = []
    monkeypatch.setattr(core, "dns_test", lambda d, t: calls.append("dns") or {"truth": ["1.1.1.1"], "system": [], "udp53": [], "verdict": "ok", "note": ""})
    monkeypatch.setattr(core, "sni_test", lambda d, ip, t: calls.append("sni") or {"verdict": "ok", "detail": ""})
    monkeypatch.setattr(core, "blockpage_test", lambda d, t: calls.append("bp") or {"verdict": "ok", "detail": ""})
    first = _report()["sites"]["discord.com"]          # only sni positive
    dom, second = scan.recheck_job("discord.com", first, scan.ScanOptions())
    assert set(second) == {"dns", "sni"} and "bp" not in calls


def test_history_html_renders():
    from filterscope.htmlreport import render_history_html
    recs = [core.history_record(_report()), core.history_record(_report())]
    recs[1]["ts"] = "2026-01-02 00:00:00"
    recs[1]["ports_blocked"] = []
    h = render_history_html(recs)
    assert "<svg" in h and "lifted" not in h and "− port SSH 22" in h


def test_diff_ignores_domains_not_in_both():
    a, b = _report(), _report()
    del b["sites"]["eff.org"]                      # b is a narrower scan
    a["sites"]["eff.org"]["sni"]["verdict"] = "SNI-DPI"
    d = analysis.diff(a, b)
    assert d["removed"] == [] and d["added"] == []


def test_score_small_sample_is_damped():
    r = _report()
    r["sites"] = {"discord.com": r["sites"]["discord.com"]}
    r.update(ports={}, quic="open", dns_intercept={}, http_proxy={}, tor={}, ssh="open", dns_encrypted={})
    assert analysis.level(analysis.score(r)) in ("light", "moderate")


def test_gui_module_imports_and_builds(monkeypatch):
    import pytest
    tk = pytest.importorskip("tkinter")
    from filterscope import gui
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("no display")
    app = gui.App(root)
    assert app.nb.index("end") == 5
    app.draw_gauge(42, "moderate")
    root.destroy()


def test_vpn_advice_udp_untested():
    r = _report()
    r["udp"] = ""
    text = " ".join(t for _, t in core.vpn_advice(r))
    assert "not tested" in text and "FAIL" not in text


def test_safe_name():
    assert core.safe_name("school") == "school"
    assert core.safe_name("../../etc/passwd") == "etc_passwd"
    assert core.safe_name("  .hidden/../x  ") == "hidden_.._x"
    assert core.safe_name("") == "scan" and core.safe_name("///", "id") == "id"
    assert "/" not in core.safe_name("a/b\\c") and len(core.safe_name("x" * 200)) <= 48


def test_site_list_sanity():
    import re
    doms = list(core.SITES.values())
    assert len(doms) >= 200
    assert len(doms) == len(set(doms)), "duplicate domains"
    host = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")
    bad = [d for d in doms if not host.match(d)]
    assert not bad, bad
    assert all("/" in k and k.split("/")[0] for k in core.SITES)
    from filterscope import config
    cats = set(core.categories())
    for name, prof in config.PROFILES.items():
        unknown = set(prof.get("categories", [])) - cats
        assert not unknown, (name, unknown)


def test_blockpage_generic_wording_over_https_not_counted(monkeypatch):
    class R:
        def __init__(self, url, text): self.url, self.text = url, text
    def fake_get(url, **kw):
        if "france24" in url: return R("https://www.france24.com/", "<h1>Access Denied</h1> reference #18")
        if "pinterest" in url: return R("https://www.pinterest.com/", "footer: 5651 sayili kanun temsilcisi")
        if "discord" in url: return R("http://discord.com/", "Bu siteye erişim engellenmiştir 5651")
        if "school" in url: return R("https://filter.school.local/block?u=x", "Web Page Blocked - FortiGuard")
        return R("http://ok.example/", "hello")
    monkeypatch.setattr(core.requests, "get", fake_get)
    assert core.blockpage_test("france24.com", 5)["verdict"] == "ok"
    assert core.blockpage_test("pinterest.com", 5)["verdict"] == "ok"
    assert core.blockpage_test("discord.com", 5)["verdict"] == "BLOCKPAGE"
    assert core.blockpage_test("school.example", 5)["verdict"] == "BLOCKPAGE"

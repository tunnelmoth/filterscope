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
    assert "interference signals" in html
    assert "<script" not in html


def test_scan_options_quick():
    o = scan.ScanOptions.quick(label="x")
    assert not o.tor and not o.ech and "tor" not in o.steps
    assert scan.ScanOptions().steps == scan.ALL_STEPS

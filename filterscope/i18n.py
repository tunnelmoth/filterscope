"""Tiny i18n layer. `t("key", **params)` returns the string for the active language,
falling back to English. Language: explicit `set_lang()`, else config `lang`, else the
system locale (tr → Turkish), else English."""
from __future__ import annotations

import locale
import os

LANGS = ("en", "tr")
_lang = "en"

STRINGS = {
    "en": {
        # levels / techniques
        "level.clean": "clean", "level.light": "light", "level.moderate": "moderate", "level.heavy": "heavy", "level.severe": "severe",
        "tech.SNI-DPI": "TLS server-name inspection", "tech.RST-injection": "in-path RST injection (middlebox)",
        "tech.TLS-MITM": "TLS interception / SSL inspection", "tech.DNS-hijack": "DNS redirection to a block page",
        "tech.DNS-block": "DNS answers withheld (NXDOMAIN/empty)", "tech.DNS-intercept": "transparent port-53 DNS proxy",
        "tech.encrypted-DNS-block": "DoH/DoT blocked", "tech.NXDOMAIN-hijack": "NXDOMAIN hijacking / search redirect",
        "tech.block-page": "HTTP block page", "tech.HTTP-proxy": "transparent HTTP proxy / filter appliance",
        "tech.URL-keyword-filter": "URL keyword filtering", "tech.port-filter": "outbound TCP port filtering",
        "tech.UDP-block": "UDP egress blocked", "tech.QUIC-block": "QUIC / UDP-443 blocked", "tech.Tor-block": "Tor bootstrap blocked",
        "tech.SSH-block": "SSH egress blocked", "tech.IPv6-block": "IPv6 egress blocked", "tech.throttling": "bandwidth throttling",
        # summary
        "summary.clean": "No interference detected on {name}: {n} sites, all outbound probes and encrypted DNS behaved normally.",
        "summary.level": "{name} shows {level} filtering (score {score}/100).",
        "summary.affected": "{blocked} of {n} sites are affected, mostly {cats}.",
        "summary.techniques": "Techniques: {list}.",
        "summary.vendor": "Signatures point to {vendor}.",
        "summary.mitm": "HTTPS is decrypted by the network — treat every session as readable by the operator.",
        "summary.applayer": "The filter is application-layer only; SNI-hiding tunnels and ECH get through.",
        "summary.throttle": "Bandwidth to {targets} is throttled to a fraction of the baseline.",
        "net.this": "this network",
        # advice: VPN
        "adv.vpn.blocked": "VPN site/API blocked (SNI-DPI): {doms}",
        "adv.vpn.why": "  → the app can't log in / pull config = it FAILS at connect (API, not tunnel).",
        "adv.vpn.fix1": "  → fix: set the app up on another network and copy the config; or ECH/DoH;",
        "adv.vpn.fix2": "    or pick a provider whose API isn't blocked.",
        "adv.udp.untested": "UDP egress not tested in this scan (udp step skipped).",
        "adv.udp.blocked": "UDP egress blocked → WireGuard / OpenVPN-UDP FAIL.",
        "adv.udp.tcp": "  → switch to TCP: OpenVPN-TCP-443 (443 open: {p443}),",
        "adv.udp.alt": "    WireGuard-over-TCP (wstunnel/udp2raw), OpenConnect, Shadowsocks.",
        "adv.udp.open": "UDP egress open → WireGuard / OpenVPN-UDP worth trying.",
        "adv.udp.test": "  → definitive end-to-end test: filterscope wg --config <wg.conf>",
        "adv.vpn.noclear": "No clear blocking at the VPN layer; the issue may be config/provider side.",
        "adv.mitm": "TLS is being INTERCEPTED (SSL inspection): the network decrypts HTTPS with its own CA. Assume every page and login is readable by the operator; a VPN/tunnel is the only privacy.",
        "adv.encdns": "All DoH/DoT resolvers blocked → the network forces its own DNS; apps using encrypted DNS (Firefox DoH, Android Private DNS) will fail.",
        "adv.dnsint": "Port-53 DNS is transparently intercepted → 'use 8.8.8.8' does NOTHING here; only DoH/DoT (if reachable) or a tunnel gives honest DNS.",
        # advice: tunnels
        "adv.ssh.open": "SSH tunnel works → `ssh -D 1080 user@server`, then SOCKS5",
        "adv.ssh.open2": "  127.0.0.1:1080. All traffic inside SSH, DPI can't see it.",
        "adv.ssh.blocked": "SSH (22) blocked → use a server listening for SSH on 443.",
        "adv.443.sni": "443 open + SNI-DPI only → SNI-hiding tunnels PASS:",
        "adv.443.l1": "  • Shadowsocks / VLESS+TLS / Trojan-Go  (harmless or empty SNI)",
        "adv.443.l2": "  • wstunnel / websocket-over-443  (tunnel inside WebSocket)",
        "adv.443.l3": "  • OpenVPN-TCP-443 or WireGuard-over-TCP (udp2raw/wstunnel)",
        "adv.443.l4": "  • Cloudflare WARP (MASQUE/443) — engage.cloudflareclient.com",
        "adv.443.open": "443 open → TLS-based tunnels (Shadowsocks/VLESS) should work.",
        "adv.quic.open": "QUIC/UDP-443 open → HTTP/3-based tunnels (MASQUE, Hysteria, TUIC) pass.",
        "adv.quic.blocked": "QUIC/UDP-443 blocked → HTTP/3 disabled here; browsers fall back to TCP.",
        "adv.tor.ok": "Tor works directly → easiest tunnel: Tor Browser / `tor` SOCKS 9050.",
        "adv.tor.untested": "Tor not tested (--no-tor). If blocked, try obfs4/Snowflake bridge.",
        "adv.tor.missing": "Tor binary not found — install tor (or Tor Expert Bundle on Windows) to test.",
        "adv.tor.blocked": "Tor blocked directly → try obfs4 / Snowflake / meek bridge.",
        "adv.throttle": "Throttled: {targets} — video/game traffic will stall even though nothing is 'blocked'.",
        # sections / UI (shared by CLI, TUI, GUI)
        "ui.title": "NETWORK FILTERING TEST", "ui.network": "network", "ui.scan": "Scan", "ui.stop": "Stop", "ui.label": "label",
        "ui.profile": "profile", "ui.tor": "Tor test", "ui.sites": "Sites…", "ui.report": "Open report", "ui.html": "HTML…",
        "ui.json": "JSON…", "ui.card": "Share card…", "ui.compare": "Compare", "ui.folder": "Folder", "ui.ready": "ready",
        "ui.press_scan": "press Scan", "ui.scanning": "scanning…", "ui.intro": "Measures the filtering behaviour of this network with your own traffic and a clean allowlist of well-known sites.",
        "ui.tab.overview": "Overview", "ui.tab.sites": "Sites", "ui.tab.egress": "Egress & DNS", "ui.tab.history": "History", "ui.tab.about": "About",
        "ui.findings": "findings", "ui.advice": "diagnosis & advice", "ui.filter": "filter", "ui.affected_only": "affected only",
        "ui.select_row": "select a row for details", "ui.no_report": "Run a scan first.", "ui.done": "done in {s}s — {n} signals",
        "ui.verdict": "{level} filtering — score {score}/100 — {n} signals — confidence {conf}",
        "ui.vendor": "vendor signature: {vendor}", "ui.probing": "probing {done}/{total}", "ui.recheck": "re-checking {n} positives…",
        "ui.saved": "saved {name}", "ui.stopped": "stopped", "ui.update": "v{latest} available — click to download",
        "ui.vpn_diag": "VPN diagnosis", "ui.tunnel": "Tunnel / circumvention", "ui.summary": "SUMMARY", "ui.signals": "{n} interference signals",
        "ui.no_interference": "No clear interference detected.", "ui.ech_bypass": "reachable via ECH (SNI-DPI bypassed):",
        "ui.transient": "transient (not reproduced on retry, ignored):", "ui.confirmed": "confirmed on retry",
        "ui.export_timeline": "Export timeline HTML…", "ui.no_history": "No history yet.", "ui.no_prev": "No earlier stored scan of this network.",
        "ui.throttle": "throughput", "ui.language": "language", "ui.save": "Save",
        "conf.high": "high", "conf.medium": "medium", "conf.low": "low",
        # html report
        "html.title": "filterscope report", "html.summary": "Summary", "html.findings": "Findings", "html.impact": "Impact by category",
        "html.sites": "Sites — DNS / TLS-SNI / block page / ECH", "html.method": "Method", "html.no_interference": "No clear interference.",
        "html.badge_signals": "{n} interference signals", "html.badge_clean": "no interference technique detected",
        "html.vantage": "vantage", "html.confidence": "confidence", "html.blocked_of": "{b}/{t} blocked",
        # card
        "card.title": "Network filtering score", "card.affected": "{b} of {n} sites affected", "card.clean": "no interference detected",
        "card.footer": "measured with filterscope · tunnelmoth.github.io/filterscope",
    },
    "tr": {
        "level.clean": "temiz", "level.light": "hafif", "level.moderate": "orta", "level.heavy": "ağır", "level.severe": "şiddetli",
        "tech.SNI-DPI": "TLS sunucu-adı denetimi", "tech.RST-injection": "yol üstünde RST enjeksiyonu (ara cihaz)",
        "tech.TLS-MITM": "TLS'in kırılması / SSL denetimi", "tech.DNS-hijack": "engel sayfasına DNS yönlendirmesi",
        "tech.DNS-block": "DNS cevabı yutuluyor (NXDOMAIN/boş)", "tech.DNS-intercept": "port-53'e transparan DNS müdahalesi",
        "tech.encrypted-DNS-block": "DoH/DoT engelli", "tech.NXDOMAIN-hijack": "NXDOMAIN kaçırma / arama yönlendirmesi",
        "tech.block-page": "HTTP engel sayfası", "tech.HTTP-proxy": "transparan HTTP proxy / filtre cihazı",
        "tech.URL-keyword-filter": "URL anahtar-kelime filtresi", "tech.port-filter": "giden TCP port filtresi",
        "tech.UDP-block": "UDP çıkışı engelli", "tech.QUIC-block": "QUIC / UDP-443 engelli", "tech.Tor-block": "Tor bootstrap engelli",
        "tech.SSH-block": "SSH çıkışı engelli", "tech.IPv6-block": "IPv6 çıkışı engelli", "tech.throttling": "bant genişliği kısıtlaması",
        "summary.clean": "{name} üzerinde müdahale saptanmadı: {n} site, tüm giden sondalar ve şifreli DNS normal davrandı.",
        "summary.level": "{name} {level} filtreleme gösteriyor (skor {score}/100).",
        "summary.affected": "{n} sitenin {blocked} tanesi etkilenmiş; çoğunlukla {cats}.",
        "summary.techniques": "Teknikler: {list}.",
        "summary.vendor": "İmzalar {vendor} işaret ediyor.",
        "summary.mitm": "HTTPS ağ tarafından çözülüyor — her oturumu işletmecinin okuyabildiğini varsay.",
        "summary.applayer": "Filtre yalnızca uygulama katmanında; SNI gizleyen tüneller ve ECH geçer.",
        "summary.throttle": "{targets} yönüne bant genişliği taban değerin çok altına kısılmış.",
        "net.this": "bu ağ",
        "adv.vpn.blocked": "VPN sitesi/API'si engelli (SNI-DPI): {doms}",
        "adv.vpn.why": "  → uygulama giriş yapamaz / config çekemez = bağlanırken TAKILIR (API, tünel değil).",
        "adv.vpn.fix1": "  → çözüm: uygulamayı başka ağda kur, config'i kopyala; ya da ECH/DoH;",
        "adv.vpn.fix2": "    ya da API'si engellenmemiş bir sağlayıcı seç.",
        "adv.udp.untested": "UDP çıkışı bu taramada test edilmedi (udp adımı atlandı).",
        "adv.udp.blocked": "UDP çıkışı engelli → WireGuard / OpenVPN-UDP ÇALIŞMAZ.",
        "adv.udp.tcp": "  → TCP'ye geç: OpenVPN-TCP-443 (443 açık: {p443}),",
        "adv.udp.alt": "    WireGuard-over-TCP (wstunnel/udp2raw), OpenConnect, Shadowsocks.",
        "adv.udp.open": "UDP çıkışı açık → WireGuard / OpenVPN-UDP denemeye değer.",
        "adv.udp.test": "  → kesin uçtan uca test: filterscope wg --config <wg.conf>",
        "adv.vpn.noclear": "VPN katmanında net bir engel yok; sorun config/sağlayıcı tarafında olabilir.",
        "adv.mitm": "TLS KIRILIYOR (SSL denetimi): ağ HTTPS'i kendi sertifikasıyla çözüyor. Her sayfayı ve girişi işletmecinin okuyabildiğini varsay; tek mahremiyet VPN/tünel.",
        "adv.encdns": "Tüm DoH/DoT çözücüler engelli → ağ kendi DNS'ini dayatıyor; şifreli DNS kullanan uygulamalar (Firefox DoH, Android Private DNS) çalışmaz.",
        "adv.dnsint": "Port-53 DNS transparan biçimde yakalanıyor → '8.8.8.8 kullan' burada HİÇBİR işe yaramaz; dürüst DNS için yalnız DoH/DoT (erişilebiliyorsa) ya da tünel.",
        "adv.ssh.open": "SSH tüneli çalışır → `ssh -D 1080 kullanici@sunucu`, sonra SOCKS5",
        "adv.ssh.open2": "  127.0.0.1:1080. Tüm trafik SSH içinde, DPI göremez.",
        "adv.ssh.blocked": "SSH (22) engelli → 443'te SSH dinleyen bir sunucu kullan.",
        "adv.443.sni": "443 açık + yalnız SNI-DPI → SNI gizleyen tüneller GEÇER:",
        "adv.443.l1": "  • Shadowsocks / VLESS+TLS / Trojan-Go  (zararsız ya da boş SNI)",
        "adv.443.l2": "  • wstunnel / websocket-over-443  (WebSocket içinde tünel)",
        "adv.443.l3": "  • OpenVPN-TCP-443 ya da WireGuard-over-TCP (udp2raw/wstunnel)",
        "adv.443.l4": "  • Cloudflare WARP (MASQUE/443) — engage.cloudflareclient.com",
        "adv.443.open": "443 açık → TLS tabanlı tüneller (Shadowsocks/VLESS) çalışmalı.",
        "adv.quic.open": "QUIC/UDP-443 açık → HTTP/3 tabanlı tüneller (MASQUE, Hysteria, TUIC) geçer.",
        "adv.quic.blocked": "QUIC/UDP-443 engelli → HTTP/3 burada kapalı; tarayıcılar TCP'ye düşer.",
        "adv.tor.ok": "Tor doğrudan çalışıyor → en kolay tünel: Tor Browser / `tor` SOCKS 9050.",
        "adv.tor.untested": "Tor test edilmedi (--no-tor). Engelliyse obfs4/Snowflake köprüsü dene.",
        "adv.tor.missing": "Tor binary'si yok — test için tor (Windows'ta Tor Expert Bundle) kur.",
        "adv.tor.blocked": "Tor doğrudan engelli → obfs4 / Snowflake / meek köprüsü dene.",
        "adv.throttle": "Kısıtlanmış: {targets} — hiçbir şey 'engelli' olmasa da video/oyun trafiği takılır.",
        "ui.title": "AĞ FİLTRELEME TESTİ", "ui.network": "ağ", "ui.scan": "Tara", "ui.stop": "Durdur", "ui.label": "etiket",
        "ui.profile": "profil", "ui.tor": "Tor testi", "ui.sites": "Siteler…", "ui.report": "Raporu aç", "ui.html": "HTML…",
        "ui.json": "JSON…", "ui.card": "Paylaşım kartı…", "ui.compare": "Karşılaştır", "ui.folder": "Klasör", "ui.ready": "hazır",
        "ui.press_scan": "Tara'ya bas", "ui.scanning": "taranıyor…", "ui.intro": "Bu ağın filtreleme davranışını kendi trafiğinle ve temiz, tanınmış site listesiyle ölçer.",
        "ui.tab.overview": "Özet", "ui.tab.sites": "Siteler", "ui.tab.egress": "Çıkış ve DNS", "ui.tab.history": "Geçmiş", "ui.tab.about": "Hakkında",
        "ui.findings": "bulgular", "ui.advice": "tanı ve tavsiye", "ui.filter": "filtre", "ui.affected_only": "yalnız etkilenenler",
        "ui.select_row": "ayrıntı için bir satır seç", "ui.no_report": "Önce bir tarama yap.", "ui.done": "{s} s'de bitti — {n} sinyal",
        "ui.verdict": "{level} filtreleme — skor {score}/100 — {n} sinyal — güven {conf}",
        "ui.vendor": "üretici imzası: {vendor}", "ui.probing": "sondalanıyor {done}/{total}", "ui.recheck": "{n} pozitif yeniden kontrol ediliyor…",
        "ui.saved": "kaydedildi: {name}", "ui.stopped": "durduruldu", "ui.update": "v{latest} çıktı — indirmek için tıkla",
        "ui.vpn_diag": "VPN tanısı", "ui.tunnel": "Tünel / aşma", "ui.summary": "ÖZET", "ui.signals": "{n} müdahale sinyali",
        "ui.no_interference": "Net bir müdahale saptanmadı.", "ui.ech_bypass": "ECH ile erişilebilir (SNI-DPI aşılır):",
        "ui.transient": "geçici (tekrarda görülmedi, yok sayıldı):", "ui.confirmed": "tekrarda doğrulandı",
        "ui.export_timeline": "Zaman çizelgesi HTML…", "ui.no_history": "Henüz geçmiş yok.", "ui.no_prev": "Bu ağın daha eski kayıtlı taraması yok.",
        "ui.throttle": "hız", "ui.language": "dil", "ui.save": "Kaydet",
        "conf.high": "yüksek", "conf.medium": "orta", "conf.low": "düşük",
        "html.title": "filterscope raporu", "html.summary": "Özet", "html.findings": "Bulgular", "html.impact": "Kategoriye göre etki",
        "html.sites": "Siteler — DNS / TLS-SNI / engel sayfası / ECH", "html.method": "Yöntem", "html.no_interference": "Net bir müdahale yok.",
        "html.badge_signals": "{n} müdahale sinyali", "html.badge_clean": "müdahale tekniği saptanmadı",
        "html.vantage": "bakış noktası", "html.confidence": "güven", "html.blocked_of": "{b}/{t} engelli",
        "card.title": "Ağ filtreleme skoru", "card.affected": "{n} sitenin {b} tanesi etkilenmiş", "card.clean": "müdahale saptanmadı",
        "card.footer": "filterscope ile ölçüldü · tunnelmoth.github.io/filterscope",
    },
}


def detect() -> str:
    env = os.environ.get("FILTERSCOPE_LANG", "").lower()
    if env[:2] in LANGS:
        return env[:2]
    try:
        from . import config
        cfg = config.load()
        if str(cfg.get("lang", ""))[:2] in LANGS and cfg.get("lang"):
            return str(cfg["lang"])[:2]
    except Exception:
        pass
    try:
        loc = (locale.getlocale()[0] or os.environ.get("LANG", "") or "").lower()
        if loc.startswith("tr"):
            return "tr"
    except Exception:
        pass
    return "en"


def set_lang(lang: str | None):
    global _lang
    _lang = lang[:2] if lang and lang[:2] in LANGS else detect()
    return _lang


def get_lang() -> str:
    return _lang


def t(key: str, **kw) -> str:
    s = STRINGS.get(_lang, {}).get(key) or STRINGS["en"].get(key) or key
    try:
        return s.format(**kw) if kw else s
    except (KeyError, IndexError):
        return s


def upper(s: str) -> str:
    """Locale-aware upper: Turkish dotted/dotless i."""
    if _lang == "tr":
        s = s.replace("i", "İ").replace("ı", "I")
    return s.upper()


def level_name(level: str, up: bool = False) -> str:
    n = t(f"level.{level}")
    return upper(n) if up else n


def tech_label(tech: str) -> str:
    return t(f"tech.{tech}")


set_lang(None)

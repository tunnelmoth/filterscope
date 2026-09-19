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
        "summary.mitm": "The network decrypts HTTPS. Treat every session as readable by the operator.",
        "summary.applayer": "The filter works on the application layer only. Tunnels that hide the SNI and ECH get through.",
        "summary.throttle": "Bandwidth to {targets} is throttled to a fraction of the baseline.",
        "net.this": "this network",
        # advice: VPN
        "adv.vpn.blocked": "VPN site/API blocked (SNI-DPI): {doms}",
        "adv.vpn.why": "  → the app cannot log in or fetch its config, so it fails at connect. The API is blocked, the tunnel may be fine.",
        "adv.vpn.fix1": "  → fix: set the app up on another network and copy the config. ECH or DoH can also help.",
        "adv.vpn.fix2": "    Or choose a provider whose API is not blocked.",
        "adv.udp.untested": "UDP egress not tested in this scan (udp step skipped).",
        "adv.udp.blocked": "UDP egress is blocked → WireGuard and OpenVPN over UDP fail.",
        "adv.udp.tcp": "  → switch to TCP: OpenVPN-TCP-443 (443 open: {p443}),",
        "adv.udp.alt": "    WireGuard-over-TCP (wstunnel/udp2raw), OpenConnect, Shadowsocks.",
        "adv.udp.open": "UDP egress is open → WireGuard and OpenVPN over UDP are worth a try.",
        "adv.udp.test": "  → definitive end-to-end test: filterscope wg --config <wg.conf>",
        "adv.vpn.noclear": "No clear blocking at the VPN layer. The problem is probably on the config or provider side.",
        "adv.mitm": "TLS is INTERCEPTED (SSL inspection). The network decrypts HTTPS with its own CA. Assume that the operator can read every page and every login. Only a VPN or a tunnel gives privacy here.",
        "adv.encdns": "All DoH and DoT resolvers are blocked → the network forces its own DNS. Apps that use encrypted DNS (Firefox DoH, Android Private DNS) fail.",
        "adv.dnsint": "Port-53 DNS is intercepted → a change to 8.8.8.8 has no effect here. Only DoH or DoT (when reachable) or a tunnel gives honest DNS.",
        # advice: tunnels
        "adv.ssh.open": "SSH tunnel works → `ssh -D 1080 user@server`, then SOCKS5",
        "adv.ssh.open2": "  127.0.0.1:1080. All traffic travels inside SSH, so DPI cannot see it.",
        "adv.ssh.blocked": "SSH (22) blocked → use a server listening for SSH on 443.",
        "adv.443.sni": "443 open + SNI-DPI only → SNI-hiding tunnels PASS:",
        "adv.443.l1": "  • Shadowsocks / VLESS+TLS / Trojan-Go  (harmless or empty SNI)",
        "adv.443.l2": "  • wstunnel / websocket-over-443  (tunnel inside WebSocket)",
        "adv.443.l3": "  • OpenVPN-TCP-443 or WireGuard-over-TCP (udp2raw/wstunnel)",
        "adv.443.l4": "  • Cloudflare WARP (MASQUE/443) — engage.cloudflareclient.com",
        "adv.443.open": "443 open → TLS-based tunnels (Shadowsocks/VLESS) should work.",
        "adv.quic.open": "QUIC/UDP-443 open → HTTP/3-based tunnels (MASQUE, Hysteria, TUIC) pass.",
        "adv.quic.blocked": "QUIC/UDP-443 is blocked → HTTP/3 does not work here. Browsers fall back to TCP.",
        "adv.tor.ok": "Tor works directly → easiest tunnel: Tor Browser / `tor` SOCKS 9050.",
        "adv.tor.untested": "Tor not tested (--no-tor). If blocked, try obfs4/Snowflake bridge.",
        "adv.tor.missing": "No tor binary found. Install tor (the Tor Expert Bundle on Windows) to run this test.",
        "adv.tor.blocked": "Tor blocked directly → try obfs4 / Snowflake / meek bridge.",
        "adv.throttle": "Throttled: {targets}. Video and game traffic stalls, although nothing is blocked.",
        # sections / UI (shared by CLI, TUI, GUI)
        "ui.title": "NETWORK FILTERING TEST", "ui.network": "network", "ui.scan": "Scan", "ui.stop": "Stop", "ui.label": "label",
        "ui.profile": "profile", "ui.tor": "Tor test", "ui.sites": "Sites…", "ui.report": "Open report", "ui.html": "HTML…",
        "ui.json": "JSON…", "ui.card": "Share card…", "ui.compare": "Compare", "ui.folder": "Folder", "ui.ready": "ready",
        "ui.press_scan": "press Scan", "ui.scanning": "scanning…", "ui.intro": "Measures the filtering behaviour of this network with your own traffic and a clean allowlist of well-known sites.",
        "ui.tab.overview": "Overview", "ui.tab.sites": "Sites", "ui.tab.egress": "Egress & DNS", "ui.tab.history": "History", "ui.tab.about": "About",
        "ui.findings": "findings", "ui.advice": "diagnosis & advice", "ui.filter": "filter", "ui.affected_only": "affected only",
        "ui.select_row": "select a row for details", "ui.no_report": "Run a scan first.", "ui.done": "done in {s} s, {n} signals",
        "ui.verdict": "{level} filtering · score {score}/100 · {n} signals · confidence {conf}",
        "ui.vendor": "vendor signature: {vendor}", "ui.probing": "probing {done}/{total}", "ui.recheck": "re-checking {n} positives…",
        "ui.saved": "saved {name}", "ui.stopped": "stopped", "ui.update": "v{latest} is available. Click to download.",
        "ui.vpn_diag": "VPN diagnosis", "ui.tunnel": "Tunnel / circumvention", "ui.summary": "SUMMARY", "ui.signals": "{n} interference signals",
        "ui.no_interference": "No clear interference detected.", "ui.ech_bypass": "reachable via ECH (SNI-DPI bypassed):",
        "ui.transient": "transient (not reproduced on retry, ignored):", "ui.confirmed": "confirmed on retry",
        "ui.export_timeline": "Export timeline HTML…", "ui.no_history": "No history yet.", "ui.no_prev": "No earlier stored scan of this network.",
        "ui.throttle": "throughput", "ui.language": "language", "ui.save": "Save",
        "conf.high": "high", "conf.medium": "medium", "conf.low": "low",
        "chk.title": "Check a service", "chk.hint": "e.g. valorant, discord, roblox, youtube, whatsapp…", "chk.go": "Check",
        "chk.unknown": "Unknown service '{q}'. Known: {known}", "chk.ok": "{name}: works on this network. All endpoints, ports and the CDN speed are normal.",
        "chk.blocked": "{name}: BLOCKED on this network.", "chk.partial": "{name}: PARTIALLY blocked. Some endpoints or ports fail.",
        "chk.throttled": "{name}: reachable but THROTTLED. Its CDN gets a fraction of the line speed.",
        "chk.reasons": "why", "chk.endpoints": "endpoints", "chk.ports": "TCP ports (egress)", "chk.udp": "UDP egress",
        "chk.download": "download from the service's CDN", "chk.baseline": "baseline (Cloudflare)", "chk.udp_note": "UDP game and voice ports cannot be verified without the game. Generic UDP egress is shown instead.",
        "tray.open": "Open window", "tray.scan": "Scan now", "tray.autoscan": "Auto-scan when the network changes", "tray.quit": "Quit",
        "tray.blocked_title": "{name}: blocked here", "tray.net_changed": "Network changed: {name}. Scanning…", "tray.start": "Start in the tray",
        "ui.view": "View", "ui.theme": "Theme", "ui.theme.system": "System", "ui.theme.light": "Light", "ui.theme.dark": "Dark",
        "ui.contrast": "High contrast", "ui.textsize": "Text size", "ui.restart_note": "Saved. Restart filterscope to apply.",
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
        "tech.TLS-MITM": "HTTPS'in kırılması (SSL denetimi)", "tech.DNS-hijack": "engel sayfasına DNS yönlendirmesi",
        "tech.DNS-block": "DNS cevabı yutuluyor (NXDOMAIN/boş)", "tech.DNS-intercept": "port 53 DNS'e transparan müdahale",
        "tech.encrypted-DNS-block": "DoH/DoT engelli", "tech.NXDOMAIN-hijack": "NXDOMAIN kaçırma / arama yönlendirmesi",
        "tech.block-page": "HTTP engel sayfası", "tech.HTTP-proxy": "transparan HTTP proxy / filtre cihazı",
        "tech.URL-keyword-filter": "URL anahtar-kelime filtresi", "tech.port-filter": "giden TCP portları engelli",
        "tech.UDP-block": "UDP dışa erişimi engelli", "tech.QUIC-block": "QUIC / UDP-443 engelli", "tech.Tor-block": "Tor bootstrap engelli",
        "tech.SSH-block": "SSH dışa erişimi engelli", "tech.IPv6-block": "IPv6 dışa erişimi engelli", "tech.throttling": "bant genişliği kısıtlaması",
        "summary.clean": "{name}: müdahale saptanmadı. {n} site, tüm dışa erişim testleri ve şifreli DNS normal davrandı.",
        "summary.level": "{name}: {level} filtreleme (skor {score}/100).",
        "summary.affected": "{n} sitenin {blocked} tanesi etkilenmiş, çoğu şu kategorilerde: {cats}.",
        "summary.techniques": "Teknikler: {list}.",
        "summary.vendor": "İmzalar şu ürüne işaret ediyor: {vendor}.",
        "summary.mitm": "Ağ HTTPS'i çözüyor. Her oturumu işletmecinin okuyabildiğini varsay.",
        "summary.applayer": "Filtre yalnızca uygulama katmanında çalışıyor. SNI gizleyen tüneller ve ECH geçer.",
        "summary.throttle": "{targets} yönünde bant genişliği referans değerin çok altına kısılmış.",
        "net.this": "bu ağ",
        "adv.vpn.blocked": "VPN sitesi/API'si engelli (SNI-DPI): {doms}",
        "adv.vpn.why": "  → uygulama giriş yapamaz veya config çekemez, bu yüzden bağlanırken takılır. Engelli olan API, tünel sağlam olabilir.",
        "adv.vpn.fix1": "  → çözüm: uygulamayı başka ağda kur ve config'i kopyala. ECH veya DoH da yardımcı olabilir.",
        "adv.vpn.fix2": "    Ya da API'si engellenmemiş bir sağlayıcı seç.",
        "adv.udp.untested": "UDP dışa erişimi bu taramada test edilmedi (udp adımı atlandı).",
        "adv.udp.blocked": "UDP dışa erişimi engelli → WireGuard ve OpenVPN-UDP çalışmaz.",
        "adv.udp.tcp": "  → TCP'ye geç: OpenVPN-TCP-443 (443 açık: {p443}),",
        "adv.udp.alt": "    WireGuard-over-TCP (wstunnel/udp2raw), OpenConnect, Shadowsocks.",
        "adv.udp.open": "UDP dışa erişimi açık → WireGuard ve OpenVPN-UDP denemeye değer.",
        "adv.udp.test": "  → kesin uçtan uca test: filterscope wg --config <wg.conf>",
        "adv.vpn.noclear": "VPN katmanında net bir engel yok. Sorun büyük olasılıkla config veya sağlayıcı tarafında.",
        "adv.mitm": "TLS KIRILIYOR (SSL denetimi). Ağ HTTPS'i kendi sertifikasıyla çözüyor. İşletmecinin her sayfayı ve her girişi okuyabildiğini varsay. Burada mahremiyeti yalnızca bir VPN veya tünel sağlar.",
        "adv.encdns": "Tüm DoH ve DoT çözücüler engelli → ağ kendi DNS'ini dayatıyor. Şifreli DNS kullanan uygulamalar (Firefox DoH, Android Private DNS) çalışmaz.",
        "adv.dnsint": "Port-53 DNS yakalanıyor → 8.8.8.8'e geçmenin burada etkisi yok. Dürüst DNS için yalnız DoH veya DoT (erişilebiliyorsa) ya da bir tünel var.",
        "adv.ssh.open": "SSH tüneli çalışır → `ssh -D 1080 kullanici@sunucu`, sonra SOCKS5",
        "adv.ssh.open2": "  127.0.0.1:1080. Tüm trafik SSH içinde gider, bu yüzden DPI göremez.",
        "adv.ssh.blocked": "SSH (22) engelli → 443'te SSH dinleyen bir sunucu kullan.",
        "adv.443.sni": "443 açık + yalnız SNI-DPI → SNI gizleyen tüneller GEÇER:",
        "adv.443.l1": "  • Shadowsocks / VLESS+TLS / Trojan-Go  (zararsız ya da boş SNI)",
        "adv.443.l2": "  • wstunnel / websocket-over-443  (WebSocket içinde tünel)",
        "adv.443.l3": "  • OpenVPN-TCP-443 ya da WireGuard-over-TCP (udp2raw/wstunnel)",
        "adv.443.l4": "  • Cloudflare WARP (MASQUE/443) — engage.cloudflareclient.com",
        "adv.443.open": "443 açık → TLS tabanlı tüneller (Shadowsocks/VLESS) çalışmalı.",
        "adv.quic.open": "QUIC/UDP-443 açık → HTTP/3 tabanlı tüneller (MASQUE, Hysteria, TUIC) geçer.",
        "adv.quic.blocked": "QUIC/UDP-443 engelli → HTTP/3 burada çalışmaz. Tarayıcılar TCP'ye düşer.",
        "adv.tor.ok": "Tor doğrudan çalışıyor → en kolay tünel: Tor Browser / `tor` SOCKS 9050.",
        "adv.tor.untested": "Tor test edilmedi (--no-tor). Engelliyse obfs4/Snowflake köprüsü dene.",
        "adv.tor.missing": "Tor binary'si bulunamadı. Bu test için tor (Windows'ta Tor Expert Bundle) kur.",
        "adv.tor.blocked": "Tor doğrudan engelli → obfs4 / Snowflake / meek köprüsü dene.",
        "adv.throttle": "Kısıtlanmış: {targets}. Hiçbir şey engelli olmasa da video ve oyun trafiği takılır.",
        "ui.title": "AĞ FİLTRELEME TESTİ", "ui.network": "ağ", "ui.scan": "Tara", "ui.stop": "Durdur", "ui.label": "etiket",
        "ui.profile": "profil", "ui.tor": "Tor testi", "ui.sites": "Siteler…", "ui.report": "Raporu aç", "ui.html": "HTML…",
        "ui.json": "JSON…", "ui.card": "Paylaşım kartı…", "ui.compare": "Karşılaştır", "ui.folder": "Klasör", "ui.ready": "hazır",
        "ui.press_scan": "Tara'ya bas", "ui.scanning": "taranıyor…", "ui.intro": "Bu ağın filtreleme davranışını kendi trafiğinle ve temiz, tanınmış site listesiyle ölçer.",
        "ui.tab.overview": "Özet", "ui.tab.sites": "Siteler", "ui.tab.egress": "Dışa erişim ve DNS", "ui.tab.history": "Geçmiş", "ui.tab.about": "Hakkında",
        "ui.findings": "bulgular", "ui.advice": "tanı ve tavsiye", "ui.filter": "filtre", "ui.affected_only": "yalnız etkilenenler",
        "ui.select_row": "ayrıntı için bir satır seç", "ui.no_report": "Önce bir tarama yap.", "ui.done": "{s} s'de bitti, {n} bulgu",
        "ui.verdict": "{level} filtreleme · skor {score}/100 · {n} bulgu · güven {conf}",
        "ui.vendor": "filtre ürünü imzası: {vendor}", "ui.probing": "test ediliyor {done}/{total}", "ui.recheck": "{n} bulgu yeniden kontrol ediliyor…",
        "ui.saved": "kaydedildi: {name}", "ui.stopped": "durduruldu", "ui.update": "v{latest} çıktı. İndirmek için tıkla.",
        "ui.vpn_diag": "VPN tanısı", "ui.tunnel": "Tünel / erişim yolları", "ui.summary": "ÖZET", "ui.signals": "{n} müdahale bulgusu",
        "ui.no_interference": "Net bir müdahale saptanmadı.", "ui.ech_bypass": "ECH ile erişilebilir (SNI-DPI aşılır):",
        "ui.transient": "geçici (tekrarda görülmedi, yok sayıldı):", "ui.confirmed": "tekrarda doğrulandı",
        "ui.export_timeline": "Zaman çizelgesi HTML…", "ui.no_history": "Henüz geçmiş yok.", "ui.no_prev": "Bu ağın daha eski kayıtlı taraması yok.",
        "ui.throttle": "hız", "ui.language": "dil", "ui.save": "Kaydet",
        "conf.high": "yüksek", "conf.medium": "orta", "conf.low": "düşük",
        "chk.title": "Bir servisi sorgula", "chk.hint": "örn. valorant, discord, roblox, youtube, whatsapp…", "chk.go": "Sorgula",
        "chk.unknown": "Bilinmeyen servis '{q}'. Bilinenler: {known}", "chk.ok": "{name}: bu ağda çalışıyor. Tüm uç noktalar, portlar ve CDN hızı normal.",
        "chk.blocked": "{name}: bu ağda ENGELLİ.", "chk.partial": "{name}: KISMEN engelli. Bazı uç noktalar veya portlar çalışmıyor.",
        "chk.throttled": "{name}: erişilebilir ama KISITLI. CDN'i hat hızının çok altında.",
        "chk.reasons": "neden", "chk.endpoints": "uç noktalar", "chk.ports": "TCP portları (dışa erişim)", "chk.udp": "UDP dışa erişimi",
        "chk.download": "servisin CDN'inden indirme", "chk.baseline": "referans (Cloudflare)", "chk.udp_note": "UDP oyun ve ses portları oyun olmadan doğrulanamaz. Bunun yerine genel UDP dışa erişimi gösteriliyor.",
        "tray.open": "Pencereyi aç", "tray.scan": "Şimdi tara", "tray.autoscan": "Ağ değişince otomatik tara", "tray.quit": "Çık",
        "tray.blocked_title": "{name}: burada engelli", "tray.net_changed": "Ağ değişti: {name}. Taranıyor…", "tray.start": "Tepside başlat",
        "ui.view": "Görünüm", "ui.theme": "Tema", "ui.theme.system": "Sistem", "ui.theme.light": "Açık", "ui.theme.dark": "Koyu",
        "ui.contrast": "Yüksek kontrast", "ui.textsize": "Yazı boyutu", "ui.restart_note": "Kaydedildi. Uygulamak için filterscope'u yeniden başlat.",
        "html.title": "filterscope raporu", "html.summary": "Özet", "html.findings": "Bulgular", "html.impact": "Kategoriye göre etki",
        "html.sites": "Siteler — DNS / TLS-SNI / engel sayfası / ECH", "html.method": "Yöntem", "html.no_interference": "Net bir müdahale yok.",
        "html.badge_signals": "{n} müdahale bulgusu", "html.badge_clean": "müdahale tekniği saptanmadı",
        "html.vantage": "konum", "html.confidence": "güven", "html.blocked_of": "{b}/{t} engelli",
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

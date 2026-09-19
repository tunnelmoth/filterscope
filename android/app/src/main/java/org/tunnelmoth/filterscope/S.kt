package org.tunnelmoth.filterscope

/** UI labels, EN/TR by system locale (engine text is localized on the Python side). */
object S {
    private val tr = java.util.Locale.getDefault().language == "tr"
    private fun p(en: String, trs: String) = if (tr) trs else en
    val scan get() = p("Scan", "Tara"); val stop get() = p("Stop", "Durdur"); val label get() = p("label", "etiket")
    val share get() = p("Share", "Paylaş"); val openReport get() = p("Open report", "Raporu aç"); val card get() = p("Card", "Kart")
    val ownDomains get() = p("own domains", "kendi domainlerin"); val ownDomainsHint get() = p("extra domains, comma or newline separated", "ek domainler; virgül veya satırla ayır")
    val set get() = p("(set)", "(ayarlı)")
    val tabOverview get() = p("Overview", "Özet"); val tabSites get() = p("Sites", "Siteler"); val tabEgress get() = p("Egress", "Çıkış"); val tabHistory get() = p("History", "Geçmiş")
    val findings get() = p("findings", "bulgular"); val comparePrev get() = p("Compare with previous", "Öncekiyle karşılaştır")
    val noFindings get() = p("no findings yet", "henüz bulgu yok"); val filter get() = p("filter", "filtre"); val affectedOnly get() = p("affected only", "yalnız etkilenenler")
    val shown get() = p("shown", "gösteriliyor"); val affected get() = p("affected", "etkilenmiş"); val pending get() = p("pending", "bekliyor")
    val noProbes get() = p("no probes yet", "henüz sonda yok"); val noHistory get() = p("no history yet. Run a scan.", "henüz geçmiş yok. Bir tarama yap.")
    val scanning get() = p("scanning…", "taranıyor…"); val pressScan get() = p("press Scan", "Tara'ya bas"); val ready get() = p("ready", "hazır")
    val intro get() = p("Measures the filtering behaviour of this network with your own traffic and a clean allowlist of well-known sites.",
        "Bu ağın filtreleme davranışını kendi trafiğinle ve temiz, tanınmış site listesiyle ölçer.")
    fun verdict(level: String, n: Int, conf: String) = p("${levelName(level).uppercase()} filtering · $n signals · confidence $conf",
        "${levelName(level).uppercase(java.util.Locale("tr"))} filtreleme · $n sinyal · güven $conf")
    fun levelName(l: String) = if (!tr) l else mapOf("clean" to "temiz", "light" to "hafif", "moderate" to "orta", "heavy" to "ağır", "severe" to "şiddetli")[l] ?: l
    fun done(s: Int, n: Int) = p("done in $s s, $n signals", "$s s'de bitti, $n sinyal")
    fun probing(a: Int, b: Int) = p("probing $a/$b", "sondalanıyor $a/$b")
    fun recheck(n: Int) = p("re-checking $n positives…", "$n pozitif yeniden kontrol ediliyor…")
    fun update(v: String) = p("v$v is available. Tap to download.", "v$v çıktı. İndirmek için dokun.")
    val vendor get() = p("vendor signature", "üretici imzası"); val score get() = p("score", "skor"); val blocks get() = p("blocks", "engel")
    val noChange get() = p("no change", "değişiklik yok"); val stopped get() = p("stopped", "durduruldu"); val failed get() = p("failed", "başarısız")
    val noEarlier get() = p("no earlier stored scan of this network", "bu ağın daha eski kayıtlı taraması yok")
    val newBlock get() = p("new block", "yeni engel"); val lifted get() = p("lifted", "kalktı")
    val includeNet get() = p("Include network name on the card?", "Kartta ağ adı görünsün mü?"); val yes get() = p("Yes", "Evet"); val no get() = p("No", "Hayır")
    val widgetTap get() = p("tap to scan", "taramak için dokun"); val widgetNone get() = p("no scan yet", "henüz tarama yok")
    val tabCheck get() = p("Check", "Sorgula"); val checkHint get() = p("service: valorant, discord, roblox, youtube…", "servis: valorant, discord, roblox, youtube…")
    val check get() = p("Check", "Sorgula"); val why get() = p("why", "neden"); val endpoints get() = p("endpoints", "uç noktalar")
    val ports get() = p("TCP ports (egress)", "TCP portları (çıkış)"); val udp get() = p("UDP egress", "UDP çıkışı")
    val download get() = p("download from the service's CDN", "servisin CDN'inden indirme"); val baseline get() = p("baseline", "taban")
    val checking get() = p("checking…", "sorgulanıyor…")
}

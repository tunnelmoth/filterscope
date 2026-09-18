package org.tunnelmoth.filterscope

import android.app.Application
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.chaquo.python.PyObject
import com.chaquo.python.Python
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/** Java-side listener that Python calls for every scan event. */
interface ScanListener {
    fun onEvent(kind: String, payload: String)
}

data class SiteRow(
    val domain: String, val category: String, val dns: String, val sni: String, val block: String,
    val ech: String, val ms: Int, val flagged: Boolean, val transient: Boolean, val detail: String,
)

data class ProbeRow(val probe: String, val status: String, val detail: String, val bad: Boolean)

data class HistoryRow(val ts: String, val net: String, val score: String, val blocks: Int, val changes: String)

data class UiState(
    val ready: Boolean = false,
    val version: String = "",
    val scanning: Boolean = false,
    val status: String = "ready",
    val progress: Float = 0f,
    val netLine: String = "",
    val label: String = "",
    val profile: String = "full",
    val domains: String = "",
    val profiles: List<String> = listOf("full", "quick", "school", "isp", "vpn"),
    val score: Int = -1,
    val level: String = "",
    val summary: String = "Measures the filtering behaviour of this network with your own traffic and a clean allowlist of well-known sites.",
    val techniques: List<Pair<String, String>> = emptyList(),
    val vendor: String = "",
    val confidence: String = "",
    val findings: List<Pair<String, String>> = emptyList(),   // text, colour tag (r/y/g/n)
    val advice: List<Pair<String, String>> = emptyList(),      // text, colour tag
    val sites: List<SiteRow> = emptyList(),
    val sitesExpected: Int = 0,
    val probes: List<ProbeRow> = emptyList(),
    val history: List<HistoryRow> = emptyList(),
    val reportJson: String? = null,
    val error: String? = null,
)

private val NEUTRAL = setOf("ok", "?", "no-dns", "unreachable", "")

class ScanViewModel(app: Application) : AndroidViewModel(app) {
    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state

    private val py: Python by lazy { Python.getInstance() }
    private val bridge: PyObject by lazy { py.getModule("bridge") }

    init {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val files = getApplication<Application>().filesDir.absolutePath
                val version = bridge.callAttr("init", files).toString()
                val profiles = JSONArray(bridge.callAttr("profiles").toString()).let { a -> List(a.length()) { a.getString(it) } }
                val saved = try { getApplication<Application>().getSharedPreferences("fs", Context.MODE_PRIVATE).getString("domains", "") ?: "" } catch (_: Exception) { "" }
                _state.update { it.copy(ready = true, version = version, profiles = profiles, domains = saved) }
                loadHistory()
            } catch (e: Exception) {
                _state.update { it.copy(error = "engine failed to start: ${e.message}") }
            }
        }
    }

    fun setLabel(v: String) = _state.update { it.copy(label = v) }
    fun setDomains(v: String) {
        _state.update { it.copy(domains = v) }
        try { getApplication<Application>().getSharedPreferences("fs", Context.MODE_PRIVATE).edit().putString("domains", v).apply() } catch (_: Exception) {}
    }
    fun setProfile(v: String) = _state.update { it.copy(profile = v) }

    private fun netHints() {
        val ctx = getApplication<Application>()
        val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val net = cm.activeNetwork ?: return
        val lp = cm.getLinkProperties(net)
        val caps = cm.getNetworkCapabilities(net)
        val transport = when {
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true -> "wifi"
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true -> "mobile"
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true -> "ethernet"
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true -> "vpn"
            else -> ""
        }
        val defaults = lp?.routes?.filter { it.isDefaultRoute && it.gateway != null }.orEmpty()
        val gw = (defaults.firstOrNull { it.gateway is java.net.Inet4Address } ?: defaults.firstOrNull())?.gateway?.hostAddress ?: ""
        val dnsList = lp?.dnsServers.orEmpty()
        val dns = (dnsList.firstOrNull { it is java.net.Inet4Address } ?: dnsList.firstOrNull())?.hostAddress ?: ""
        val wifiInfo = if (transport == "wifi") caps?.transportInfo as? android.net.wifi.WifiInfo else null
        val ssid = wifiInfo?.ssid?.trim('"')?.takeIf { it != "<unknown ssid>" } ?: ""
        bridge.callAttr("set_net_hints", gw, dns, ssid, transport)
    }

    fun startScan() {
        val s = _state.value
        if (s.scanning || !s.ready) return
        _state.update {
            it.copy(scanning = true, status = "starting…", progress = 0f, score = -1, level = "", techniques = emptyList(),
                findings = emptyList(), advice = emptyList(), sites = emptyList(), probes = emptyList(),
                reportJson = null, summary = "", vendor = "", confidence = "", error = null)
        }
        viewModelScope.launch(Dispatchers.IO) {
            try {
                try { netHints() } catch (_: Exception) {}
                val listener = object : ScanListener {
                    override fun onEvent(kind: String, payload: String) = handle(kind, payload)
                }
                val json = bridge.callAttr("start", s.profile, s.label, listener, s.domains).toString()
                finish(json)
            } catch (e: Exception) {
                _state.update { it.copy(scanning = false, status = "failed", error = e.message ?: e.toString()) }
            }
        }
    }

    fun stopScan() {
        bridge.callAttr("cancel")
        _state.update { it.copy(status = "stopping…") }
    }

    private fun handle(kind: String, payload: String) {
        val a = JSONArray(payload)
        when (kind) {
            "net" -> {
                val fp = a.getJSONObject(0)
                val name = fp.optString("label").ifEmpty { fp.optString("ssid").ifEmpty { fp.optString("search").ifEmpty { "?" } } }
                _state.update { it.copy(netLine = "network: $name  [id ${fp.optString("id")}]  gw ${fp.optString("gateway").ifEmpty { "?" }}  resolver ${fp.optString("resolver").ifEmpty { "?" }}") }
            }
            "progress" -> {
                val done = a.getInt(0); val total = a.getInt(1).coerceAtLeast(1)
                _state.update { it.copy(progress = done.toFloat() / total, status = "probing $done/$total") }
            }
            "site" -> addSite(a.getString(0), a.getJSONObject(1), announce = true)
            "verify" -> {
                val dom = a.getString(0); val ok = a.getBoolean(1)
                addSite(dom, a.getJSONObject(2), announce = false)
                if (!ok) finding("↺ $dom: not reproduced on retry — dropped", "y")
            }
            "verify_start" -> _state.update { it.copy(status = "re-checking ${a.getInt(0)} positives…") }
            "port" -> probe(a.getString(0), a.getString(1), "")
            "udp" -> probe("UDP STUN ${a.getString(0)}", a.getString(1), "")
            "quic" -> probe("QUIC ${a.getString(0)}", a.getString(1), "")
            "dns_enc" -> probe(a.getString(0), a.getString(1), "")
            "ipv6", "dns_int", "http_proxy", "nxdomain", "url_filter" -> {
                val o = a.getJSONObject(0)
                val label = mapOf("ipv6" to "IPv6 egress", "dns_int" to "port-53 interception", "http_proxy" to "transparent HTTP proxy",
                    "nxdomain" to "NXDOMAIN hijack", "url_filter" to "URL keyword filter")[kind]!!
                probe(label, o.optString("verdict"), o.optString("detail"))
            }
            "mitm" -> {
                val o = a.getJSONObject(1)
                probe("TLS chain ${a.getString(0)}", o.optString("verdict"), o.optString("detail").ifEmpty { "issuer ${o.optString("issuer", "?")}" })
            }
            "ssh" -> probe("SSH egress (22)", a.getString(0), a.optString(1))
        }
    }

    private fun isBad(status: String): Boolean =
        !(status == "ok" || status == "open" || status.startsWith("open") || status.startsWith("passed") ||
                status in setOf("?", "unavailable", "refused", "tor-missing", "skipped") ||
                status.startsWith("error") || status.startsWith("tls-error") || status.startsWith("bad-reply"))

    private fun probe(label: String, status: String, detail: String) {
        val bad = isBad(status)
        _state.update { st ->
            val rows = st.probes.filter { it.probe != label } + ProbeRow(label, status, detail, bad)
            st.copy(probes = rows)
        }
        if (bad) finding("$label: $status", "r")
    }

    private fun finding(text: String, tag: String) = _state.update { it.copy(findings = it.findings + (text to tag)) }

    private fun addSite(dom: String, d: JSONObject, announce: Boolean) {
        val dns = d.getJSONObject("dns"); val sni = d.getJSONObject("sni"); val bp = d.getJSONObject("blockpage")
        val verdicts = listOf("dns" to dns, "sni" to sni, "blockpage" to bp)
        val flagged = verdicts.any { it.second.optString("verdict") !in NEUTRAL }
        val notes = mutableListOf<String>()
        if (sni.optString("verdict") == "SNI-DPI" && d.optBoolean("ech")) notes += "ECH can bypass this"
        if (sni.optBoolean("injected")) notes += "RST injected in-path"
        if (d.optBoolean("confirmed")) notes += "confirmed on retry"
        for ((k, r) in verdicts) {
            val n = r.optString("note").ifEmpty { r.optString("detail") }
            if (n.isNotEmpty() && r.optString("verdict") != "ok" && n != "skipped") notes += "$k: $n"
        }
        val refs = "ref " + joinArr(dns.optJSONArray("truth")) + " · system " + joinArr(dns.optJSONArray("system")) +
                " · @8.8.8.8 " + joinArr(dns.optJSONArray("udp53"))
        val rtt = if (sni.has("rtt_ms")) "  rtt ${sni.opt("rtt_ms")} ms" else ""
        val rst = if (sni.has("rst_ms")) "  rst ${sni.opt("rst_ms")} ms" else ""
        val detail = "DNS: $refs\nTLS/SNI: ${sni.optString("detail")}$rtt$rst\n" + notes.joinToString("; ")
        val ech = if (d.isNull("ech")) "?" else if (d.optBoolean("ech")) "yes" else "no"
        val row = SiteRow(dom, d.optString("cat"), dns.optString("verdict"), sni.optString("verdict"), bp.optString("verdict"),
            ech, d.optInt("ms"), flagged, d.optBoolean("transient"), detail)
        _state.update { st -> st.copy(sites = st.sites.filter { it.domain != dom } + row) }
        if (announce) for ((k, r) in verdicts) {
            val v = r.optString("verdict")
            if (v !in NEUTRAL) finding("$dom: $k=$v" + (if (k == "sni" && v == "SNI-DPI" && d.optBoolean("ech")) "  (bypassable via ECH)" else ""), "r")
        }
    }

    private fun joinArr(a: JSONArray?): String =
        if (a == null || a.length() == 0) "—" else (0 until minOf(3, a.length())).joinToString(", ") { a.getString(it) }

    private fun finish(json: String) {
        val rep = JSONObject(json)
        val an = rep.optJSONObject("analysis")
        if (an == null) {   // cancelled
            _state.update { it.copy(scanning = false, status = "stopped") }
            return
        }
        val techs = an.getJSONArray("techniques"); val labels = an.getJSONObject("technique_labels")
        val tl = List(techs.length()) { techs.getString(it) to labels.optString(techs.getString(it)) }
        val advice = mutableListOf<Pair<String, String>>()
        advice += "VPN diagnosis" to "h"
        advice += lines(rep, "vpn")
        advice += "Tunnel / circumvention" to "h"
        advice += lines(rep, "tunnel")
        val n = rep.optJSONArray("flagged")?.length() ?: 0
        val tm = rep.optJSONObject("timings")?.optInt("total_ms") ?: 0
        _state.update {
            it.copy(scanning = false, progress = 1f, status = "done in ${tm / 1000}s — $n signals", reportJson = json,
                score = an.getInt("score"), level = an.getString("level"), summary = an.getString("summary"),
                techniques = tl, vendor = an.optString("vendor"), confidence = an.optString("confidence"), advice = advice,
                findings = it.findings + ("✓ scan done — score ${an.getInt("score")} (${an.getString("level")})" to "g"))
        }
        loadHistory()
    }

    /** Advice lines come from Python (same text as the CLI). */
    private fun lines(rep: JSONObject, which: String): List<Pair<String, String>> {
        return try {
            val mod = py.getModule("filterscope.core")
            val fn = if (which == "vpn") "vpn_advice" else "tunnel_advice"
            val pyRep = py.getModule("json").callAttr("loads", rep.toString())
            val res = mod.callAttr(fn, pyRep).asList()
            res.map { pair -> val t = pair.asList(); t[1].toString() to t[0].toString() }
        } catch (e: Exception) { listOf("advice unavailable: ${e.message}" to "d") }
    }

    fun loadHistory() {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val arr = JSONArray(bridge.callAttr("history").toString())
                val rows = List(arr.length()) { i ->
                    val o = arr.getJSONObject(i)
                    HistoryRow(o.optString("ts"), o.optString("net"), if (o.isNull("score")) "" else o.optInt("score").toString(),
                        o.optInt("blocks"), o.optString("changes"))
                }
                _state.update { it.copy(history = rows) }
            } catch (_: Exception) {}
        }
    }

    suspend fun renderReportFile(): File? = withContext(Dispatchers.IO) {
        val json = _state.value.reportJson ?: return@withContext null
        val html = bridge.callAttr("render_html", json).toString()
        val dir = File(getApplication<Application>().cacheDir, "reports").apply { mkdirs() }
        val safe = _state.value.label.replace(Regex("[^A-Za-z0-9._-]+"), "_").trim('.', '_', '-').take(48).ifEmpty { "scan" }
        val name = "filterscope-" + safe + "-" +
                java.text.SimpleDateFormat("yyyyMMdd-HHmmss", java.util.Locale.US).format(java.util.Date()) + ".html"
        File(dir, name).apply { writeText(html) }
    }

    fun comparePrev() {
        val json = _state.value.reportJson ?: return
        viewModelScope.launch(Dispatchers.IO) {
            val res = bridge.callAttr("diff_prev", json).toString()
            if (res == "null") { finding("no earlier stored scan of this network", "n"); return@launch }
            val d = JSONObject(res)
            finding("vs ${d.optString("old_ts")}: score ${d.optInt("score_old")} → ${d.optInt("score_new")}", "n")
            val add = d.getJSONArray("added"); val rem = d.getJSONArray("removed")
            for (i in 0 until add.length()) finding("  + new block: ${add.getString(i)}", "r")
            for (i in 0 until rem.length()) finding("  − lifted: ${rem.getString(i)}", "g")
            if (add.length() == 0 && rem.length() == 0) finding("  no change", "n")
        }
    }
}

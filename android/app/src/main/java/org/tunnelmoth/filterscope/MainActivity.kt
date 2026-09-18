package org.tunnelmoth.filterscope

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.lightColorScheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.FileProvider
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch

val Green = Color(0xFF1A7F37)
val Red = Color(0xFFC62828)
val Amber = Color(0xFFB26A00)
val Blue = Color(0xFF2B5FD9)
val RedBg = Color(0xFFFDE8E8)
val YelBg = Color(0xFFFFF4D6)

fun levelColor(level: String) = when (level) {
    "clean" -> Green; "light" -> Amber; "moderate" -> Color(0xFFD97706); "heavy" -> Red; "severe" -> Color(0xFF8B0000)
    else -> Color.Gray
}

fun verdictColor(v: String): Color = when {
    v == "ok" || v == "open" || v.startsWith("open") || v.startsWith("passed") -> Green
    v in setOf("?", "no-dns", "unreachable", "unavailable", "refused", "skipped", "tor-missing", "") ||
            v.startsWith("error") || v.startsWith("tls-error") || v.startsWith("bad-reply") -> Amber
    else -> Red
}

fun tagColor(tag: String, default: Color): Color = when (tag) {
    "r" -> Red; "g" -> Green; "y" -> Amber; "d" -> Color.Gray; else -> default
}

class MainActivity : ComponentActivity() {
    private val vm: ScanViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            val dark = isSystemInDarkTheme()
            val scheme = if (dark) darkColorScheme(primary = Color(0xFF8AB4F8)) else lightColorScheme(primary = Blue)
            MaterialTheme(colorScheme = scheme) {
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    Main(vm, onOpen = { openReport(share = false) }, onShare = { openReport(share = true) })
                }
            }
        }
    }

    private fun openReport(share: Boolean) {
        lifecycleScope.launch {
            val f = vm.renderReportFile() ?: return@launch
            val uri = FileProvider.getUriForFile(this@MainActivity, "org.tunnelmoth.filterscope.files", f)
            val intent = if (share) Intent(Intent.ACTION_SEND).apply {
                type = "text/html"; putExtra(Intent.EXTRA_STREAM, uri); putExtra(Intent.EXTRA_SUBJECT, f.name)
            } else Intent(Intent.ACTION_VIEW).apply { setDataAndType(uri, "text/html") }
            intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            try {
                startActivity(if (share) Intent.createChooser(intent, "Share report") else intent)
            } catch (e: Exception) {
                // no browser accepting content:// html → fall back to the share sheet
                if (!share) startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).apply {
                    type = "text/html"; putExtra(Intent.EXTRA_STREAM, uri); addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                }, "Open report with"))
            }
        }
    }

}

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun Main(vm: ScanViewModel, onOpen: () -> Unit, onShare: () -> Unit) {
    val st by vm.state.collectAsState()
    var tab by remember { mutableIntStateOf(0) }
    val scope = rememberCoroutineScope()

    Scaffold(topBar = {
        TopAppBar(title = { Text("filterscope ${st.version}", fontWeight = FontWeight.Bold) }, actions = {
            TextButton(onClick = onShare, enabled = st.reportJson != null) { Text("Share") }
            TextButton(onClick = onOpen, enabled = st.reportJson != null) { Text("Open report") }
        })
    }) { pad ->
        Column(Modifier.padding(pad).fillMaxSize()) {
            // controls
            Row(Modifier.padding(horizontal = 12.dp), verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(value = st.label, onValueChange = vm::setLabel, label = { Text("label") },
                    singleLine = true, modifier = Modifier.weight(1f), enabled = !st.scanning)
                Spacer(Modifier.width(8.dp))
                ProfilePicker(st.profile, st.profiles, enabled = !st.scanning, onPick = vm::setProfile)
                Spacer(Modifier.width(8.dp))
                if (st.scanning) OutlinedButton(onClick = vm::stopScan) { Text("Stop") }
                else Button(onClick = vm::startScan, enabled = st.ready) { Text("Scan") }
            }
            var showDomains by remember { mutableStateOf(false) }
            Row(Modifier.padding(horizontal = 12.dp), verticalAlignment = Alignment.CenterVertically) {
                TextButton(onClick = { showDomains = !showDomains }) { Text(if (showDomains) "▴ own domains" else "▾ own domains" + (if (st.domains.isNotBlank()) " (set)" else "")) }
            }
            if (showDomains) OutlinedTextField(value = st.domains, onValueChange = vm::setDomains, label = { Text("extra domains, comma or newline separated") },
                modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp), minLines = 2, maxLines = 4, enabled = !st.scanning)
            LinearProgressIndicator(progress = { st.progress }, modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp))
            Text(st.status + (st.error?.let { "  ·  $it" } ?: ""), color = if (st.error != null) Red else Color.Gray,
                fontSize = 12.sp, modifier = Modifier.padding(horizontal = 12.dp), maxLines = 2, overflow = TextOverflow.Ellipsis)

            // verdict card (tap to expand the summary)
            var expanded by remember { mutableStateOf(false) }
            Card(Modifier.padding(horizontal = 12.dp, vertical = 6.dp).fillMaxWidth().clickable { expanded = !expanded },
                colors = CardDefaults.cardColors()) {
                Row(Modifier.padding(10.dp), verticalAlignment = Alignment.CenterVertically) {
                    Gauge(st.score, st.level)
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) {
                        if (st.netLine.isNotEmpty()) Text(st.netLine, fontSize = 11.sp, color = Color.Gray, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text(
                            when {
                                st.scanning -> "scanning…"
                                st.score < 0 -> "press Scan"
                                else -> "${st.level.uppercase()} filtering — ${st.findings.count { it.second == "r" }} signals — confidence ${st.confidence}"
                            }, fontWeight = FontWeight.Bold, fontSize = 14.sp, maxLines = 2, overflow = TextOverflow.Ellipsis,
                            color = if (st.score >= 0) levelColor(st.level) else MaterialTheme.colorScheme.onSurface)
                        Text(st.summary, fontSize = 13.sp, maxLines = if (expanded) 20 else 3, overflow = TextOverflow.Ellipsis)
                        if (st.techniques.isNotEmpty()) FlowRow(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                            st.techniques.forEach { (t, l) -> AssistChip(onClick = {}, label = { Text(t, fontSize = 11.sp, color = Red) }) }
                        }
                        if (st.vendor.isNotEmpty()) Text("vendor signature: ${st.vendor}", fontSize = 12.sp, color = Color(0xFF8E24AA))
                    }
                }
            }

            TabRow(selectedTabIndex = tab) {
                listOf("Overview", "Sites", "Egress", "History").forEachIndexed { i, t ->
                    Tab(selected = tab == i, onClick = { tab = i }, text = { Text(t) })
                }
            }
            when (tab) {
                0 -> Overview(st, onCompare = vm::comparePrev)
                1 -> Sites(st)
                2 -> Probes(st)
                3 -> History(st)
            }
        }
    }
}

@Composable
fun Gauge(score: Int, level: String) {
    val color = if (score >= 0) levelColor(level) else Color.LightGray
    Box(Modifier.size(84.dp), contentAlignment = Alignment.Center) {
        Canvas(Modifier.size(84.dp)) {
            val stroke = Stroke(width = 10.dp.toPx(), cap = StrokeCap.Round)
            val inset = 6.dp.toPx()
            val sz = Size(size.width - inset * 2, size.height - inset * 2)
            drawArc(Color(0xFFE0E0E0), 135f, 270f, false, Offset(inset, inset), sz, style = stroke)
            if (score > 0) drawArc(color, 135f, 270f * score / 100f, false, Offset(inset, inset), sz, style = stroke)
        }
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(if (score >= 0) "$score" else "—", fontSize = 22.sp, fontWeight = FontWeight.Bold, color = color)
            if (score >= 0) Text(level.uppercase(), fontSize = 9.sp, color = color)
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ProfilePicker(current: String, options: List<String>, enabled: Boolean, onPick: (String) -> Unit) {
    var open by remember { mutableStateOf(false) }
    Box {
        OutlinedButton(onClick = { open = true }, enabled = enabled) { Text(current) }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            options.forEach { DropdownMenuItem(text = { Text(it) }, onClick = { onPick(it); open = false }) }
        }
    }
}

@Composable
fun Overview(st: UiState, onCompare: () -> Unit) {
    LazyColumn(Modifier.fillMaxSize().padding(12.dp)) {
        item {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("findings", fontWeight = FontWeight.Bold)
                Spacer(Modifier.weight(1f))
                TextButton(onClick = onCompare, enabled = st.reportJson != null) { Text("Compare with previous") }
            }
        }
        if (st.findings.isEmpty()) item { Text(if (st.scanning) "…" else "no findings yet", color = Color.Gray) }
        items(st.findings) { (t, tag) -> Text(t, color = tagColor(tag, MaterialTheme.colorScheme.onSurface), fontSize = 13.sp, modifier = Modifier.padding(vertical = 2.dp)) }
        if (st.advice.isNotEmpty()) {
            item { HorizontalDivider(Modifier.padding(vertical = 8.dp)) }
            items(st.advice) { (t, tag) ->
                if (tag == "h") Text(t, fontWeight = FontWeight.Bold, modifier = Modifier.padding(top = 6.dp))
                else Text(t, color = tagColor(tag, MaterialTheme.colorScheme.onSurface), fontSize = 13.sp)
            }
        }
    }
}

@Composable
fun Sites(st: UiState) {
    var filter by remember { mutableStateOf("") }
    var flaggedOnly by remember { mutableStateOf(false) }
    var expanded by remember { mutableStateOf<String?>(null) }
    val rows = st.sites.sortedWith(compareBy({ !it.flagged }, { it.category }))
        .filter { !flaggedOnly || it.flagged }
        .filter { filter.isEmpty() || it.category.contains(filter, true) || it.domain.contains(filter, true) ||
                it.dns.contains(filter, true) || it.sni.contains(filter, true) || it.block.contains(filter, true) }
    Column(Modifier.fillMaxSize()) {
        Row(Modifier.padding(horizontal = 12.dp), verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(value = filter, onValueChange = { filter = it }, label = { Text("filter") }, singleLine = true, modifier = Modifier.weight(1f))
            Checkbox(checked = flaggedOnly, onCheckedChange = { flaggedOnly = it })
            Text("affected only", fontSize = 12.sp)
        }
        Text("${rows.size} shown · ${st.sites.count { it.flagged }} affected" +
                (if (st.scanning && st.sites.size < st.sitesExpected) " · pending" else ""),
            fontSize = 11.sp, color = Color.Gray, modifier = Modifier.padding(horizontal = 12.dp))
        LazyColumn(Modifier.fillMaxSize()) {
            items(rows, key = { it.domain }) { r ->
                val bg = if (r.flagged) RedBg else if (r.transient) YelBg else Color.Transparent
                Column(Modifier.fillMaxWidth().background(bg).clickable { expanded = if (expanded == r.domain) null else r.domain }
                    .padding(horizontal = 12.dp, vertical = 6.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text(r.domain, fontWeight = FontWeight.SemiBold, fontSize = 14.sp, color = if (r.flagged) Color.Black else MaterialTheme.colorScheme.onSurface)
                            Text(r.category + "  ·  ${r.ms} ms", fontSize = 11.sp, color = Color.Gray)
                        }
                        Column(horizontalAlignment = Alignment.End) {
                            Text("DNS ${r.dns}", fontSize = 11.sp, color = verdictColor(r.dns))
                            Text("SNI ${r.sni}", fontSize = 11.sp, color = verdictColor(r.sni))
                            Text("page ${r.block} · ECH ${r.ech}", fontSize = 11.sp, color = verdictColor(r.block))
                        }
                    }
                    if (expanded == r.domain) Text(r.detail, fontSize = 11.sp, color = Color.DarkGray, modifier = Modifier.padding(top = 4.dp))
                }
                HorizontalDivider()
            }
        }
    }
}

@Composable
fun Probes(st: UiState) {
    LazyColumn(Modifier.fillMaxSize()) {
        items(st.probes) { p ->
            Row(Modifier.fillMaxWidth().background(if (p.bad) RedBg else Color.Transparent).padding(horizontal = 12.dp, vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(p.probe, fontSize = 13.sp, color = if (p.bad) Color.Black else MaterialTheme.colorScheme.onSurface)
                    if (p.detail.isNotEmpty()) Text(p.detail, fontSize = 11.sp, color = Color.Gray, maxLines = 3)
                }
                Text(p.status, fontSize = 12.sp, color = verdictColor(p.status), fontWeight = FontWeight.SemiBold)
            }
            HorizontalDivider()
        }
        if (st.probes.isEmpty()) item { Text(if (st.scanning) "…" else "no probes yet", color = Color.Gray, modifier = Modifier.padding(12.dp)) }
    }
}

@Composable
fun History(st: UiState) {
    LazyColumn(Modifier.fillMaxSize()) {
        items(st.history) { h ->
            Row(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("${h.ts}  ${h.net}", fontSize = 13.sp)
                    if (h.changes.isNotEmpty()) Text(h.changes, fontSize = 11.sp,
                        color = if (h.changes.startsWith("+")) Red else if (h.changes.startsWith("−")) Green else Color.Gray)
                }
                Column(horizontalAlignment = Alignment.End) {
                    if (h.score.isNotEmpty()) Text("score ${h.score}", fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                    Text("${h.blocks} blocks", fontSize = 11.sp, color = Color.Gray)
                }
            }
            HorizontalDivider()
        }
        if (st.history.isEmpty()) item { Text("no history yet — run a scan", color = Color.Gray, modifier = Modifier.padding(12.dp)) }
    }
}

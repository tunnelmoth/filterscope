package org.tunnelmoth.filterscope

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.widget.RemoteViews
import com.chaquo.python.Python
import org.json.JSONObject

/** Home-screen widget: last score + level; tapping opens the app and starts a scan. */
class FilterWidget : AppWidgetProvider() {
    override fun onUpdate(context: Context, mgr: AppWidgetManager, ids: IntArray) {
        for (id in ids) mgr.updateAppWidget(id, build(context))
    }

    companion object {
        private val LEVEL_COLOR = mapOf("clean" to 0xFF3DDC84.toInt(), "light" to 0xFFFFB74D.toInt(), "moderate" to 0xFFFF9800.toInt(),
            "heavy" to 0xFFFF6B6B.toInt(), "severe" to 0xFFE53935.toInt())

        fun build(context: Context): RemoteViews {
            val rv = RemoteViews(context.packageName, R.layout.widget)
            val launch = Intent(context, MainActivity::class.java).apply {
                putExtra("autoscan", true); addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            }
            val flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            rv.setOnClickPendingIntent(R.id.root, PendingIntent.getActivity(context, 1, launch, flags))
            try {
                val py = Python.getInstance()
                val br = py.getModule("bridge")
                try { br.callAttr("init", context.filesDir.absolutePath, java.util.Locale.getDefault().language) } catch (_: Exception) {}
                val s = br.callAttr("last_summary").toString()
                if (s != "null") {
                    val o = JSONObject(s)
                    val level = o.optString("level")
                    rv.setTextViewText(R.id.score, if (o.isNull("score")) "—" else o.optInt("score").toString())
                    rv.setTextColor(R.id.score, LEVEL_COLOR[level] ?: 0xFFC4B5FD.toInt())
                    rv.setTextViewText(R.id.sub, "${S.levelName(level)} · ${o.optString("ts").take(16)}${if (o.optString("net").isNotEmpty()) " · " + o.optString("net") else ""}\n${S.widgetTap}")
                } else {
                    rv.setTextViewText(R.id.sub, "${S.widgetNone} · ${S.widgetTap}")
                }
            } catch (_: Exception) {
                rv.setTextViewText(R.id.sub, S.widgetTap)
            }
            return rv
        }

        fun refresh(context: Context) {
            val mgr = AppWidgetManager.getInstance(context)
            val ids = mgr.getAppWidgetIds(ComponentName(context, FilterWidget::class.java))
            for (id in ids) mgr.updateAppWidget(id, build(context))
        }
    }
}

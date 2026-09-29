package com.mcvpn.client

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.SystemClock
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.graphics.Typeface
import android.widget.Button
import android.widget.EditText
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import org.json.JSONObject

class MainActivity : AppCompatActivity() {
    private lateinit var serverEdit: EditText
    private lateinit var portEdit: EditText
    private lateinit var tokenEdit: EditText
    private lateinit var connectBtn: Button
    private lateinit var disconnectBtn: Button
    private lateinit var logBtn: Button
    private lateinit var statusText: TextView
    private lateinit var statsText: TextView
    private val handler = Handler(Looper.getMainLooper())
    private val poller = object : Runnable {
        override fun run() {
            refreshUi()
            handler.postDelayed(this, 1000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_YES)
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        requestNotificationPermission()

        serverEdit = findViewById(R.id.serverEdit)
        portEdit = findViewById(R.id.portEdit)
        tokenEdit = findViewById(R.id.tokenEdit)
        connectBtn = findViewById(R.id.connectBtn)
        disconnectBtn = findViewById(R.id.disconnectBtn)
        logBtn = findViewById(R.id.logBtn)
        statusText = findViewById(R.id.statusText)
        statsText = findViewById(R.id.statsText)

        val prefs = getSharedPreferences("mcvpn", MODE_PRIVATE)
        serverEdit.setText(prefs.getString("server", ""))
        portEdit.setText(prefs.getInt("port", 25565).toString())
        tokenEdit.setText(prefs.getString("token", ""))

        logBtn.setOnClickListener { showLog() }
        connectBtn.setOnClickListener { onConnect() }
        disconnectBtn.setOnClickListener {
            startService(Intent(this, TunnelService::class.java).putExtra("action", "disconnect"))
            refreshUi()
        }
        refreshUi()
    }

    override fun onResume() {
        super.onResume()
        handler.post(poller)
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(poller)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST) {
            if (resultCode == RESULT_OK) startVpn() else statusText.text = "VPN permission denied"
        }
    }

    private fun onConnect() {
        val server = serverEdit.text.toString().trim()
        val port = portEdit.text.toString().trim().toIntOrNull() ?: 25565
        val token = tokenEdit.text.toString().trim()
        // A full mcvpn:// link in the server field carries its own token.
        if (server.isEmpty() || (token.isEmpty() && !server.contains("@"))) {
            statusText.text = "Fill in server and token (or paste an mcvpn:// link)"
            return
        }
        getSharedPreferences("mcvpn", MODE_PRIVATE).edit()
            .putString("server", server)
            .putInt("port", port)
            .putString("token", token)
            .apply()

        val prepare = VpnService.prepare(this)
        if (prepare != null) {
            startActivityForResult(prepare, VPN_REQUEST)
        } else {
            startVpn()
        }
    }

    private fun startVpn() {
        val server = serverEdit.text.toString().trim()
        val port = portEdit.text.toString().trim().toIntOrNull() ?: 25565
        val token = tokenEdit.text.toString().trim()
        val intent = Intent(this, TunnelService::class.java)
            .putExtra("action", "connect")
            .putExtra("server", server)
            .putExtra("port", port)
            .putExtra("token", token)
        ContextCompat.startForegroundService(this, intent)
        statusText.text = "connecting…"
    }

    private fun refreshUi() {
        val active = TunnelService.running
        TunnelService.libError?.let { TunnelService.lastError = it }
        connectBtn.isEnabled = !active
        disconnectBtn.isEnabled = active
        statsText.text = when {
            active -> {
                val uptime = (SystemClock.elapsedRealtime() - TunnelService.connectedAtMs) / 1000
                "ip ${TunnelService.lastIp}   uptime ${uptime}s\n${
                    formatStats(TunnelService.lastStats)
                }"
            }
            TunnelService.connecting -> "connecting…"
            else -> ""
        }
        statusText.text = when {
            active -> "● connected (${TunnelService.lastIp})"
            TunnelService.connecting -> "● connecting…"
            TunnelService.lastError.isNotEmpty() -> "● error: ${TunnelService.lastError}"
            else -> "● idle"
        }
        statusText.setTextColor(
            ContextCompat.getColor(
                this,
                when {
                    active -> R.color.ok
                    TunnelService.connecting -> R.color.accent
                    TunnelService.lastError.isNotEmpty() -> R.color.err
                    else -> R.color.muted
                }
            )
        )
    }

    private fun logText(): String {
        val header = "mcvpn ${BuildInfo.VERSION} / Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT}), ${Build.MANUFACTURER} ${Build.MODEL}\n" +
            "state: running=${TunnelService.running} connecting=${TunnelService.connecting}\n" +
            "last error: ${TunnelService.lastError.ifEmpty { "-" }}\n\n"
        return header + TunnelService.lastLog.ifEmpty { "(no log yet — press CONNECT first)" }
    }

    private fun showLog() {
        val text = logText()
        val tv = TextView(this).apply {
            setText(text)
            typeface = Typeface.MONOSPACE
            textSize = 11f
            setTextIsSelectable(true)
            setPadding(32, 24, 32, 24)
        }
        val scroll = ScrollView(this).apply { addView(tv) }
        AlertDialog.Builder(this)
            .setTitle("Log")
            .setView(scroll)
            .setPositiveButton("Copy") { _, _ ->
                val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                cm.setPrimaryClip(ClipData.newPlainText("mcvpn log", text))
                Toast.makeText(this, "Log copied", Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton("Close", null)
            .show()
    }

    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            ActivityCompat.requestPermissions(
                this, arrayOf(Manifest.permission.POST_NOTIFICATIONS), 2
            )
        }
    }

    private fun formatStats(json: String): String {
        return try {
            val o = JSONObject(json)
            val up = o.optLong("up", 0) / 1024
            val down = o.optLong("down", 0) / 1024
            val rtt = o.optInt("rtt", 0)
            "up ${up} KB   down ${down} KB   rtt ${if (rtt > 0) "$rtt ms" else "-"}"
        } catch (_: Exception) {
            ""
        }
    }

    companion object {
        private const val VPN_REQUEST = 1
    }
}

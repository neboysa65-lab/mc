package com.mcvpn.client

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.content.ContextCompat
import org.json.JSONObject

class MainActivity : AppCompatActivity() {
    private lateinit var serverEdit: EditText
    private lateinit var portEdit: EditText
    private lateinit var tokenEdit: EditText
    private lateinit var connectBtn: Button
    private lateinit var disconnectBtn: Button
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

        serverEdit = findViewById(R.id.serverEdit)
        portEdit = findViewById(R.id.portEdit)
        tokenEdit = findViewById(R.id.tokenEdit)
        connectBtn = findViewById(R.id.connectBtn)
        disconnectBtn = findViewById(R.id.disconnectBtn)
        statusText = findViewById(R.id.statusText)
        statsText = findViewById(R.id.statsText)

        val prefs = getSharedPreferences("mcvpn", MODE_PRIVATE)
        serverEdit.setText(prefs.getString("server", ""))
        portEdit.setText(prefs.getInt("port", 25565).toString())
        tokenEdit.setText(prefs.getString("token", ""))

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
        val port = portEdit.text.toString().toIntOrNull() ?: 25565
        val token = tokenEdit.text.toString()
        if (server.isEmpty() || token.isEmpty()) {
            statusText.text = "Fill in server and token"
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
        val port = portEdit.text.toString().toIntOrNull() ?: 25565
        val token = tokenEdit.text.toString()
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
        connectBtn.isEnabled = !active
        disconnectBtn.isEnabled = active
        statsText.text = if (active) formatStats(TunnelService.lastStats) else ""
        statusText.text = when {
            active -> "● connected"
            TunnelService.lastError.isNotEmpty() -> "● error: ${TunnelService.lastError}"
            else -> "● idle"
        }
        statusText.setTextColor(
            resources.getColor(
                when {
                    active -> R.color.ok
                    TunnelService.lastError.isNotEmpty() -> R.color.err
                    else -> R.color.muted
                }, theme
            )
        )
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

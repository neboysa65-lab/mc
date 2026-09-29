package com.mcvpn.client

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import org.json.JSONObject

class TunnelService : VpnService() {
    companion object {
        init {
+            System.loadLibrary("mcvpn")
        }
        @Volatile var running = false
        @Volatile var lastStats = "{}"
        @Volatile var lastError = ""
        const val CHANNEL_ID = "mcvpn-tunnel"
    }

    private external fun nativeConnect(server: String, port: Int, token: String): String
    private external fun nativeStart(fd: Int): Boolean
    private external fun nativeStop()
    private external fun nativeGetStats(): String

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.getStringExtra("action")) {
            "connect" -> startVpn(intent)
            else -> stopVpn()
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    private fun startVpn(intent: Intent) {
        ensureChannel()
        startForeground(1, notification("connecting…"))
        running = true
        lastError = ""

        val server = intent.getStringExtra("server")
        val port = intent.getIntExtra("port", 25565)
        val token = intent.getStringExtra("token")
        if (server.isNullOrEmpty() || token.isNullOrEmpty()) {
            lastError = "missing server/token"
            stopSelf()
            return
        }

        Thread {
            val json = nativeConnect(server, port, token)
            val cfg = JSONObject(json)
            if (!cfg.optBoolean("ok", false)) {
                lastError = cfg.optString("error", "connection failed")
                running = false
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return@Thread
            }

            val builder = Builder()
                .setSession("mcvpn")
                .setMtu(cfg.getInt("mtu"))
                .addAddress(cfg.getString("ip"), cfg.getInt("prefix_len"))
                .addRoute("0.0.0.0", 0)

            val dns = cfg.optJSONArray("dns")
            if (dns != null) {
                for (i in 0 until dns.length()) {
                    builder.addDnsServer(dns.getString(i))
                }
            }
            // Keep this app's own traffic on the physical network: the
            // tunnel socket was established before the VPN came up, and
            // this also makes manual reconnects safe.
            try {
                builder.addDisallowedApplication("com.mcvpn.client")
            } catch (_: Exception) {
            }

            val pfd: ParcelFileDescriptor = builder.establish() ?: run {
                lastError = "VPN permission revoked"
                stopSelf()
                return@Thread
            }
            val fd = pfd.detachFd()
            if (!nativeStart(fd)) {
                lastError = "tunnel start failed"
                stopSelf()
                return@Thread
            }

            Thread {
                while (running) {
                    lastStats = nativeGetStats()
                    val stats = JSONObject(lastStats)
                    val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
                    if (running) {
                        val up = stats.optLong("up", 0) / 1024
                        val down = stats.optLong("down", 0) / 1024
                        nm.notify(1, notification("up ${up} KB · down ${down} KB"))
                    }
                    Thread.sleep(1000)
                }
            }.start()
        }.start()
    }

    private fun stopVpn() {
        if (running) {
            nativeStop()
        }
        running = false
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun ensureChannel() {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        if (nm.getNotificationChannel(CHANNEL_ID) == null) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "mcvpn tunnel", NotificationManager.IMPORTANCE_LOW)
            )
        }
    }

    private fun notification(text: String): Notification {
        val pi = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("mcvpn")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_sys_download_done)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }
}

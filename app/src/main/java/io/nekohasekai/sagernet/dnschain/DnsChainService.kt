package io.nekohasekai.sagernet.dnschain

import android.app.Notification
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.widget.Toast
import androidx.core.app.NotificationChannelCompat
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.ktx.Logs
import io.nekohasekai.sagernet.ui.DnsChainActivity
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * Keeps the DNS Chain proxy (SOCKS5 / HTTP CONNECT + DoH + TLS fragmentation)
 * alive on 127.0.0.1:40445 while the switch in Settings is on.
 */
class DnsChainService : Service() {

    companion object {
        private const val CHANNEL_ID = "dns-chain"
        private const val NOTIFICATION_ID = 40445
        private const val EXTRA_RESTART = "restart"

        @Volatile
        var running = false
            private set

        /**
         * @param restart true = (re)load the saved settings even if already running;
         *                false = only start when not running yet.
         */
        fun start(context: Context, restart: Boolean = true) {
            val intent = Intent(context, DnsChainService::class.java).putExtra(EXTRA_RESTART, restart)
            try {
                ContextCompat.startForegroundService(context, intent)
            } catch (e: Exception) {
                Logs.w(e)
            }
        }

        fun stop(context: Context) {
            try {
                context.stopService(Intent(context, DnsChainService::class.java))
            } catch (e: Exception) {
                Logs.w(e)
            }
        }
    }

    private val worker: ExecutorService = Executors.newSingleThreadExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())

    // only touched from the worker thread
    private var proxy: DnsChainProxy? = null

    private val logger = DnsChainProxy.Logger { level, message ->
        when (level) {
            DnsChainProxy.ERROR -> Logs.e("DNS Chain: $message")
            DnsChainProxy.WARN -> Logs.w("DNS Chain: $message")
            DnsChainProxy.INFO -> Logs.i("DNS Chain: $message")
            else -> Logs.d("DNS Chain: $message")
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // must be called quickly after startForegroundService()
        try {
            NotificationManagerCompat.from(this).createNotificationChannel(
                NotificationChannelCompat.Builder(CHANNEL_ID, NotificationManagerCompat.IMPORTANCE_LOW)
                    .setName(getString(R.string.dns_chain))
                    .build()
            )
            startForeground(NOTIFICATION_ID, buildNotification())
        } catch (e: Exception) {
            Logs.w(e)
            stopSelf()
            return START_NOT_STICKY
        }

        // intent == null: the system restarted us after the process was killed
        if (intent == null && !DataStore.dnsChainEnabled) {
            stopSelf()
            return START_NOT_STICKY
        }
        val restart = intent?.getBooleanExtra(EXTRA_RESTART, true) ?: false
        try {
            worker.execute { applyConfig(restart) }
        } catch (e: Exception) {
            Logs.w(e)
        }
        return START_STICKY
    }

    private fun applyConfig(restart: Boolean) {
        if (!restart && proxy?.isRunning == true) return

        proxy?.stop()
        proxy = null
        running = false

        val config = try {
            DnsChainSettings.buildConfig(this)
        } catch (e: DnsChainConfig.ConfigException) {
            fail(e.message ?: "invalid settings")
            return
        } catch (e: Exception) {
            fail("cannot read ${DnsChainConfig.INI_ASSET}: ${e.message}")
            return
        }

        val p = DnsChainProxy(config, logger)
        try {
            p.start()
        } catch (e: Exception) {
            p.stop()
            fail(e.message ?: e.javaClass.simpleName)
            return
        }
        proxy = p
        running = true
    }

    private fun fail(message: String) {
        Logs.e("DNS Chain: could not start: $message")
        running = false
        DataStore.dnsChainEnabled = false
        mainHandler.post {
            Toast.makeText(
                applicationContext,
                getString(R.string.dns_chain_start_failed, message),
                Toast.LENGTH_LONG
            ).show()
            stopSelf()
        }
    }

    private fun buildNotification(): Notification {
        val contentIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, DnsChainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.dns_chain))
            .setContentText(
                getString(
                    R.string.dns_chain_notification,
                    DnsChainSettings.addressOrDefault(this)
                )
            )
            .setSmallIcon(R.drawable.ic_service_active)
            .setContentIntent(contentIntent)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    override fun onDestroy() {
        running = false
        try {
            worker.execute {
                proxy?.stop()
                proxy = null
                running = false
            }
        } catch (ignored: Exception) {
        }
        worker.shutdown()
        super.onDestroy()
    }
}

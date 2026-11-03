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
import java.io.IOException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * Hosts the DNS Chain proxy (SOCKS5 / HTTP CONNECT + DoH + TLS fragmentation).
 *
 * Runs in the ":bg" process, next to the VPN / proxy service, and follows its life cycle:
 *  - the switch in Settings only allows DNS Chain ("master switch");
 *  - the local port opens when a profile is started (BaseService calls [configStarted]);
 *  - when the profile stops, the port stays open for the configured seconds (default 60) and then
 *    closes, unless "close after idle" is turned off in the DNS Chain page (then it stays open);
 *  - starting a profile again (also a different one) cancels the countdown and reuses the
 *    same, already open port;
 *  - while a profile is running the port is never closed by the countdown.
 */
class DnsChainService : Service() {

    companion object {
        private const val CHANNEL_ID = "dns-chain"
        private const val NOTIFICATION_ID = 40445
        private const val ACTION_ENSURE = "io.nekohasekai.sagernet.dnschain.ENSURE"
        private const val ACTION_RELOAD = "io.nekohasekai.sagernet.dnschain.RELOAD"

        /** True while a profile is connecting or connected. Only meaningful inside ":bg". */
        @Volatile
        private var configRunning = false

        @Volatile
        private var instance: DnsChainService? = null

        /** BaseService (":bg"): a profile is starting. */
        fun configStarted(context: Context) {
            configRunning = true
            instance?.cancelIdleStop()
            if (DataStore.dnsChainEnabled) {
                launch(context, ACTION_ENSURE)
            }
        }

        /** BaseService (":bg"): the profile has stopped. */
        fun configStopped() {
            configRunning = false
            instance?.scheduleIdleStop()
        }

        /**
         * Settings: the switch was turned on. Opens the port right away if a profile is running,
         * or if the port is set to stay open ("close after idle" is off).
         */
        fun onSwitchedOn(context: Context) {
            if (DataStore.startedProfile > 0L || !DataStore.dnsChainAutoClose) {
                launch(context, ACTION_ENSURE)
            }
        }

        /** Settings: the switch was turned off. Closes the port immediately. */
        fun onSwitchedOff(context: Context) {
            try {
                context.stopService(Intent(context, DnsChainService::class.java))
            } catch (e: Exception) {
                Logs.w(e)
            }
        }

        /** DNS Chain page: DoH list / login changed. Applies them if the proxy is currently up. */
        fun reload(context: Context) {
            try {
                context.startService(
                    Intent(context, DnsChainService::class.java).setAction(ACTION_RELOAD)
                )
            } catch (e: Exception) {
                Logs.w(e)
            }
        }

        private fun launch(context: Context, action: String) {
            val intent = Intent(context, DnsChainService::class.java).setAction(action)
            try {
                ContextCompat.startForegroundService(context, intent)
            } catch (e: Exception) {
                // the profile service keeps the process alive anyway
                try {
                    context.startService(intent)
                } catch (e2: Exception) {
                    Logs.w(e2)
                }
            }
        }
    }

    private val worker: ExecutorService = Executors.newSingleThreadExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())
    private val idleStop = Runnable { onIdleTimeout() }
    private val lock = Any()

    // guarded by lock
    private var proxy: DnsChainProxy? = null

    @Volatile
    private var destroyed = false

    @Volatile
    private var lastStartId = 0

    // login / DoH list the running proxy was started with (guarded by lock)
    private var appliedSignature: String? = null
    private var foregroundStarted = false

    private val logger = DnsChainProxy.Logger { level, message ->
        when (level) {
            DnsChainProxy.ERROR -> Logs.e("DNS Chain: $message")
            DnsChainProxy.WARN -> Logs.w("DNS Chain: $message")
            DnsChainProxy.INFO -> Logs.i("DNS Chain: $message")
            else -> Logs.d("DNS Chain: $message")
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        instance = this
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        lastStartId = startId
        when (intent?.action) {
            ACTION_ENSURE -> {
                enterForeground()
                post { ensureProxy() }
            }
            ACTION_RELOAD -> post { reloadProxy() }
            else -> stopSelf(startId)
        }
        // when the process dies the profile dies with it, so there is nothing to restore
        return START_NOT_STICKY
    }

    private fun post(task: () -> Unit) {
        try {
            worker.execute { task() }
        } catch (e: Exception) {
            Logs.w(e)
        }
    }

    // ---- proxy ----

    private fun isProxyRunning(): Boolean = synchronized(lock) { proxy?.isRunning == true }

    private fun ensureProxy() {
        if (!DataStore.dnsChainEnabled) { // switched off in the meantime
            mainHandler.post { stopSelf(lastStartId) }
            return
        }
        if (!isProxyRunning() && !startProxy()) return
        scheduleIdleStop() // does nothing while a profile is running
    }

    private fun reloadProxy() {
        if (!isProxyRunning()) {
            if (DataStore.dnsChainEnabled && !DataStore.dnsChainAutoClose) {
                // "stay open" was just turned on: open the port now
                mainHandler.post { enterForeground() }
                if (startProxy()) scheduleIdleStop()
            } else { // nothing is up; this instance was only started for the reload
                mainHandler.post { stopSelf(lastStartId) }
            }
            return
        }
        val changed = synchronized(lock) { appliedSignature != DnsChainSettings.signature() }
        if (changed) { // new DoH list or login
            synchronized(lock) {
                proxy?.stop()
                proxy = null
            }
            startProxy()
        }
        scheduleIdleStop() // the countdown settings may have changed
    }

    /** Starts the proxy with the saved settings. Returns false (and reports) on failure. */
    private fun startProxy(): Boolean {
        val config = try {
            DnsChainSettings.buildConfig(this)
        } catch (e: DnsChainConfig.ConfigException) {
            fail(e.message ?: "invalid settings")
            return false
        } catch (e: Exception) {
            fail("cannot read ${DnsChainConfig.INI_ASSET}: ${e.message}")
            return false
        }

        var lastError: Exception? = null
        for (attempt in 1..4) { // the port may still be released by a proxy that was just stopped
            val p = DnsChainProxy(config, logger)
            try {
                p.start()
                synchronized(lock) {
                    if (destroyed) {
                        p.stop()
                        return false
                    }
                    proxy = p
                    appliedSignature = DnsChainSettings.signature()
                }
                return true
            } catch (e: IOException) {
                p.stop()
                lastError = e
                try {
                    Thread.sleep(300)
                } catch (ie: InterruptedException) {
                    return false
                }
            }
        }
        fail(lastError?.message ?: "cannot open the local port")
        return false
    }

    private fun fail(message: String) {
        Logs.e("DNS Chain: could not start: $message")
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

    // ---- 60 second countdown after the last profile stopped ----

    fun cancelIdleStop() {
        mainHandler.removeCallbacks(idleStop)
    }

    fun scheduleIdleStop() {
        mainHandler.post {
            mainHandler.removeCallbacks(idleStop)
            if (!configRunning && DataStore.dnsChainAutoClose) {
                val seconds = DataStore.dnsChainIdleSeconds.coerceIn(1, DnsChainSettings.MAX_IDLE_SECONDS)
                mainHandler.postDelayed(idleStop, seconds * 1000L)
            }
        }
    }

    private fun onIdleTimeout() {
        if (configRunning) return // a profile is running: never close the port
        if (!DataStore.dnsChainAutoClose) return
        stopSelf(lastStartId)     // no-op if a newer start request has arrived
    }

    // ---- notification ----

    private fun enterForeground() {
        if (foregroundStarted) return
        try {
            NotificationManagerCompat.from(this).createNotificationChannel(
                NotificationChannelCompat.Builder(CHANNEL_ID, NotificationManagerCompat.IMPORTANCE_LOW)
                    .setName(getString(R.string.dns_chain))
                    .build()
            )
            startForeground(NOTIFICATION_ID, buildNotification())
            foregroundStarted = true
        } catch (e: Exception) {
            Logs.w(e)
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
        mainHandler.removeCallbacks(idleStop)
        if (instance === this) instance = null
        worker.shutdownNow()
        synchronized(lock) {
            destroyed = true
            proxy?.stop() // synchronous: the port is free when a new instance starts
            proxy = null
        }
        super.onDestroy()
    }
}

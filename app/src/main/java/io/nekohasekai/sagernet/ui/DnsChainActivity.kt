package io.nekohasekai.sagernet.ui

import android.os.Bundle
import android.view.MenuItem
import android.widget.Toast
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updatePadding
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.databinding.LayoutDnsChainBinding
import io.nekohasekai.sagernet.dnschain.DnsChainConfig
import io.nekohasekai.sagernet.dnschain.DnsChainService
import io.nekohasekai.sagernet.dnschain.DnsChainSettings
import java.net.InetSocketAddress
import java.net.Socket
import kotlin.concurrent.thread

class DnsChainActivity : ThemedActivity() {

    private lateinit var binding: LayoutDnsChainBinding
    private var ini: DnsChainConfig? = null
    private var iniError: String? = null
    private var address = DnsChainSettings.DEFAULT_ADDRESS

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = LayoutDnsChainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        ViewCompat.setOnApplyWindowInsetsListener(binding.root) { v, insets ->
            val ime = insets.getInsets(WindowInsetsCompat.Type.ime())
            v.updatePadding(
                bottom = ime.bottom,
            )
            insets
        }
        ViewCompat.setOnApplyWindowInsetsListener(binding.dnsChainScroll) { v, insets ->
            val bars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars()
                        or WindowInsetsCompat.Type.displayCutout()
            )
            val ime = insets.getInsets(WindowInsetsCompat.Type.ime())
            v.updatePadding(
                left = bars.left,
                right = bars.right,
                bottom = if (ime.bottom > bars.bottom) 0 else bars.bottom - ime.bottom,
            )
            insets
        }
        setSupportActionBar(findViewById(R.id.toolbar))
        supportActionBar?.apply {
            setTitle(R.string.dns_chain)
            setDisplayHomeAsUpEnabled(true)
            setHomeAsUpIndicator(R.drawable.ic_navigation_close)
        }

        try {
            ini = DnsChainSettings.loadIni(this)
            ini?.let { address = DnsChainSettings.address(it) }
        } catch (e: Exception) {
            iniError = e.message ?: e.javaClass.simpleName
        }
        binding.dnsChainDescription.text = getString(R.string.dns_chain_description, address)

        if (savedInstanceState == null) {
            binding.dohInput.setText(DnsChainSettings.dohText(ini))
            binding.userInput.setText(DataStore.dnsChainUser)
            binding.passInput.setText(DataStore.dnsChainPass)
            binding.autoCloseSwitch.isChecked = DataStore.dnsChainAutoClose
            binding.idleInput.setText(DataStore.dnsChainIdleSeconds.toString())
        }
        binding.autoCloseSwitch.setOnCheckedChangeListener { _, checked ->
            binding.idleLayout.isEnabled = checked
        }
        binding.idleLayout.isEnabled = binding.autoCloseSwitch.isChecked

        binding.dnsChainSave.setOnClickListener { save() }
        binding.dnsChainReset.setOnClickListener {
            // back to the DoH list written in setting.ini and the default login
            binding.dohInput.setText(ini?.dohServers?.joinToString("\n").orEmpty())
            binding.userInput.setText("admin")
            binding.passInput.setText("admin")
            binding.autoCloseSwitch.isChecked = true
            binding.idleInput.setText("60")
        }
    }

    override fun onResume() {
        super.onResume()
        updateStatus()
    }

    /** Asks the real thing: is something listening on the proxy address right now? */
    private fun updateStatus() {
        val error = iniError
        if (error != null) {
            binding.dnsChainStatus.text = error
            return
        }
        val config = ini ?: return
        val host = config.listenIp
        val port = config.listenPort
        thread(isDaemon = true) {
            val up = try {
                Socket().use { it.connect(InetSocketAddress(host, port), 400) }
                true
            } catch (e: Exception) {
                false
            }
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                binding.dnsChainStatus.text = if (up) {
                    getString(R.string.dns_chain_status_running, address)
                } else {
                    getString(R.string.dns_chain_status_stopped)
                }
            }
        }
    }

    private fun showError(message: String?) {
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.error_title)
            .setMessage(message)
            .setPositiveButton(android.R.string.ok, null)
            .show()
    }

    private fun save() {
        val doh = binding.dohInput.text?.toString().orEmpty().trim()
        val user = binding.userInput.text?.toString().orEmpty()
        val pass = binding.passInput.text?.toString().orEmpty()
        val autoClose = binding.autoCloseSwitch.isChecked
        val idleText = binding.idleInput.text?.toString().orEmpty().trim()
        val idleSeconds = idleText.toIntOrNull()

        // validate before saving so a typo can never break the running proxy
        try {
            DnsChainConfig.parseDohText(doh)
        } catch (e: DnsChainConfig.ConfigException) {
            showError(e.message)
            return
        }
        if (!DnsChainSettings.checkLogin(user, pass)) {
            showError(getString(R.string.dns_chain_login_invalid))
            return
        }

        // the seconds only matter while "close after idle" is on
        if (autoClose && (idleSeconds == null || idleSeconds < 1 || idleSeconds > DnsChainSettings.MAX_IDLE_SECONDS)) {
            showError(getString(R.string.dns_chain_idle_invalid, DnsChainSettings.MAX_IDLE_SECONDS))
            return
        }

        DnsChainSettings.saveDoh(doh)
        DnsChainSettings.saveLogin(user, pass)
        DataStore.dnsChainAutoClose = autoClose
        if (idleSeconds != null && idleSeconds in 1..DnsChainSettings.MAX_IDLE_SECONDS) {
            DataStore.dnsChainIdleSeconds = idleSeconds
        }
        DnsChainService.reload(this) // applies the new settings if the proxy is up right now
        Toast.makeText(this, R.string.dns_chain_saved, Toast.LENGTH_SHORT).show()
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            android.R.id.home -> {
                finish()
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }
}

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
        }

        binding.dnsChainSave.setOnClickListener { save() }
        binding.dnsChainReset.setOnClickListener {
            // back to the DoH list written in setting.ini
            binding.dohInput.setText(ini?.dohServers?.joinToString("\n").orEmpty())
        }
    }

    override fun onResume() {
        super.onResume()
        updateStatus()
    }

    private fun updateStatus() {
        val error = iniError
        binding.dnsChainStatus.text = when {
            error != null -> error
            DnsChainService.running -> getString(R.string.dns_chain_status_running, address)
            else -> getString(R.string.dns_chain_status_stopped)
        }
    }

    private fun save() {
        val doh = binding.dohInput.text?.toString().orEmpty().trim()

        // validate before saving so a typo can never break the running proxy
        try {
            DnsChainConfig.parseDohText(doh)
        } catch (e: DnsChainConfig.ConfigException) {
            MaterialAlertDialogBuilder(this)
                .setTitle(R.string.error_title)
                .setMessage(e.message)
                .setPositiveButton(android.R.string.ok, null)
                .show()
            return
        }

        DnsChainSettings.saveDoh(doh)
        if (DataStore.dnsChainEnabled) {
            DnsChainService.start(this) // restart with the new settings
        }
        Toast.makeText(this, R.string.dns_chain_saved, Toast.LENGTH_SHORT).show()
        binding.dnsChainStatus.postDelayed({ updateStatus() }, 800)
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

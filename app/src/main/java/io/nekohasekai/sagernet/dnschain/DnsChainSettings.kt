package io.nekohasekai.sagernet.dnschain

import android.content.Context
import io.nekohasekai.sagernet.Key
import io.nekohasekai.sagernet.database.DataStore

/**
 * Loads DNS Chain settings.
 *
 * - Listen address, timeouts, log level ... always come from the bundled dns_chain.ini
 *   (app/src/main/assets/dns_chain.ini).
 * - The DoH list and the fragment parameters come from the boxes in the DNS Chain page once
 *   the user has saved them there; until then (or after "Reset") the values of dns_chain.ini are used.
 * - The proxy login (default admin / admin) is stored by the DNS Chain page.
 */
object DnsChainSettings {

    const val DEFAULT_ADDRESS = "127.0.0.1:40443"

    /** Reads and parses dns_chain.ini; throws DnsChainConfig.ConfigException / IOException. */
    fun loadIni(context: Context): DnsChainConfig {
        val text = context.applicationContext.assets.open(DnsChainConfig.INI_ASSET).use {
            String(it.readBytes(), Charsets.UTF_8)
        }
        return DnsChainConfig.fromIni(text)
    }

    /** Text for the DoH box: what the user saved, else the list from dns_chain.ini. */
    fun dohText(ini: DnsChainConfig?): String {
        val saved = DataStore.configurationStore.getString(Key.DNS_CHAIN_DOH)
        if (saved != null) return saved
        return ini?.dohServers?.joinToString("\n").orEmpty()
    }

    /** Text for the fragment box: what the user saved, else the enabled section of dns_chain.ini. */
    fun fragmentText(ini: DnsChainConfig?): String {
        val saved = DataStore.configurationStore.getString(Key.DNS_CHAIN_FRAGMENT)
        if (saved != null) return saved
        return ini?.fragmentText ?: DnsChainConfig.DEFAULT_FRAGMENT_TEXT
    }

    private fun same(a: String, b: String): Boolean =
        a.replace("\r\n", "\n").trim() == b.replace("\r\n", "\n").trim()

    /** Saves the DoH list; the value of dns_chain.ini is not stored (later edits of the ini keep working). */
    fun saveDoh(text: String, ini: DnsChainConfig?) {
        val fromIni = ini?.dohServers?.joinToString("\n").orEmpty()
        DataStore.configurationStore.putString(Key.DNS_CHAIN_DOH, if (ini != null && same(text, fromIni)) null else text)
    }

    fun saveFragment(text: String, ini: DnsChainConfig?) {
        val fromIni = ini?.fragmentText ?: DnsChainConfig.DEFAULT_FRAGMENT_TEXT
        DataStore.configurationStore.putString(Key.DNS_CHAIN_FRAGMENT, if (ini != null && same(text, fromIni)) null else text)
    }

    fun saveLogin(user: String, pass: String) {
        DataStore.dnsChainUser = user
        DataStore.dnsChainPass = pass
    }

    /** true when the login can be used by the proxy. */
    fun checkLogin(user: String, pass: String): Boolean {
        return user.isNotEmpty() && pass.isNotEmpty() && !user.contains(':') &&
                user.toByteArray(Charsets.UTF_8).size <= 255 &&
                pass.toByteArray(Charsets.UTF_8).size <= 255
    }

    /** dns_chain.ini + the user's DoH list, fragment parameters and login, ready for the proxy. */
    fun buildConfig(context: Context): DnsChainConfig {
        val config = loadIni(context)
        config.dohServers = DnsChainConfig.parseDohText(dohText(config))
        // a fragment box saved in the app replaces every fragment section of the ini
        val savedFragment = DataStore.configurationStore.getString(Key.DNS_CHAIN_FRAGMENT)
        if (savedFragment != null) {
            val rule = DnsChainConfig.parseFragmentText(savedFragment)
            config.rules = if (rule == null) emptyList() else listOf(rule)
        }
        config.username = DataStore.dnsChainUser
        config.password = DataStore.dnsChainPass
        return config
    }

    /** Changes when the proxy has to be restarted (DoH list or login). */
    fun signature(): String =
        (DataStore.configurationStore.getString(Key.DNS_CHAIN_DOH) ?: "\u0000") +
                "\u0001" + (DataStore.configurationStore.getString(Key.DNS_CHAIN_FRAGMENT) ?: "\u0000") +
                "\u0001" + DataStore.dnsChainUser + "\u0001" + DataStore.dnsChainPass

    const val MAX_IDLE_SECONDS = 86400

    fun address(config: DnsChainConfig): String = "${config.listenIp}:${config.listenPort}"

    /** Address for texts; never throws. */
    fun addressOrDefault(context: Context): String = try {
        address(loadIni(context))
    } catch (e: Exception) {
        DEFAULT_ADDRESS
    }
}

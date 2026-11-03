package io.nekohasekai.sagernet.dnschain

import android.content.Context
import io.nekohasekai.sagernet.Key
import io.nekohasekai.sagernet.database.DataStore

/**
 * Loads DNS Chain settings.
 *
 * - Everything except the DoH list always comes from the bundled setting.ini
 *   (app/src/main/assets/setting.ini): listen address, timeouts, fragment rules ...
 * - The DoH list comes from the box in the DNS Chain page once the user has saved it there;
 *   until then the DOH_xx entries of setting.ini are used.
 * - The proxy login (default admin / admin) is stored by the DNS Chain page.
 */
object DnsChainSettings {

    const val DEFAULT_ADDRESS = "127.0.0.1:40443"

    /** Reads and parses setting.ini; throws DnsChainConfig.ConfigException / IOException. */
    fun loadIni(context: Context): DnsChainConfig {
        val text = context.applicationContext.assets.open(DnsChainConfig.INI_ASSET).use {
            String(it.readBytes(), Charsets.UTF_8)
        }
        return DnsChainConfig.fromIni(text)
    }

    /** Text for the DoH box: what the user saved, else the list from setting.ini. */
    fun dohText(ini: DnsChainConfig?): String {
        val saved = DataStore.configurationStore.getString(Key.DNS_CHAIN_DOH)
        if (saved != null) return saved
        return ini?.dohServers?.joinToString("\n").orEmpty()
    }

    fun saveDoh(text: String) {
        DataStore.configurationStore.putString(Key.DNS_CHAIN_DOH, text)
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

    /** setting.ini + the user's DoH list and login, ready for the proxy. */
    fun buildConfig(context: Context): DnsChainConfig {
        val config = loadIni(context)
        config.dohServers = DnsChainConfig.parseDohText(dohText(config))
        config.username = DataStore.dnsChainUser
        config.password = DataStore.dnsChainPass
        return config
    }

    /** Changes when the proxy has to be restarted (DoH list or login). */
    fun signature(): String =
        (DataStore.configurationStore.getString(Key.DNS_CHAIN_DOH) ?: "\u0000") +
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

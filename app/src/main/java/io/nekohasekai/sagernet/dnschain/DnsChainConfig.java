package io.nekohasekai.sagernet.dnschain;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Configuration of the DNS Chain proxy (SOCKS5 / HTTP CONNECT + DNS-over-HTTPS + TLS fragmentation).
 * Everything comes from setting.ini (bundled as an Android asset), same format as the Python original.
 *
 * Pure Java, no Android dependency.
 */
public final class DnsChainConfig {

    /** Name of the bundled file (app/src/main/assets/setting.ini). */
    public static final String INI_ASSET = "setting.ini";

    public static final int LEVEL_DEBUG = 0;
    public static final int LEVEL_INFO = 1;
    public static final int LEVEL_WARN = 2;
    public static final int LEVEL_ERROR = 3;

    // ---- runtime settings (seconds unless noted) ----
    public String listenIp = "127.0.0.1";
    public int listenPort = 40443;
    public int idleTimeout = 300;            // 0 = disabled
    public double connectTimeout = 10;
    public double handshakeTimeout = 15;
    public double dohTimeout = 5;
    public double dohCooldown = 30;
    public double systemDnsTimeout = 5;
    public String testDomain = "example.com";
    public int logLevel = LEVEL_INFO;

    public List<String> dohServers = new ArrayList<String>();
    /** Enabled fragment rules in file order; the first matching rule is applied. */
    public List<FragmentRule> rules = new ArrayList<FragmentRule>();
    /** Non-fatal problems found while reading the ini (skipped lines / sections). */
    public final List<String> warnings = new ArrayList<String>();

    public static final class ConfigException extends Exception {
        public ConfigException(String message) {
            super(message);
        }
    }

    public static final class FragmentRule {
        public final String name;
        /** true = only the first TLS ClientHello packet. */
        public final boolean tlsHello;
        public final int start;
        /** -1 = open ended. */
        public final int end;
        /** each item is {lo, hi}; a single number N is {N, N}. */
        public final List<int[]> lengths;
        /** seconds */
        public final double delay;
        public final int maxSplit;
        public final boolean splitSni;

        FragmentRule(String name, boolean tlsHello, int start, int end, List<int[]> lengths,
                     double delay, int maxSplit, boolean splitSni) {
            this.name = name;
            this.tlsHello = tlsHello;
            this.start = start;
            this.end = end;
            this.lengths = Collections.unmodifiableList(lengths);
            this.delay = delay;
            this.maxSplit = maxSplit;
            this.splitSni = splitSni;
        }
    }

    // ------------------------------------------------------------------
    // ini reader (same rules as Python's configparser for this file)
    // ------------------------------------------------------------------

    private static String stripInlineComment(String v) {
        // " ; comment" / " # comment" (needs whitespace before the marker)
        for (int i = 1; i < v.length(); i++) {
            char c = v.charAt(i);
            if ((c == ';' || c == '#') && Character.isWhitespace(v.charAt(i - 1))) {
                return v.substring(0, i).trim();
            }
        }
        return v;
    }

    static LinkedHashMap<String, LinkedHashMap<String, String>> parseIni(String text) throws ConfigException {
        LinkedHashMap<String, LinkedHashMap<String, String>> sections =
                new LinkedHashMap<String, LinkedHashMap<String, String>>();
        if (text == null) text = "";
        if (text.length() > 0 && text.charAt(0) == '\uFEFF') text = text.substring(1);
        LinkedHashMap<String, String> current = null;
        String[] lines = text.split("\r\n|\n|\r");
        for (int i = 0; i < lines.length; i++) {
            String t = lines[i].trim();
            if (t.isEmpty() || t.charAt(0) == ';' || t.charAt(0) == '#') continue;
            if (t.charAt(0) == '[') {
                int e = t.indexOf(']');
                if (e < 0) throw new ConfigException("setting.ini line " + (i + 1) + ": missing ']'");
                String name = t.substring(1, e).trim();
                current = sections.get(name);
                if (current == null) {
                    current = new LinkedHashMap<String, String>();
                    sections.put(name, current);
                }
                continue;
            }
            if (current == null) {
                throw new ConfigException("setting.ini line " + (i + 1) + ": setting outside of a [section]");
            }
            int eq = -1;
            for (int k = 0; k < t.length(); k++) {
                char c = t.charAt(k);
                if (c == '=' || c == ':') {
                    eq = k;
                    break;
                }
            }
            if (eq <= 0) {
                throw new ConfigException("setting.ini line " + (i + 1) + ": expected 'key = value'  (" + t + ")");
            }
            String key = t.substring(0, eq).trim().toLowerCase(Locale.ROOT);
            String value = stripInlineComment(t.substring(eq + 1).trim());
            current.put(key, value);
        }
        return sections;
    }

    private static String get(Map<String, String> m, String key, String def) {
        String v = m.get(key);
        return v == null ? def : v;
    }

    private static int getInt(Map<String, String> m, String key, int def, String where) throws ConfigException {
        String v = m.get(key);
        if (v == null || v.isEmpty()) return def;
        try {
            return Integer.parseInt(v.trim());
        } catch (NumberFormatException e) {
            throw new ConfigException("setting.ini " + where + ": '" + key + "' must be a whole number (got '" + v + "')");
        }
    }

    private static double getDouble(Map<String, String> m, String key, double def, String where) throws ConfigException {
        String v = m.get(key);
        if (v == null || v.isEmpty()) return def;
        double d;
        try {
            d = Double.parseDouble(v.trim());
        } catch (NumberFormatException e) {
            throw new ConfigException("setting.ini " + where + ": '" + key + "' must be a number (got '" + v + "')");
        }
        if (Double.isNaN(d) || Double.isInfinite(d)) {
            throw new ConfigException("setting.ini " + where + ": '" + key + "' must be a number (got '" + v + "')");
        }
        return d;
    }

    /** Parses the complete setting.ini text. */
    public static DnsChainConfig fromIni(String text) throws ConfigException {
        LinkedHashMap<String, LinkedHashMap<String, String>> sections = parseIni(text);

        LinkedHashMap<String, String> proxy = null;
        for (Map.Entry<String, LinkedHashMap<String, String>> e : sections.entrySet()) {
            if (e.getKey().equalsIgnoreCase("proxy")) proxy = e.getValue();
        }
        if (proxy == null) throw new ConfigException("setting.ini: [proxy] section is missing");

        DnsChainConfig c = new DnsChainConfig();
        String where = "[proxy]";
        c.listenIp = get(proxy, "listen_ip", "127.0.0.1").trim();
        if (c.listenIp.isEmpty()) c.listenIp = "127.0.0.1";
        c.listenPort = getInt(proxy, "listen_port", 40443, where);
        if (c.listenPort < 1 || c.listenPort > 65535) {
            throw new ConfigException("setting.ini [proxy]: listen_port must be between 1 and 65535");
        }
        c.idleTimeout = getInt(proxy, "idle_timeout", 300, where);
        if (c.idleTimeout < 0) c.idleTimeout = 0;
        c.connectTimeout = getDouble(proxy, "connect_timeout", 10, where);
        c.handshakeTimeout = getDouble(proxy, "handshake_timeout", 15, where);
        c.dohTimeout = getDouble(proxy, "doh_timeout", 5, where);
        c.dohCooldown = getDouble(proxy, "doh_cooldown", 30, where);
        c.systemDnsTimeout = getDouble(proxy, "system_dns_timeout", 5, where);
        if (c.connectTimeout <= 0 || c.handshakeTimeout <= 0 || c.dohTimeout <= 0 || c.systemDnsTimeout <= 0) {
            throw new ConfigException("setting.ini [proxy]: timeouts must be greater than 0");
        }
        if (c.dohCooldown < 0) c.dohCooldown = 0;

        String domain = get(proxy, "domain", "").trim();
        domain = domain.replaceFirst("^[A-Za-z]+://", "");
        int slash = domain.indexOf('/');
        if (slash >= 0) domain = domain.substring(0, slash);
        int colon = domain.indexOf(':');
        if (colon >= 0) domain = domain.substring(0, colon);
        while (domain.endsWith(".")) domain = domain.substring(0, domain.length() - 1);
        c.testDomain = domain.isEmpty() ? "example.com" : domain;

        String lvl = get(proxy, "log_level", "INFO").trim().toUpperCase(Locale.ROOT);
        if (lvl.equals("DEBUG")) c.logLevel = LEVEL_DEBUG;
        else if (lvl.equals("WARNING") || lvl.equals("WARN")) c.logLevel = LEVEL_WARN;
        else if (lvl.equals("ERROR") || lvl.equals("CRITICAL")) c.logLevel = LEVEL_ERROR;
        else c.logLevel = LEVEL_INFO;

        // DoH list: DOH, DOH_01, DOH_2 ... sorted by number
        Pattern dohKey = Pattern.compile("doh(?:_?(\\d+))?");
        List<Object[]> found = new ArrayList<Object[]>();
        for (Map.Entry<String, String> e : proxy.entrySet()) {
            String key = e.getKey();
            Matcher m = dohKey.matcher(key);
            String value = e.getValue().trim();
            if (!m.matches() || value.isEmpty()) continue;
            if (!value.toLowerCase(Locale.ROOT).startsWith("https://")) {
                c.warnings.add(key + " ignored: DoH URL must start with https://");
                continue;
            }
            int num = 0;
            if (m.group(1) != null) {
                try {
                    num = Integer.parseInt(m.group(1));
                } catch (NumberFormatException ex) {
                    num = Integer.MAX_VALUE;
                }
            }
            found.add(new Object[]{Integer.valueOf(num), value});
        }
        Collections.sort(found, new Comparator<Object[]>() {
            @Override
            public int compare(Object[] a, Object[] b) {
                return ((Integer) a[0]).compareTo((Integer) b[0]);
            }
        });
        for (Object[] f : found) {
            String url = (String) f[1];
            if (!c.dohServers.contains(url)) c.dohServers.add(url);
        }

        // fragment rules: every other section whose name contains "fragment"
        for (Map.Entry<String, LinkedHashMap<String, String>> e : sections.entrySet()) {
            String name = e.getKey();
            if (name.equalsIgnoreCase("proxy")) continue;
            if (!name.toLowerCase(Locale.ROOT).contains("fragment")) {
                c.warnings.add("Section [" + name + "] ignored (name must contain 'fragment')");
                continue;
            }
            Map<String, String> sec = e.getValue();
            if (!get(sec, "enable", "0").trim().equals("1")) continue;
            try {
                c.rules.add(buildRule(name, sec));
            } catch (ConfigException ex) {
                c.warnings.add("Section [" + name + "] skipped, invalid config: " + ex.getMessage());
            }
        }
        return c;
    }

    // ------------------------------------------------------------------
    // DoH list typed in the app (one URL per line)
    // ------------------------------------------------------------------

    /**
     * One DoH URL per line. Empty lines and lines starting with # or ; are ignored.
     * "DOH_01 = https://..." (setting.ini style) is accepted too.
     */
    public static List<String> parseDohText(String text) throws ConfigException {
        List<String> out = new ArrayList<String>();
        if (text == null) return out;
        String[] lines = text.split("\r?\n|\r");
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i].trim();
            if (line.isEmpty() || line.charAt(0) == '#' || line.charAt(0) == ';') continue;

            int eq = line.indexOf('=');
            if (eq > 0) {
                String key = line.substring(0, eq).trim().toLowerCase(Locale.ROOT);
                if (key.matches("doh(_?\\d+)?")) {
                    line = line.substring(eq + 1).trim();
                    if (line.isEmpty()) continue;
                }
            }

            if (!line.toLowerCase(Locale.ROOT).startsWith("https://")) {
                throw new ConfigException("DoH line " + (i + 1)
                        + ": URL must start with https://  (" + line + ")");
            }
            String host;
            try {
                host = new URI(line).getHost();
            } catch (Exception e) {
                throw new ConfigException("DoH line " + (i + 1) + ": invalid URL (" + line + ")");
            }
            if (host == null || host.isEmpty()) {
                throw new ConfigException("DoH line " + (i + 1) + ": invalid URL (" + line + ")");
            }
            if (!out.contains(line)) out.add(line);
        }
        return out;
    }

    // ------------------------------------------------------------------
    // Fragment rule
    // ------------------------------------------------------------------

    private static int parseInt(String s, String what) throws ConfigException {
        try {
            return Integer.parseInt(s.trim());
        } catch (NumberFormatException e) {
            throw new ConfigException("Invalid number for " + what + ": '" + s.trim() + "'");
        }
    }

    /** '0,104,1' / '[10,1]' / '100-200,5' -> list of {lo,hi}. Negative single = "rest in one go". */
    static List<int[]> parseLengths(String raw) throws ConfigException {
        String s = raw.trim();
        while (s.length() > 0 && (s.charAt(0) == '[' || s.charAt(0) == ']')) s = s.substring(1);
        while (s.length() > 0 && (s.charAt(s.length() - 1) == '[' || s.charAt(s.length() - 1) == ']')) {
            s = s.substring(0, s.length() - 1);
        }
        List<int[]> out = new ArrayList<int[]>();
        for (String tok0 : s.split(",")) {
            String tok = tok0.trim();
            if (tok.isEmpty()) continue;
            int idx = tok.indexOf('-', 1);
            if (idx >= 0) {
                int lo = parseInt(tok.substring(0, idx), "lengths");
                int hi = parseInt(tok.substring(idx + 1), "lengths");
                if (lo > hi) {
                    int t = lo;
                    lo = hi;
                    hi = t;
                }
                if (lo < 0) throw new ConfigException("Invalid length range: '" + tok + "'");
                out.add(new int[]{lo, hi});
            } else {
                int n = parseInt(tok, "lengths");
                out.add(new int[]{n, n});
            }
        }
        if (out.isEmpty()) throw new ConfigException("lengths is empty");
        return out;
    }

    private static double parseDelaySeconds(String raw) throws ConfigException {
        String s = raw.toLowerCase(Locale.ROOT).replace("ms", "").trim();
        double ms;
        try {
            ms = Double.parseDouble(s);
        } catch (NumberFormatException e) {
            throw new ConfigException("Invalid delay: '" + raw.trim() + "' (example: 0 ms)");
        }
        if (Double.isNaN(ms) || Double.isInfinite(ms) || ms < 0) {
            throw new ConfigException("Invalid delay: '" + raw.trim() + "'");
        }
        return ms / 1000.0;
    }

    private static boolean parseBool(String raw, String what) throws ConfigException {
        String s = raw.trim().toLowerCase(Locale.ROOT);
        if (s.equals("1") || s.equals("true") || s.equals("yes") || s.equals("on")) return true;
        if (s.equals("0") || s.equals("false") || s.equals("no") || s.equals("off")) return false;
        throw new ConfigException("Invalid value for " + what + ": '" + raw.trim() + "' (use 1 or 0)");
    }

    /**
     * packets and lengths are required. Missing delay / maxSplit / splitSNI behave like the
     * Python original (0 ms / unlimited / 0).
     */
    static FragmentRule buildRule(String name, Map<String, String> sec) throws ConfigException {
        String packets = get(sec, "packets", null);
        String lengths = get(sec, "lengths", null);
        String delay = get(sec, "delay", null);
        String maxSplit = get(sec, "maxsplit", null);
        String splitSni = get(sec, "splitsni", null);

        if (packets == null || packets.trim().isEmpty()) {
            throw new ConfigException("'packets' is required (example: tlshello or 1-3)");
        }
        if (lengths == null || lengths.trim().isEmpty()) {
            throw new ConfigException("'lengths' is required (example: 0,10,1)");
        }

        boolean tlsHello = false;
        int start = 0, end = -1;
        String p = packets.trim().toLowerCase(Locale.ROOT);
        if (p.equals("tlshello")) {
            tlsHello = true;
        } else {
            int dash = p.indexOf('-');
            if (dash >= 0) {
                start = parseInt(p.substring(0, dash), "packets");
                String b = p.substring(dash + 1).trim();
                end = (b.isEmpty() || b.equals("~")) ? -1 : parseInt(b, "packets");
            } else {
                start = parseInt(p, "packets");
                end = start;
            }
            if (start < 1) throw new ConfigException("packets must start at 1 or higher");
            if (end != -1 && end < start) throw new ConfigException("Invalid packets range: '" + packets.trim() + "'");
        }

        List<int[]> lens = parseLengths(lengths);
        double delaySec = (delay == null || delay.trim().isEmpty()) ? 0.0 : parseDelaySeconds(delay);
        int max = (maxSplit == null || maxSplit.trim().isEmpty()) ? 0 : parseInt(maxSplit, "maxSplit");
        if (max < 0) throw new ConfigException("maxSplit must be 0 (unlimited) or a positive number");
        boolean sni = (splitSni != null && !splitSni.trim().isEmpty()) && parseBool(splitSni, "splitSNI");

        return new FragmentRule(name, tlsHello, start, end, lens, delaySec, max, sni);
    }
}

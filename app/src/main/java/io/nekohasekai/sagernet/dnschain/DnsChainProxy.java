package io.nekohasekai.sagernet.dnschain;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.IDN;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * SOCKS5 / HTTP CONNECT proxy with TLS fragmentation and DNS-over-HTTPS.
 * Java port of the original Python script (main_03.py). Pure Java, no Android dependency.
 */
public final class DnsChainProxy {

    public interface Logger {
        void log(int level, String message);
    }

    public static final int DEBUG = 0;
    public static final int INFO = 1;
    public static final int WARN = 2;
    public static final int ERROR = 3;

    private static final int READ_SIZE = 16384;
    private static final int MAX_TLS_RECORD = 5 + 16384 + 2048;
    private static final double DOH_COOLDOWN_MAX = 300.0;
    private static final long NEG_CACHE_TTL_NANOS = 20L * 1000000000L;
    private static final int DNS_CACHE_MAX = 2048;
    private static final int MAX_HTTP_HEADER = 65536;
    private static final byte[] EMPTY = new byte[0];

    private static final int SOCKS_OK = 0x00;
    private static final int SOCKS_GENERAL_FAILURE = 0x01;
    private static final int SOCKS_HOST_UNREACHABLE = 0x04;
    private static final int SOCKS_CONN_REFUSED = 0x05;
    private static final int SOCKS_CMD_UNSUPPORTED = 0x07;
    private static final int SOCKS_ATYP_UNSUPPORTED = 0x08;

    private final DnsChainConfig cfg;
    private final Logger logger;
    private final Random random = new Random();
    private final ExecutorService pool;
    private final Set<Socket> openSockets =
            Collections.newSetFromMap(new ConcurrentHashMap<Socket, Boolean>());

    private volatile boolean running;
    private ServerSocket server;

    // ---- DNS state ----
    static final class Answer {
        final String ip;
        final long ttl;

        Answer(String ip, long ttl) {
            this.ip = ip;
            this.ttl = ttl;
        }
    }

    private static final class CacheEntry {
        final String ip;
        final long expiresAt;

        CacheEntry(String ip, long expiresAt) {
            this.ip = ip;
            this.expiresAt = expiresAt;
        }
    }

    private static final class Health {
        int fails;
        boolean cooling;
        long until;
    }

    private final Map<String, CacheEntry> dnsCache = new ConcurrentHashMap<String, CacheEntry>();
    private final Map<String, Long> negCache = new ConcurrentHashMap<String, Long>();
    private final Map<String, java.util.concurrent.FutureTask<String>> inflight =
            new ConcurrentHashMap<String, java.util.concurrent.FutureTask<String>>();
    private final Map<String, Health> health = new java.util.HashMap<String, Health>();

    public DnsChainProxy(DnsChainConfig cfg, Logger logger) {
        this.cfg = cfg;
        this.logger = logger;
        final AtomicInteger counter = new AtomicInteger();
        this.pool = Executors.newCachedThreadPool(new ThreadFactory() {
            @Override
            public Thread newThread(Runnable r) {
                Thread t = new Thread(r, "dnschain-" + counter.incrementAndGet());
                t.setDaemon(true);
                return t;
            }
        });
    }

    private void log(int level, String msg) {
        if (level < cfg.logLevel) return;
        try {
            logger.log(level, msg);
        } catch (Throwable ignored) {
        }
    }

    // ==================================================================
    // Lifecycle
    // ==================================================================

    public synchronized void start() throws IOException {
        if (running) return;
        ServerSocket s = new ServerSocket();
        try {
            s.setReuseAddress(true);
            s.bind(new InetSocketAddress(InetAddress.getByName(cfg.listenIp), cfg.listenPort), 128);
        } catch (IOException e) {
            closeQuietly(s);
            throw e;
        }
        server = s;
        running = true;

        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                acceptLoop();
            }
        }, "dnschain-accept");
        t.setDaemon(true);
        t.start();

        log(INFO, "Proxy listening on " + cfg.listenIp + ":" + cfg.listenPort
                + ", DoH servers: " + cfg.dohServers.size()
                + ", fragment rules: " + cfg.rules.size());
        for (String w : cfg.warnings) log(WARN, w);

        try {
            pool.execute(new Runnable() {
                @Override
                public void run() {
                    warmUpDoh();
                }
            });
        } catch (RejectedExecutionException ignored) {
        }
    }

    public synchronized void stop() {
        running = false;
        closeQuietly(server);
        server = null;
        for (Socket s : new ArrayList<Socket>(openSockets)) closeQuietly(s);
        openSockets.clear();
        pool.shutdownNow();
        log(INFO, "Proxy stopped");
    }

    public boolean isRunning() {
        return running;
    }

    private void acceptLoop() {
        while (running) {
            Socket c;
            try {
                c = server.accept();
            } catch (IOException e) {
                if (!running) break;
                log(WARN, "accept failed: " + e);
                try {
                    Thread.sleep(50);
                } catch (InterruptedException ie) {
                    break;
                }
                continue;
            } catch (RuntimeException e) {
                break;
            }
            final Socket client = c;
            try {
                pool.execute(new Runnable() {
                    @Override
                    public void run() {
                        handleConnection(client);
                    }
                });
            } catch (RejectedExecutionException e) {
                closeQuietly(client);
                break;
            }
        }
    }

    // ==================================================================
    // Helpers
    // ==================================================================

    private static void closeQuietly(Closeable c) {
        if (c == null) return;
        try {
            c.close();
        } catch (Throwable ignored) {
        }
    }

    private static void closeQuietly(Socket s) {
        if (s == null) return;
        try {
            s.close();
        } catch (Throwable ignored) {
        }
    }

    private static String why(Throwable e) {
        if (e == null) return "error";
        String m = e.getMessage();
        return (m == null || m.isEmpty()) ? e.getClass().getSimpleName()
                : e.getClass().getSimpleName() + ": " + m;
    }

    private static int toMs(double seconds) {
        long ms = Math.round(seconds * 1000.0);
        if (ms < 1) ms = 1;
        if (ms > Integer.MAX_VALUE) ms = Integer.MAX_VALUE;
        return (int) ms;
    }

    private void sleepSeconds(double seconds) throws IOException {
        if (seconds <= 0) return;
        long nanos = (long) (seconds * 1e9);
        try {
            Thread.sleep(nanos / 1000000L, (int) (nanos % 1000000L));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted");
        }
    }

    private void tune(Socket s) {
        try {
            s.setTcpNoDelay(true);
        } catch (Throwable ignored) {
        }
        try {
            s.setKeepAlive(true);
        } catch (Throwable ignored) {
        }
    }

    static boolean isIpLiteral(String h) {
        if (h == null || h.isEmpty()) return false;
        if (h.indexOf(':') >= 0) {
            for (int i = 0; i < h.length(); i++) {
                char c = h.charAt(i);
                boolean ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
                        || c == ':' || c == '.';
                if (!ok) return false;
            }
            try {
                InetAddress.getByName(h);
                return true;
            } catch (Exception e) {
                return false;
            }
        }
        String[] parts = h.split("\\.", -1);
        if (parts.length != 4) return false;
        for (String p : parts) {
            if (p.isEmpty() || p.length() > 3) return false;
            for (int i = 0; i < p.length(); i++) {
                if (p.charAt(i) < '0' || p.charAt(i) > '9') return false;
            }
            if (Integer.parseInt(p) > 255) return false;
        }
        return true;
    }

    // ==================================================================
    // DNS over HTTPS
    // ==================================================================

    static byte[] buildDnsQuery(String domain, int qtype) {
        String d = domain;
        while (d.endsWith(".")) d = d.substring(0, d.length() - 1);
        if (d.isEmpty()) throw new IllegalArgumentException("empty domain");
        String ascii = IDN.toASCII(d);
        String[] labels = ascii.split("\\.", -1);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        // id=0 (RFC 8484), flags=0x0100 (RD), qdcount=1
        out.write(0);
        out.write(0);
        out.write(0x01);
        out.write(0x00);
        out.write(0);
        out.write(1);
        for (int i = 0; i < 6; i++) out.write(0);
        int total = 0;
        for (String label : labels) {
            byte[] b = label.getBytes(StandardCharsets.US_ASCII);
            if (b.length == 0 || b.length > 63) throw new IllegalArgumentException("invalid label");
            total += b.length + 1;
            out.write(b.length);
            out.write(b, 0, b.length);
        }
        if (total > 253) throw new IllegalArgumentException("domain too long");
        out.write(0);
        out.write((qtype >> 8) & 0xFF);
        out.write(qtype & 0xFF);
        out.write(0);
        out.write(1);
        return out.toByteArray();
    }

    private static int skipName(byte[] data, int off) {
        while (true) {
            int length = data[off] & 0xFF;
            if (length == 0) return off + 1;
            if ((length & 0xC0) == 0xC0) return off + 2;
            off += length + 1;
        }
    }

    private static int u16(byte[] d, int p) {
        return ((d[p] & 0xFF) << 8) | (d[p + 1] & 0xFF);
    }

    /** Returns (ip, ttl) of the first A/AAAA record, else null. */
    static Answer parseDnsResponse(byte[] data, int qtype) {
        try {
            if (data.length < 12 || (data[3] & 0x0F) != 0) return null;
            int qd = u16(data, 4);
            int an = u16(data, 6);
            int off = 12;
            for (int i = 0; i < qd; i++) off = skipName(data, off) + 4;
            for (int i = 0; i < an; i++) {
                off = skipName(data, off);
                int rtype = u16(data, off);
                long ttl = ((long) (data[off + 4] & 0xFF) << 24) | ((data[off + 5] & 0xFF) << 16)
                        | ((data[off + 6] & 0xFF) << 8) | (data[off + 7] & 0xFF);
                int rdlen = u16(data, off + 8);
                off += 10;
                if (rtype == qtype) {
                    if (qtype == 1 && rdlen == 4) {
                        String ip = (data[off] & 0xFF) + "." + (data[off + 1] & 0xFF) + "."
                                + (data[off + 2] & 0xFF) + "." + (data[off + 3] & 0xFF);
                        return new Answer(ip, ttl);
                    }
                    if (qtype == 28 && rdlen == 16) {
                        byte[] raw = Arrays.copyOfRange(data, off, off + 16);
                        return new Answer(InetAddress.getByAddress(raw).getHostAddress(), ttl);
                    }
                }
                off += rdlen;
            }
        } catch (RuntimeException e) {
            // truncated / malformed
        } catch (UnknownHostException e) {
            // cannot happen for 16 raw bytes
        }
        return null;
    }

    private static final char[] B64URL =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".toCharArray();

    static String base64UrlNoPad(byte[] in) {
        StringBuilder sb = new StringBuilder((in.length * 4 + 2) / 3);
        int i = 0;
        while (i + 2 < in.length) {
            int v = ((in[i] & 0xFF) << 16) | ((in[i + 1] & 0xFF) << 8) | (in[i + 2] & 0xFF);
            sb.append(B64URL[(v >> 18) & 63]).append(B64URL[(v >> 12) & 63])
                    .append(B64URL[(v >> 6) & 63]).append(B64URL[v & 63]);
            i += 3;
        }
        int rem = in.length - i;
        if (rem == 1) {
            int v = (in[i] & 0xFF) << 16;
            sb.append(B64URL[(v >> 18) & 63]).append(B64URL[(v >> 12) & 63]);
        } else if (rem == 2) {
            int v = ((in[i] & 0xFF) << 16) | ((in[i + 1] & 0xFF) << 8);
            sb.append(B64URL[(v >> 18) & 63]).append(B64URL[(v >> 12) & 63])
                    .append(B64URL[(v >> 6) & 63]);
        }
        return sb.toString();
    }

    /** One DoH request; can be cancelled from another thread. */
    private final class DohAttempt implements Callable<Answer> {
        final String url;
        final String domain;
        final int qtype;
        volatile HttpURLConnection conn;
        volatile boolean cancelled;
        volatile long rttNanos;

        DohAttempt(String url, String domain, int qtype) {
            this.url = url;
            this.domain = domain;
            this.qtype = qtype;
        }

        void cancel() {
            cancelled = true;
            HttpURLConnection c = conn;
            if (c != null) {
                try {
                    c.disconnect();
                } catch (Throwable ignored) {
                }
            }
        }

        @Override
        public Answer call() throws Exception {
            long t0 = System.nanoTime();
            Answer a = query();
            rttNanos = System.nanoTime() - t0;
            return a;
        }

        private Answer query() throws Exception {
            byte[] q = buildDnsQuery(domain, qtype);
            URI u = new URI(url);
            String path = u.getRawPath();
            if (path == null || path.isEmpty()) path = "/dns-query";
            URL target = new URI("https://" + u.getRawAuthority() + path + "?dns=" + base64UrlNoPad(q)).toURL();

            // Proxy.NO_PROXY: never go through a system/VPN HTTP proxy (would loop back).
            HttpURLConnection c = (HttpURLConnection) target.openConnection(Proxy.NO_PROXY);
            conn = c;
            if (cancelled) {
                c.disconnect();
                throw new IOException("cancelled");
            }
            try {
                int to = toMs(cfg.dohTimeout);
                c.setConnectTimeout(to);
                c.setReadTimeout(to);
                c.setUseCaches(false);
                c.setInstanceFollowRedirects(false);
                c.setRequestMethod("GET");
                c.setRequestProperty("Accept", "application/dns-message");
                c.setRequestProperty("Connection", "close");

                int code = c.getResponseCode();
                if (code != 200) throw new IOException("DoH server returned HTTP " + code);

                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                byte[] tmp = new byte[4096];
                InputStream is = c.getInputStream();
                try {
                    int n;
                    while (bos.size() < 65536 && (n = is.read(tmp)) > 0) bos.write(tmp, 0, n);
                } catch (IOException e) {
                    // some servers close without a clean TLS shutdown; keep what we have
                    if (bos.size() == 0) throw e;
                } finally {
                    closeQuietly(is);
                }
                if (bos.size() == 0) throw new IOException("empty DoH response");
                return parseDnsResponse(bos.toByteArray(), qtype);
            } finally {
                try {
                    c.disconnect();
                } catch (Throwable ignored) {
                }
            }
        }
    }

    // ---- server health ----
    private void markOk(String url, double rttSeconds) {
        synchronized (health) {
            Health h = health.get(url);
            if (h == null) {
                h = new Health();
                health.put(url, h);
            }
            if (h.fails > 0) {
                log(INFO, "DoH " + url + " is back (" + Math.round(rttSeconds * 1000) + " ms)");
            }
            h.fails = 0;
            h.cooling = false;
        }
    }

    private void markFail(String url, String reason) {
        synchronized (health) {
            Health h = health.get(url);
            if (h == null) {
                h = new Health();
                health.put(url, h);
            }
            h.fails++;
            double cooldown = Math.min(cfg.dohCooldown * Math.pow(2, Math.min(h.fails - 1, 10)), DOH_COOLDOWN_MAX);
            h.until = System.nanoTime() + (long) (cooldown * 1e9);
            h.cooling = true;
            if (h.fails == 1) {
                log(WARN, "DoH " + url + " failed (" + reason + ") - paused for " + Math.round(cooldown) + "s");
            } else {
                log(DEBUG, "DoH " + url + " failed again (" + reason + ") - paused for " + Math.round(cooldown) + "s");
            }
        }
    }

    private List<String> activeServers() {
        long now = System.nanoTime();
        List<String> active = new ArrayList<String>();
        synchronized (health) {
            for (String u : cfg.dohServers) {
                Health h = health.get(u);
                if (h == null || !h.cooling || h.until - now <= 0) active.add(u);
            }
        }
        if (active.isEmpty()) return new ArrayList<String>(cfg.dohServers);
        return active;
    }

    private static final class RaceResult {
        final Answer answer;
        final boolean answered;

        RaceResult(Answer answer, boolean answered) {
            this.answer = answer;
            this.answered = answered;
        }
    }

    /** Sends the query to all healthy servers at once; the first reply wins. */
    private RaceResult raceDoh(String domain, int qtype) {
        List<String> servers = activeServers();
        ExecutorCompletionService<Answer> ecs = new ExecutorCompletionService<Answer>(pool);
        Map<Future<Answer>, DohAttempt> attempts = new IdentityHashMap<Future<Answer>, DohAttempt>();
        Set<Future<Answer>> pending = Collections.newSetFromMap(new IdentityHashMap<Future<Answer>, Boolean>());
        try {
            for (String url : servers) {
                DohAttempt a = new DohAttempt(url, domain, qtype);
                Future<Answer> f = ecs.submit(a);
                attempts.put(f, a);
                pending.add(f);
            }
            long deadline = System.nanoTime() + (long) (cfg.dohTimeout * 1e9);
            boolean timedOut = false;
            while (!pending.isEmpty()) {
                long remaining = deadline - System.nanoTime();
                if (remaining <= 0) {
                    timedOut = true;
                    break;
                }
                Future<Answer> f = ecs.poll(remaining, TimeUnit.NANOSECONDS);
                if (f == null) {
                    timedOut = true;
                    break;
                }
                pending.remove(f);
                DohAttempt a = attempts.get(f);
                try {
                    Answer ans = f.get();
                    markOk(a.url, a.rttNanos / 1e9);
                    log(DEBUG, "DoH winner for " + domain + ": " + a.url + " (" + (a.rttNanos / 1000000L) + " ms)");
                    return new RaceResult(ans, true);
                } catch (ExecutionException e) {
                    markFail(a.url, why(e.getCause()));
                }
            }
            if (timedOut) {
                for (Future<Answer> f : pending) markFail(attempts.get(f).url, "timeout");
            }
            log(WARN, "No DoH server answered for " + domain);
            return new RaceResult(null, false);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new RaceResult(null, false);
        } catch (RejectedExecutionException e) {
            return new RaceResult(null, false);
        } finally {
            for (DohAttempt a : attempts.values()) a.cancel();
        }
    }

    private String resolveDohUncached(String domain) {
        try {
            buildDnsQuery(domain, 1); // an invalid domain must not be blamed on the servers
        } catch (RuntimeException e) {
            return null;
        }
        int[] types = {1, 28}; // A, then AAAA
        for (int qtype : types) {
            RaceResult r = raceDoh(domain, qtype);
            if (r.answer != null) {
                if (dnsCache.size() >= DNS_CACHE_MAX) dnsCache.clear();
                long ttl = Math.min(Math.max(r.answer.ttl, 30L), 3600L);
                dnsCache.put(domain, new CacheEntry(r.answer.ip, System.nanoTime() + ttl * 1000000000L));
                return r.answer.ip;
            }
            if (!r.answered) return null; // nobody answered; do not waste time on AAAA
        }
        return null;
    }

    private String resolveWithDoh(final String domain) {
        if (cfg.dohServers.isEmpty()) return null;
        Long neg = negCache.get(domain);
        if (neg != null && neg.longValue() - System.nanoTime() > 0) return null;

        // concurrent requests for one domain share a single race
        java.util.concurrent.FutureTask<String> task = new java.util.concurrent.FutureTask<String>(
                new Callable<String>() {
                    @Override
                    public String call() {
                        return resolveDohUncached(domain);
                    }
                });
        java.util.concurrent.FutureTask<String> existing = inflight.putIfAbsent(domain, task);
        String ip = null;
        try {
            if (existing == null) {
                try {
                    task.run();
                } finally {
                    inflight.remove(domain);
                }
                ip = task.get();
            } else {
                ip = existing.get(30, TimeUnit.SECONDS);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (ExecutionException e) {
            ip = null;
        } catch (TimeoutException e) {
            ip = null;
        }

        if (ip == null) {
            if (negCache.size() >= DNS_CACHE_MAX) negCache.clear();
            negCache.put(domain, System.nanoTime() + NEG_CACHE_TTL_NANOS);
        }
        return ip;
    }

    /** Health-probes every DoH server at start-up so broken ones are skipped from the first request. */
    private void warmUpDoh() {
        if (cfg.dohServers.isEmpty()) return;
        List<DohAttempt> attempts = new ArrayList<DohAttempt>();
        List<Future<Answer>> futures = new ArrayList<Future<Answer>>();
        try {
            for (String url : cfg.dohServers) {
                DohAttempt a = new DohAttempt(url, cfg.testDomain, 1);
                attempts.add(a);
                futures.add(pool.submit(a));
            }
            for (int i = 0; i < futures.size(); i++) {
                DohAttempt a = attempts.get(i);
                try {
                    Answer ans = futures.get(i).get(toMs(cfg.dohTimeout) + 1000L, TimeUnit.MILLISECONDS);
                    markOk(a.url, a.rttNanos / 1e9);
                    log(INFO, "DoH OK      " + a.url + " (" + (a.rttNanos / 1000000L) + " ms)"
                            + (ans == null ? " [no A record for " + cfg.testDomain + "]" : ""));
                } catch (ExecutionException e) {
                    markFail(a.url, why(e.getCause()));
                } catch (TimeoutException e) {
                    a.cancel();
                    markFail(a.url, "timeout");
                }
            }
            int good = 0;
            synchronized (health) {
                for (String u : cfg.dohServers) {
                    Health h = health.get(u);
                    if (h == null || h.fails == 0) good++;
                }
            }
            log(INFO, "DoH ready: " + good + "/" + cfg.dohServers.size() + " servers responding");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (RejectedExecutionException e) {
            // stopping
        } finally {
            for (DohAttempt a : attempts) a.cancel();
        }
    }

    private static String firstAddress(InetAddress[] all) throws UnknownHostException {
        if (all == null || all.length == 0) throw new UnknownHostException("no address");
        for (InetAddress a : all) {
            if (a instanceof java.net.Inet4Address) return a.getHostAddress(); // IPv4 first
        }
        return all[0].getHostAddress();
    }

    String resolveHost(final String host) throws IOException {
        if (isIpLiteral(host)) return host;

        CacheEntry cached = dnsCache.get(host);
        if (cached != null && cached.expiresAt - System.nanoTime() > 0) return cached.ip;

        if (!cfg.dohServers.isEmpty()) {
            String ip = resolveWithDoh(host);
            if (ip != null) {
                log(DEBUG, "DoH resolved " + host + " -> " + ip);
                return ip;
            }
        }

        // fallback: system DNS (with timeout)
        Future<String> f;
        try {
            f = pool.submit(new Callable<String>() {
                @Override
                public String call() throws Exception {
                    return firstAddress(InetAddress.getAllByName(host));
                }
            });
        } catch (RejectedExecutionException e) {
            throw new IOException("stopping");
        }
        try {
            return f.get(toMs(cfg.systemDnsTimeout), TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            f.cancel(true);
            throw new SocketTimeoutException("system DNS timeout for " + host);
        } catch (ExecutionException e) {
            throw new UnknownHostException(host);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted");
        }
    }

    // ==================================================================
    // TLS helpers + fragmentation
    // ==================================================================

    static boolean isTlsClientHello(byte[] d) {
        return d.length >= 6 && d[0] == 0x16 && d[1] == 0x03 && d[5] == 0x01;
    }

    /** Returns {offset, length} of the SNI host name inside a ClientHello, or null. */
    static int[] findSni(byte[] data) {
        try {
            if (!isTlsClientHello(data)) return null;
            int pos = 5 + 4 + 2 + 32; // record hdr + handshake hdr + version + random
            pos += 1 + (data[pos] & 0xFF);              // session id
            pos += 2 + u16(data, pos);                  // cipher suites
            pos += 1 + (data[pos] & 0xFF);              // compression
            int extTotal = u16(data, pos);
            pos += 2;
            int end = Math.min(pos + extTotal, data.length);
            while (pos + 4 <= end) {
                int etype = u16(data, pos);
                int elen = u16(data, pos + 2);
                pos += 4;
                if (etype == 0) { // server_name: list_len(2) name_type(1) name_len(2) name
                    int nameLen = u16(data, pos + 3);
                    int nameOff = pos + 5;
                    if (nameOff + nameLen <= data.length) return new int[]{nameOff, nameLen};
                    return null;
                }
                pos += elen;
            }
        } catch (RuntimeException e) {
            // truncated
        }
        return null;
    }

    private void sendChunks(OutputStream out, byte[][] chunks, double delay) throws IOException {
        for (int i = 0; i < chunks.length; i++) {
            byte[] chunk = chunks[i];
            if (chunk.length == 0) continue;
            out.write(chunk);
            out.flush();
            if (delay > 0 && i < chunks.length - 1) sleepSeconds(delay);
        }
    }

    /**
     * length > 0: send that many bytes (or a random number in a-b);
     * length == 0: send nothing, only count a split and wait;
     * length < 0: send the rest in one go;
     * maxSplit == 0: unlimited; otherwise at most N pieces, the rest is sent untouched.
     * When the list runs out the last value repeats (if it is 0 the rest goes in one go).
     */
    private void fragmentDataLens(OutputStream out, byte[] data, List<int[]> lengths,
                                  double delay, int maxSplit) throws IOException {
        int total = data.length;
        int offset = 0;
        int splits = 0;
        int idx = 0;

        while (offset < total) {
            if (maxSplit > 0 && splits >= maxSplit) break;

            int lo, hi;
            if (idx < lengths.size()) {
                lo = lengths.get(idx)[0];
                hi = lengths.get(idx)[1];
            } else {
                int[] last = lengths.get(lengths.size() - 1);
                lo = last[0];
                hi = last[1];
                if (hi == 0) break; // avoid an endless loop
            }
            int length = (lo == hi) ? lo : lo + random.nextInt(hi - lo + 1);

            if (length < 0) break;

            splits++;
            idx++;

            if (length == 0) {
                if (delay > 0) sleepSeconds(delay);
                continue;
            }

            int n = Math.min(length, total - offset);
            out.write(data, offset, n);
            out.flush();
            offset += n;

            if (delay > 0 && offset < total) sleepSeconds(delay);
        }

        if (offset < total) {
            out.write(data, offset, total - offset);
            out.flush();
        }
    }

    private static boolean ruleMatches(DnsChainConfig.FragmentRule rule, int packetNum, byte[] data) {
        if (rule.tlsHello) return packetNum == 1 && isTlsClientHello(data);
        return packetNum >= rule.start && (rule.end < 0 || packetNum <= rule.end);
    }

    /** Returns true if a rule was applied (data already sent). First matching rule wins. */
    boolean applyFragmentation(OutputStream out, byte[] data, int packetNum) throws IOException {
        for (DnsChainConfig.FragmentRule rule : cfg.rules) {
            if (!ruleMatches(rule, packetNum, data)) continue;

            if (rule.splitSni) {
                // SNI mode: the only thing done is one cut in the middle of the host name;
                // if there is no SNI the data goes out untouched
                int[] sni = findSni(data);
                if (sni == null) return false;
                int cut = sni[0] + Math.max(1, sni[1] / 2);
                sendChunks(out, new byte[][]{
                        Arrays.copyOfRange(data, 0, cut),
                        Arrays.copyOfRange(data, cut, data.length)
                }, rule.delay);
                return true;
            }
            fragmentDataLens(out, data, rule.lengths, rule.delay, rule.maxSplit);
            return true;
        }
        return false;
    }

    // ==================================================================
    // Streaming
    // ==================================================================

    /** First client data; if it is a TLS record the whole record is read. */
    private byte[] readFirstClientChunk(InputStream in, byte[] buf, Socket sock) throws IOException {
        int n = in.read(buf);
        if (n < 0) return EMPTY;
        byte[] data = Arrays.copyOf(buf, n);
        if (n >= 5 && (data[0] & 0xFF) == 0x16 && (data[1] & 0xFF) == 0x03) {
            int need = Math.min(5 + (((data[3] & 0xFF) << 8) | (data[4] & 0xFF)), MAX_TLS_RECORD);
            if (data.length < need) {
                int prev = sock.getSoTimeout();
                sock.setSoTimeout(toMs(cfg.handshakeTimeout));
                try {
                    byte[] acc = Arrays.copyOf(data, need);
                    int filled = data.length;
                    while (filled < need) {
                        int m = in.read(acc, filled, need - filled);
                        if (m < 0) break;
                        filled += m;
                    }
                    data = Arrays.copyOf(acc, filled);
                } finally {
                    sock.setSoTimeout(prev);
                }
            }
        }
        return data;
    }

    /** Returns true on clean EOF, false on error/timeout. */
    private boolean forward(InputStream in, OutputStream out, boolean isClient,
                            Socket srcSock, Socket dstSock) {
        int packetNum = 0;
        boolean ok = true;
        byte[] buf = new byte[READ_SIZE];
        try {
            while (true) {
                byte[] data;
                try {
                    if (isClient && packetNum == 0) {
                        data = readFirstClientChunk(in, buf, srcSock);
                    } else {
                        int n = in.read(buf);
                        data = n < 0 ? EMPTY : Arrays.copyOf(buf, n);
                    }
                } catch (SocketTimeoutException e) {
                    log(INFO, "Idle timeout - closing");
                    ok = false;
                    break;
                }

                if (data.length == 0) break; // EOF

                if (isClient) {
                    packetNum++;
                    if (applyFragmentation(out, data, packetNum)) continue;
                }
                out.write(data);
                out.flush();
            }
        } catch (IOException e) {
            log(DEBUG, "Forward stream error: " + why(e));
            ok = false;
        } catch (RuntimeException e) {
            log(WARN, "Forward unexpected error: " + why(e));
            ok = false;
        } finally {
            if (ok) {
                // half-close: only announce the end of our sending direction
                try {
                    dstSock.shutdownOutput();
                } catch (Throwable ignored) {
                }
            } else {
                closeQuietly(srcSock);
                closeQuietly(dstSock);
            }
        }
        return ok;
    }

    // ==================================================================
    // Proxy handshakes
    // ==================================================================

    private static final class Request {
        final String proto;
        final String host;
        final int port;

        Request(String proto, String host, int port) {
            this.proto = proto;
            this.host = host;
            this.port = port;
        }
    }

    private static int readByte(InputStream in) throws IOException {
        int b = in.read();
        if (b < 0) throw new IOException("unexpected EOF");
        return b;
    }

    private static byte[] readFully(InputStream in, int n) throws IOException {
        byte[] b = new byte[n];
        int off = 0;
        while (off < n) {
            int m = in.read(b, off, n - off);
            if (m < 0) throw new IOException("unexpected EOF");
            off += m;
        }
        return b;
    }

    private static byte[] socks5Reply(int code) {
        return new byte[]{0x05, (byte) code, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    }

    private static final char[] B64STD =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();

    static String base64Std(byte[] in) {
        StringBuilder sb = new StringBuilder(((in.length + 2) / 3) * 4);
        int i = 0;
        while (i + 2 < in.length) {
            int v = ((in[i] & 0xFF) << 16) | ((in[i + 1] & 0xFF) << 8) | (in[i + 2] & 0xFF);
            sb.append(B64STD[(v >> 18) & 63]).append(B64STD[(v >> 12) & 63])
                    .append(B64STD[(v >> 6) & 63]).append(B64STD[v & 63]);
            i += 3;
        }
        int rem = in.length - i;
        if (rem == 1) {
            int v = (in[i] & 0xFF) << 16;
            sb.append(B64STD[(v >> 18) & 63]).append(B64STD[(v >> 12) & 63]).append("==");
        } else if (rem == 2) {
            int v = ((in[i] & 0xFF) << 16) | ((in[i + 1] & 0xFF) << 8);
            sb.append(B64STD[(v >> 18) & 63]).append(B64STD[(v >> 12) & 63])
                    .append(B64STD[(v >> 6) & 63]).append('=');
        }
        return sb.toString();
    }

    private boolean authRequired() {
        return cfg.username != null && !cfg.username.isEmpty();
    }

    /** constant-time comparison */
    private static boolean sameBytes(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }

    /** RFC 1929 username/password sub-negotiation. Returns true when the login is correct. */
    private boolean socks5Login(InputStream in, OutputStream out) throws IOException {
        int ver = readByte(in);
        byte[] user = readFully(in, readByte(in));
        byte[] pass = readFully(in, readByte(in));
        boolean okUser = sameBytes(user, cfg.username.getBytes(StandardCharsets.UTF_8));
        boolean okPass = sameBytes(pass, (cfg.password == null ? "" : cfg.password).getBytes(StandardCharsets.UTF_8));
        boolean ok = ver == 1 && okUser && okPass;
        out.write(new byte[]{0x01, (byte) (ok ? 0x00 : 0x01)});
        out.flush();
        return ok;
    }

    /** Checks the Proxy-Authorization: Basic header of an HTTP CONNECT request. */
    private boolean httpLoginOk(String headerBlock) {
        String expected = "Basic " + base64Std((cfg.username + ":" + (cfg.password == null ? "" : cfg.password))
                .getBytes(StandardCharsets.UTF_8));
        String[] lines = headerBlock.split("\r\n");
        for (int i = 1; i < lines.length; i++) {
            int c = lines[i].indexOf(':');
            if (c <= 0) continue;
            if (!lines[i].substring(0, c).trim().equalsIgnoreCase("proxy-authorization")) continue;
            String v = lines[i].substring(c + 1).trim();
            if (v.length() > 6 && v.substring(0, 6).equalsIgnoreCase("basic ")) {
                v = "Basic " + v.substring(6).trim();
            }
            return sameBytes(v.getBytes(StandardCharsets.ISO_8859_1), expected.getBytes(StandardCharsets.ISO_8859_1));
        }
        return false;
    }

    /** Parses the client's first request; no success reply is sent here. Returns null to drop. */
    private Request readRequest(InputStream in, OutputStream out) throws IOException {
        int head = readByte(in);

        // ---- SOCKS5 ----
        if (head == 0x05) {
            int nmethods = readByte(in);
            byte[] methods = readFully(in, nmethods);
            boolean needAuth = authRequired();
            int wanted = needAuth ? 0x02 : 0x00; // 0x02 = username/password
            boolean offered = false;
            for (byte m : methods) {
                if (m == wanted) offered = true;
            }
            if (!offered) {
                out.write(new byte[]{0x05, (byte) 0xFF});
                out.flush();
                return null;
            }
            out.write(new byte[]{0x05, (byte) wanted});
            out.flush();
            if (needAuth && !socks5Login(in, out)) {
                log(INFO, "SOCKS5 login failed");
                return null;
            }

            byte[] h = readFully(in, 4);
            int ver = h[0] & 0xFF, cmd = h[1] & 0xFF, atyp = h[3] & 0xFF;
            if (ver != 5) return null;
            if (cmd != 1) {
                log(INFO, "Unsupported SOCKS5 command: " + cmd);
                out.write(socks5Reply(SOCKS_CMD_UNSUPPORTED));
                out.flush();
                return null;
            }

            String host;
            if (atyp == 1) {
                byte[] a = readFully(in, 4);
                host = (a[0] & 0xFF) + "." + (a[1] & 0xFF) + "." + (a[2] & 0xFF) + "." + (a[3] & 0xFF);
            } else if (atyp == 3) {
                int len = readByte(in);
                host = new String(readFully(in, len), StandardCharsets.UTF_8);
            } else if (atyp == 4) {
                host = InetAddress.getByAddress(readFully(in, 16)).getHostAddress();
            } else {
                log(INFO, "Unsupported address type: " + atyp);
                out.write(socks5Reply(SOCKS_ATYP_UNSUPPORTED));
                out.flush();
                return null;
            }
            byte[] p = readFully(in, 2);
            int port = ((p[0] & 0xFF) << 8) | (p[1] & 0xFF);
            return new Request("socks5", host, port);
        }

        // ---- HTTP CONNECT ----
        if (head == 'C' || head == 'c') {
            ByteArrayOutputStream hdr = new ByteArrayOutputStream();
            hdr.write(head);
            int state = 0; // matches \r\n\r\n
            while (true) {
                int b = readByte(in);
                hdr.write(b);
                if (hdr.size() > MAX_HTTP_HEADER) throw new IOException("header too large");
                if (b == '\r' && (state == 0 || state == 2)) state++;
                else if (b == '\n' && (state == 1 || state == 3)) state++;
                else state = (b == '\r') ? 1 : 0;
                if (state == 4) break;
            }
            String all = new String(hdr.toByteArray(), StandardCharsets.ISO_8859_1);
            String firstLine = all.split("\r\n", 2)[0];
            String[] parts = firstLine.split(" ");
            if (parts.length < 2 || !parts[0].toUpperCase(Locale.ROOT).equals("CONNECT")) return null;

            if (authRequired() && !httpLoginOk(all)) {
                log(INFO, "HTTP proxy login failed");
                out.write(("HTTP/1.1 407 Proxy Authentication Required\r\n"
                        + "Proxy-Authenticate: Basic realm=\"DNS Chain\"\r\n"
                        + "Content-Length: 0\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                out.flush();
                return null;
            }

            String target = parts[1];
            String host;
            int port;
            if (target.startsWith("[")) { // [IPv6]:port
                int end = target.indexOf(']');
                if (end == -1) return null;
                host = target.substring(1, end);
                String portStr = target.substring(Math.min(end + 2, target.length()));
                port = portStr.isEmpty() ? 443 : Integer.parseInt(portStr);
            } else if (target.indexOf(':') >= 0) {
                int c = target.lastIndexOf(':');
                host = target.substring(0, c);
                port = Integer.parseInt(target.substring(c + 1));
            } else {
                host = target;
                port = 443;
            }
            return new Request("http", host, port);
        }

        log(INFO, "Unknown protocol (first byte: " + Integer.toHexString(head) + ")");
        return null;
    }

    private void sendSuccess(String proto, OutputStream out) throws IOException {
        if (proto.equals("socks5")) {
            out.write(socks5Reply(SOCKS_OK));
        } else {
            out.write("HTTP/1.1 200 Connection Established\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
        }
        out.flush();
    }

    private void sendFailure(String proto, OutputStream out, Throwable e) {
        try {
            if (proto.equals("socks5")) {
                int code;
                String m = String.valueOf(e.getMessage()).toLowerCase(Locale.ROOT);
                if (e instanceof ConnectException && m.contains("refused")) {
                    code = SOCKS_CONN_REFUSED;
                } else if (e instanceof SocketTimeoutException || e instanceof UnknownHostException) {
                    code = SOCKS_HOST_UNREACHABLE;
                } else {
                    code = SOCKS_GENERAL_FAILURE;
                }
                out.write(socks5Reply(code));
            } else {
                out.write("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"
                        .getBytes(StandardCharsets.US_ASCII));
            }
            out.flush();
        } catch (Throwable ignored) {
        }
    }

    // ==================================================================
    // Connection handler
    // ==================================================================

    private void handleConnection(final Socket client) {
        String peer = String.valueOf(client.getRemoteSocketAddress());
        log(DEBUG, "New connection from " + peer);
        openSockets.add(client);
        Socket remote = null;
        try {
            tune(client);
            client.setSoTimeout(toMs(cfg.handshakeTimeout));
            InputStream cin = client.getInputStream();
            OutputStream cout = client.getOutputStream();

            Request req;
            try {
                req = readRequest(cin, cout);
            } catch (SocketTimeoutException e) {
                log(DEBUG, "Handshake timed out: " + peer);
                return;
            } catch (NumberFormatException e) {
                log(INFO, "Bad request from " + peer);
                return;
            } catch (IOException e) {
                log(DEBUG, "Handshake failed/aborted by " + peer);
                return;
            }
            if (req == null) return;

            try {
                String ip = resolveHost(req.host);
                log(DEBUG, "[" + req.proto + "] " + peer + " -> " + req.host + " (" + ip + "):" + req.port);
                remote = new Socket();
                openSockets.add(remote);
                remote.connect(new InetSocketAddress(InetAddress.getByName(ip), req.port),
                        toMs(cfg.connectTimeout));
            } catch (Exception e) {
                log(INFO, "Connect to " + req.host + ":" + req.port + " failed: " + why(e));
                sendFailure(req.proto, cout, e);
                return;
            }

            // only now tell the client it is connected
            sendSuccess(req.proto, cout);

            tune(remote);
            int idleMs = cfg.idleTimeout > 0 ? cfg.idleTimeout * 1000 : 0;
            client.setSoTimeout(idleMs);
            remote.setSoTimeout(idleMs);

            final Socket r = remote;
            final InputStream rin = r.getInputStream();
            final OutputStream rout = r.getOutputStream();
            final InputStream fcin = cin;
            Future<Boolean> up = pool.submit(new Callable<Boolean>() {
                @Override
                public Boolean call() {
                    return forward(fcin, rout, true, client, r);
                }
            });
            forward(rin, cout, false, r, client);
            try {
                up.get();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                up.cancel(true);
            } catch (ExecutionException ignored) {
            }
        } catch (IOException e) {
            log(DEBUG, "Connection error with " + peer + ": " + why(e));
        } catch (RuntimeException e) {
            log(WARN, "Unexpected error with " + peer + ": " + why(e));
        } finally {
            openSockets.remove(client);
            closeQuietly(client);
            if (remote != null) {
                openSockets.remove(remote);
                closeQuietly(remote);
            }
        }
    }
}

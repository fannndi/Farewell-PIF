package dev.farewell.pif;

import android.app.ActivityThread;
import android.content.ContentResolver;
import android.content.Context;
import android.provider.Settings;
import android.system.keystore2.KeyEntryResponse;
import android.util.Base64;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Tiny boot-classpath bootstrap.
 *
 * framework.jar only carries this shim. The real implementation (HookImpl + Config + Keybox +
 * Attestation + BouncyCastle) is delivered as a dex at runtime and loaded with
 * InMemoryDexClassLoader, so hook updates only need the companion app (or provision.py) and
 * never a ROM repack.
 *
 * Runtime dex channel (Settings.Global, obfuscated like the config envelope):
 *   sys_perf_dex_meta = "&lt;sha256hex&gt;:&lt;chunks&gt;:&lt;version&gt;"
 *   sys_perf_dex_0..N  = base64(XOR(chunk))
 *
 * Signature contract with the patcher: do not rename or change descriptors.
 */
public final class FarewellHook {
    public static final String TAG = "FarewellPIF";

    private static final String KEY_META = "sys_perf_dex_meta";
    private static final String KEY_CHUNK = "sys_perf_dex_";
    private static final String KEY_GATE = "sys_perf_dex_pkgs";
    private static final int MAX_CHUNKS = 32;
    private static final byte[] XOR_KEY = {
            0x46, 0x61, 0x72, 0x65, 0x77, 0x65, 0x6C, 0x6C,
            0x50, 0x49, 0x46, 0x2D, 0x53, 0x31, 0x21, 0x50,
            0x72, 0x6F, 0x66, 0x69, 0x6C, 0x65, 0x2D, 0x4B,
            0x65, 0x79, 0x62, 0x6F, 0x78, 0x2D, 0x30, 0x31
    };

    private static volatile Class<?> sImplClass;
    private static volatile String sLoadedMeta;
    private static volatile boolean sLoadFailed;
    private static volatile long sLoadFailedAt;
    private static volatile int sGateState; // 0 unknown, 1 allow, 2 deny
    private static volatile long sGateCheckedAt;
    private static volatile Context sContext;
    private static final long RETRY_AFTER_MS = 5000L;
    private static final Map<String, Method> sMethods = new ConcurrentHashMap<String, Method>();

    private FarewellHook() {
    }

    // ------------------------------------------------------------ entry points

    public static void initContext(Context context) {
        sContext = context;
        if (!gateAllows()) return;
        refresh();
        invoke("initContext", new Class<?>[]{Context.class}, context);
    }

    public static void initSystemServer() {
        if (!gateAllows()) return;
        refresh();
        invoke("initSystemServer", new Class<?>[0]);
    }

    public static Boolean hasSystemFeature(String name, int version) {
        return (Boolean) invoke("hasSystemFeature", new Class<?>[]{String.class, int.class},
                name, Integer.valueOf(version));
    }

    public static KeyEntryResponse getKeyEntry(KeyEntryResponse response) {
        Object result = invoke("getKeyEntry", new Class<?>[]{KeyEntryResponse.class}, response);
        return result instanceof KeyEntryResponse ? (KeyEntryResponse) result : response;
    }

    public static Certificate[] certificateChainForAlias(String alias) {
        Object result = invoke("certificateChainForAlias", new Class<?>[]{String.class}, alias);
        return result instanceof Certificate[] ? (Certificate[]) result : null;
    }

    public static Key softwareKeyForAlias(String alias) {
        Object result = invoke("softwareKeyForAlias", new Class<?>[]{String.class}, alias);
        return result instanceof Key ? (Key) result : null;
    }

    public static Certificate certificateForAlias(String alias) {
        Object result = invoke("certificateForAlias", new Class<?>[]{String.class}, alias);
        return result instanceof Certificate ? (Certificate) result : null;
    }

    public static Certificate[] certificateChainIfNeeded(Certificate[] chain) {
        Object result = invoke("certificateChainIfNeeded",
                new Class<?>[]{Certificate[].class}, (Object) chain);
        return result instanceof Certificate[] ? (Certificate[]) result : chain;
    }

    public static KeyPair softwareKeyPair(Object spi) {
        Object result = invoke("softwareKeyPair", new Class<?>[]{Object.class}, spi);
        return result instanceof KeyPair ? (KeyPair) result : null;
    }

    public static boolean isSecureFlag() {
        Object result = invoke("isSecureFlag", new Class<?>[0]);
        return result instanceof Boolean && (Boolean) result;
    }

    public static String property(String key, String def) {
        Object result = invoke("property", new Class<?>[]{String.class, String.class}, key, def);
        return result instanceof String ? (String) result : null;
    }

    public static Integer propertyInt(String key, int def) {
        Object result = invoke("propertyInt", new Class<?>[]{String.class, int.class},
                key, Integer.valueOf(def));
        return result instanceof Integer ? (Integer) result : null;
    }

    public static Long propertyLong(String key, long def) {
        Object result = invoke("propertyLong", new Class<?>[]{String.class, long.class},
                key, Long.valueOf(def));
        return result instanceof Long ? (Long) result : null;
    }

    public static Boolean propertyBoolean(String key, boolean def) {
        Object result = invoke("propertyBoolean", new Class<?>[]{String.class, boolean.class},
                key, Boolean.valueOf(def));
        return result instanceof Boolean ? (Boolean) result : null;
    }

    public static String diagnose() {
        Object result = invoke("diagnose", new Class<?>[0]);
        return result instanceof String ? (String) result : "{\"bootstrap\":true,\"impl\":"
                + (sImplClass != null) + "}";
    }

    /**
     * Bootstrap state as JSON, for the controller app (reflection) and tools/verify.py. Never
     * triggers a load, so it is safe to call from any process at any time.
     */
    public static String state() {
        try {
            String gate = readSetting(KEY_GATE);
            String pkg = currentPackageName();
            return "{\"impl\":" + (sImplClass != null)
                    + ",\"failed\":" + sLoadFailed
                    + ",\"gate\":" + sGateState
                    + ",\"package\":\"" + (pkg == null ? "" : pkg) + "\""
                    + ",\"gateValue\":" + (gate == null ? "null" : "\"" + gate + "\"")
                    + ",\"meta\":" + (sLoadedMeta == null ? "null" : "\"" + sLoadedMeta + "\"")
                    + "}";
        } catch (Throwable t) {
            return "{\"error\":\"" + t + "\"}";
        }
    }

    public static String getEvents() {
        Object result = invoke("getEvents", new Class<?>[0]);
        return result instanceof String ? (String) result : "[]";
    }

    /** End-to-end attestation check; see HookImpl.selfTest(). */
    public static String selfTest() {
        Object result = invoke("selfTest", new Class<?>[0]);
        return result instanceof String ? (String) result : "{\"bootstrap\":true,\"impl\":false}";
    }

    /** Per-process interception counters; see HookImpl.getStats(). */
    public static String getStats() {
        Object result = invoke("getStats", new Class<?>[0]);
        return result instanceof String ? (String) result : "{}";
    }

    // ------------------------------------------------------------------ loader

    /** Re-check the runtime dex version; reload when it changed. */
    public static void refresh() {
        try {
            String meta = readSetting(KEY_META);
            if (meta == null || meta.isEmpty()) {
                sImplClass = null;
                sLoadedMeta = null;
                sLoadFailed = false;
                sMethods.clear();
                return;
            }
            if (meta.equals(sLoadedMeta)) return;
            synchronized (FarewellHook.class) {
                if (meta.equals(sLoadedMeta)) return;
                Class<?> loaded = loadImpl(meta);
                if (loaded != null) {
                    sImplClass = loaded;
                    sLoadedMeta = meta;
                    sLoadFailed = false;
                    sMethods.clear();
                } else {
                    sLoadFailed = true;
                    sLoadFailedAt = System.currentTimeMillis();
                }
            }
        } catch (Throwable t) {
            log("refresh failed", t);
        }
    }

    private static Class<?> loadImpl(String meta) {
        try {
            String[] parts = meta.split(":");
            if (parts.length < 2) return null;
            String expectedSha = parts[0];
            int chunks = Integer.parseInt(parts[1]);
            if (chunks <= 0 || chunks > MAX_CHUNKS) return null;
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            for (int i = 0; i < chunks; i++) {
                String encoded = readSetting(KEY_CHUNK + i);
                if (encoded == null || encoded.isEmpty()) {
                    logOnce("chunk " + i + " unreadable pkg=" + currentPackageName());
                    return null;
                }
                out.write(xor(Base64.decode(encoded, Base64.DEFAULT)));
            }
            byte[] dex = out.toByteArray();
            if (!sha256(dex).equalsIgnoreCase(expectedSha)) {
                logOnce("dex hash mismatch pkg=" + currentPackageName());
                return null;
            }
            dalvik.system.InMemoryDexClassLoader loader =
                    new dalvik.system.InMemoryDexClassLoader(
                            ByteBuffer.wrap(dex), FarewellHook.class.getClassLoader());
            Class<?> loaded = Class.forName("dev.farewell.pif.HookImpl", true, loader);
            String version = parts.length > 2 ? parts[2] : "?";
            logOnce("dex loaded v=" + version + " pkg=" + currentPackageName());
            return loaded;
        } catch (Throwable t) {
            log("loadImpl failed", t);
            return null;
        }
    }

    private static Object invoke(String name, Class<?>[] types, Object... args) {
        try {
            if (!gateAllows()) return null;
            Class<?> impl = sImplClass;
            if (impl == null) {
                if (!sLoadFailed) {
                    refresh();
                    impl = sImplClass;
                } else if (System.currentTimeMillis() - sLoadFailedAt > RETRY_AFTER_MS) {
                    sLoadFailed = false;
                    refresh();
                    impl = sImplClass;
                }
                if (impl == null) return null;
            }
            Method method = sMethods.get(name);
            if (method == null) {
                method = impl.getMethod(name, types);
                method.setAccessible(true);
                sMethods.put(name, method);
            }
            return method.invoke(null, args);
        } catch (Throwable t) {
            log("invoke " + name + " failed", t);
            return null;
        }
    }

    // ------------------------------------------------------------------ helpers

    /**
     * Per-process allowlist so non-target processes never load the hook dex. The app writes
     * ",android,com.google.android.gms,com.android.vending," at install time; system_server
     * ("android") is required for the secure-flag hooks.
     *
     * The setting may be unreadable early in process start (no context / provider not up), so an
     * unresolved read is never cached, and a deny is retried after RETRY_AFTER_MS. Without this,
     * a process that starts before the gate is written would stay disabled until it restarts.
     */
    private static boolean gateAllows() {
        long now = System.currentTimeMillis();
        int state = sGateState;
        if (state == 1) return true;
        if (sGateCheckedAt != 0 && now - sGateCheckedAt < RETRY_AFTER_MS
                && (state == 0 || state == 2)) {
            return false;
        }
        synchronized (FarewellHook.class) {
            state = sGateState;
            now = System.currentTimeMillis();
            if (state == 1) return true;
            if (sGateCheckedAt != 0 && now - sGateCheckedAt < RETRY_AFTER_MS
                    && (state == 0 || state == 2)) {
                return false;
            }
            String gate = null;
            try {
                gate = readSetting(KEY_GATE);
            } catch (Throwable ignored) {
            }
            sGateCheckedAt = now;
            if (gate == null || gate.isEmpty()) {
                sGateState = 0; // not readable / not installed: retry later
                return false;
            }
            String pkg = currentPackageName();
            boolean allowed = pkg != null && gate.contains("," + pkg + ",");
            sGateState = allowed ? 1 : 2;
            if (!allowed) logOnce("gate denied pkg=" + pkg);
            return allowed;
        }
    }

    private static String currentPackageName() {
        try {
            return ActivityThread.currentPackageName();
        } catch (Throwable t) {
            return null;
        }
    }

    /**
     * Returns the context used to read Settings.Global.
     *
     * In an app process getSystemContext() carries package "android" while the process UID is the
     * app's, so SettingsProvider rejects every read with "Package android does not belong to &lt;uid&gt;".
     * Prefer the real application context (set by initContext or currentApplication); the system
     * context is only correct in system_server, whose UID owns the "android" package.
     */
    private static Context context() {
        Context cached = sContext;
        if (cached != null) return cached;
        try {
            Context application = ActivityThread.currentApplication();
            if (application != null) return application;
        } catch (Throwable ignored) {
        }
        try {
            ActivityThread thread = ActivityThread.currentActivityThread();
            if (thread != null) {
                Context system = thread.getSystemContext();
                if (system != null) return system;
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    private static String readSetting(String key) {
        try {
            Context context = context();
            if (context == null) return null;
            ContentResolver resolver = context.getContentResolver();
            return Settings.Global.getString(resolver, key);
        } catch (Throwable t) {
            return null;
        }
    }

    private static byte[] xor(byte[] data) {
        if (data == null) return new byte[0];
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            out[i] = (byte) (data[i] ^ XOR_KEY[i % XOR_KEY.length]);
        }
        return out;
    }

    private static String sha256(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);
            StringBuilder builder = new StringBuilder(hash.length * 2);
            for (byte value : hash) builder.append(String.format("%02x", value));
            return builder.toString();
        } catch (Throwable t) {
            return "";
        }
    }

    private static void log(String message, Throwable t) {
        try {
            Log.e(TAG, message, t);
        } catch (Throwable ignored) {
        }
    }

    private static final java.util.Set<String> LOGGED =
            java.util.Collections.newSetFromMap(
                    new ConcurrentHashMap<String, Boolean>());

    private static void logOnce(String message) {
        try {
            if (LOGGED.add(message)) Log.i(TAG, message);
        } catch (Throwable ignored) {
        }
    }
}

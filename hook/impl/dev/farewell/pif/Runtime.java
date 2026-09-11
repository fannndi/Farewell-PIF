package dev.farewell.pif;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Per-process hook runtime: generated-key cache, counters, event ring, TEE probe, lazy process
 * init and the target gates. Feature modules (keygen, certificates, props) depend on this; it
 * depends only on Config/Props/NativeProps.
 */
final class Runtime {
    static final class Generated {
        final PrivateKey privateKey;
        final X509Certificate[] chain;
        final byte[] challenge;
        final boolean deviceProperties;

        Generated(PrivateKey privateKey, X509Certificate[] chain, byte[] challenge,
                  boolean deviceProperties) {
            this.privateKey = privateKey;
            this.chain = chain;
            this.challenge = challenge;
            this.deviceProperties = deviceProperties;
        }
    }

    /** Software key pairs minted in this process, by keystore alias. */
    static final ConcurrentHashMap<String, Generated> GENERATED =
            new ConcurrentHashMap<String, Generated>();
    static final ThreadLocal<Boolean> SELF_TEST = new ThreadLocal<Boolean>();
    static final ThreadLocal<Boolean> PROBE_ACTIVE = new ThreadLocal<Boolean>();
    static final AtomicBoolean PROPS_APPLIED = new AtomicBoolean(false);

    static final AtomicInteger STAT_KEYGEN = new AtomicInteger();
    static final AtomicInteger STAT_CHAIN = new AtomicInteger();
    static final AtomicInteger STAT_KEY_ENTRY = new AtomicInteger();
    static final AtomicInteger STAT_PROPERTY = new AtomicInteger();
    static final AtomicInteger STAT_IMPORT = new AtomicInteger();
    static final AtomicInteger STAT_CHAIN_ALIAS = new AtomicInteger();
    static final AtomicInteger STAT_CERT_ALIAS = new AtomicInteger();
    static final AtomicInteger STAT_KEY_ALIAS = new AtomicInteger();

    private static final java.util.ArrayDeque<String> EVENTS =
            new java.util.ArrayDeque<String>();
    private static final int MAX_EVENTS = 64;
    private static volatile int sTeeState; // 0 unknown, 1 works, 2 broken

    private Runtime() {
    }

    // ----------------------------------------------------------------- events

    static void recordEvent(String type, String detail) {
        try {
            String entry = System.currentTimeMillis() + " " + type + " " + detail;
            synchronized (EVENTS) {
                if (EVENTS.size() >= MAX_EVENTS) EVENTS.pollFirst();
                EVENTS.addLast(entry);
            }
        } catch (Throwable ignored) {
        }
    }

    /** Ring buffer of the last framework-side events, as a JSON array of strings. */
    static String getEvents() {
        try {
            org.json.JSONArray array = new org.json.JSONArray();
            synchronized (EVENTS) {
                for (String event : EVENTS) array.put(event);
            }
            return array.toString();
        } catch (Throwable t) {
            return "[]";
        }
    }

    /** Per-process interception counters, for verification over ADB/logcat. */
    static String getStats() {
        try {
            org.json.JSONObject out = new org.json.JSONObject();
            out.put("keygen", STAT_KEYGEN.get());
            out.put("chain", STAT_CHAIN.get());
            out.put("keyEntry", STAT_KEY_ENTRY.get());
            out.put("property", STAT_PROPERTY.get());
            out.put("import", STAT_IMPORT.get());
            out.put("chainAlias", STAT_CHAIN_ALIAS.get());
            out.put("certAlias", STAT_CERT_ALIAS.get());
            out.put("keyAlias", STAT_KEY_ALIAS.get());
            out.put("tee", sTeeState == 1 ? "works" : sTeeState == 2 ? "broken" : "unknown");
            return out.toString();
        } catch (Throwable t) {
            return "{}";
        }
    }

    static String teeStateName() {
        return sTeeState == 1 ? "works" : sTeeState == 2 ? "broken" : "unknown";
    }

    static void debug(String message) {
        try {
            Log.d(HookImpl.TAG, message);
        } catch (Throwable ignored) {
        }
    }

    // ------------------------------------------------------------- process init

    /**
     * Applies Build/signature/native spoofing exactly once per process.
     *
     * initContext() is a one-shot call from Instrumentation and can be skipped when the
     * bootstrap gate is not readable yet in a fresh process, so every hook entry point calls
     * this lazily instead, before any value is read.
     */
    static void ensureProcessInit() {
        if (PROPS_APPLIED.get()) return;
        try {
            Config.Snapshot cfg = Config.get();
            if (cfg == null || !cfg.enabled) return;
            String pkg = Config.currentPackage();
            if (pkg == null) return;
            String process = currentProcessName();
            if (!cfg.propsFor(pkg, process)) {
                PROPS_APPLIED.set(true);
                return;
            }
            if (!PROPS_APPLIED.compareAndSet(false, true)) return;
            Props.applyBuildFields(cfg.profileFor(pkg));
            if (cfg.signatureSpoof()) Props.installSignatureSpoof();
            NativeProps.enableFrom(cfg);
            if (cfg.debug) debug("props applied " + pkg + ":" + process);
        } catch (Throwable t) {
            PROPS_APPLIED.set(false);
            Config.log("ensureProcessInit failed", t);
        }
    }

    static boolean keyboxApplicable(Config.Snapshot cfg) {
        if (cfg == null || !cfg.enabled || !cfg.keyboxEnabled()) return false;
        if (Boolean.TRUE.equals(SELF_TEST.get())) return true;
        return cfg.attestationFor(Config.currentPackage(), currentProcessName());
    }

    // ---------------------------------------------------------------- tee probe

    /** Probes whether real TEE attestation works; cached per process. */
    static boolean teeWorks() {
        if (Boolean.TRUE.equals(PROBE_ACTIVE.get())) return true;
        int state = sTeeState;
        if (state != 0) return state == 1;
        synchronized (Runtime.class) {
            if (sTeeState != 0) return sTeeState == 1;
            boolean works = false;
            String alias = "farewell_probe_" + android.os.Process.myPid();
            PROBE_ACTIVE.set(Boolean.TRUE);
            try {
                KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "AndroidKeyStore");
                KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                        alias, KeyProperties.PURPOSE_SIGN)
                        .setAttestationChallenge(new byte[16])
                        .build();
                generator.initialize(spec);
                KeyPair keyPair = generator.generateKeyPair();
                works = keyPair != null && keyPair.getPrivate() != null;
            } catch (Throwable t) {
                works = false;
            } finally {
                PROBE_ACTIVE.remove();
            }
            try {
                KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
                keyStore.load(null);
                keyStore.deleteEntry(alias);
            } catch (Throwable ignored) {
            }
            sTeeState = works ? 1 : 2;
            recordEvent("teeProbe", works ? "works" : "broken");
            return works;
        }
    }

    // ----------------------------------------------------------------- helpers

    static String currentProcessName() {
        try {
            String name = android.app.ActivityThread.currentProcessName();
            if (name != null) return name;
        } catch (Throwable ignored) {
        }
        try {
            return android.app.ActivityThread.currentPackageName();
        } catch (Throwable ignored) {
        }
        return null;
    }
}

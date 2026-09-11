package dev.farewell.pif;

import android.app.ActivityThread;
import android.content.Context;
import android.os.Process;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.system.keystore2.KeyEntryResponse;
import android.util.Log;

import java.lang.reflect.Field;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Rootless framework entry points.
 *
 * Signatures are a build contract with patcher/farewell_patch.py. Do not rename.
 */
public final class HookImpl {
    public static final String TAG = "FarewellPIF";

    private static final AtomicBoolean sProviderInstalled = new AtomicBoolean(false);
    private static final ConcurrentHashMap<String, Generated> sGenerated =
            new ConcurrentHashMap<String, Generated>();
    private static volatile int sTeeState; // 0 unknown, 1 works, 2 broken
    private static final ThreadLocal<Boolean> sProbeActive = new ThreadLocal<Boolean>();
    private static final ThreadLocal<Boolean> sSelfTest = new ThreadLocal<Boolean>();
    private static final AtomicInteger sStatKeygen = new AtomicInteger();
    private static final AtomicInteger sStatChain = new AtomicInteger();
    private static final AtomicInteger sStatKeyEntry = new AtomicInteger();
    private static final AtomicInteger sStatProperty = new AtomicInteger();
    private static final AtomicInteger sStatImport = new AtomicInteger();
    private static final AtomicInteger sStatChainAlias = new AtomicInteger();
    private static final AtomicInteger sStatCertAlias = new AtomicInteger();
    private static final AtomicInteger sStatKeyAlias = new AtomicInteger();
    private static final AtomicBoolean sPropsApplied = new AtomicBoolean(false);
    private static final java.util.ArrayDeque<String> sEvents =
            new java.util.ArrayDeque<String>();
    private static final int MAX_EVENTS = 64;

    private HookImpl() {
    }

    static void recordEvent(String type, String detail) {
        try {
            String entry = System.currentTimeMillis() + " " + type + " " + detail;
            synchronized (sEvents) {
                if (sEvents.size() >= MAX_EVENTS) sEvents.pollFirst();
                sEvents.addLast(entry);
            }
        } catch (Throwable ignored) {
        }
    }

    /** Ring buffer of the last framework-side events, as a JSON array of strings. */
    public static String getEvents() {
        try {
            org.json.JSONArray array = new org.json.JSONArray();
            synchronized (sEvents) {
                for (String event : sEvents) array.put(event);
            }
            return array.toString();
        } catch (Throwable t) {
            return "[]";
        }
    }

    /** Per-process interception counters, for verification over ADB/logcat. */
    public static String getStats() {
        try {
            org.json.JSONObject out = new org.json.JSONObject();
            out.put("keygen", sStatKeygen.get());
            out.put("chain", sStatChain.get());
            out.put("keyEntry", sStatKeyEntry.get());
            out.put("property", sStatProperty.get());
            out.put("import", sStatImport.get());
            out.put("chainAlias", sStatChainAlias.get());
            out.put("certAlias", sStatCertAlias.get());
            out.put("keyAlias", sStatKeyAlias.get());
            out.put("tee", sTeeState == 1 ? "works" : sTeeState == 2 ? "broken" : "unknown");
            return out.toString();
        } catch (Throwable t) {
            return "{}";
        }
    }

    /**
     * End-to-end attestation check in the calling process: generates an attested key, forces the
     * hook to apply even in a non-target process (explicit action only) and reports whether the
     * returned leaf is keybox-signed. Used by the app button and tools/verify.py.
     */
    public static String selfTest() {
        org.json.JSONObject out = new org.json.JSONObject();
        String alias = "farewell_selftest_" + Process.myPid();
        KeyStore keyStore = null;
        sSelfTest.set(Boolean.TRUE);
        try {
            Config.Snapshot cfg = Config.get();
            out.put("enabled", cfg.enabled);
            out.put("keyboxEnabled", cfg.keyboxEnabled());
            out.put("package", Config.currentPackage());
            out.put("target", cfg.isTarget(Config.currentPackage(), currentProcessName()));

            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            try {
                keyStore.deleteEntry(alias);
            } catch (Throwable ignored) {
            }

            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "AndroidKeyStore");
            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                    alias, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge("farewell-selftest".getBytes("UTF-8"))
                    .build();
            generator.initialize(spec);
            KeyPair pair = generator.generateKeyPair();
            out.put("keygen", pair != null && pair.getPrivate() != null);

            int chainBefore = sStatChainAlias.get();
            java.security.cert.Certificate[] chain = keyStore.getCertificateChain(alias);
            out.put("chainDelta", sStatChainAlias.get() - chainBefore);
            out.put("chainLength", chain != null ? chain.length : 0);
            try {
                java.security.cert.Certificate cert = keyStore.getCertificate(alias);
                out.put("certDirect", cert != null ? "yes" : "null");
            } catch (Throwable t) {
                out.put("certDirect", "error: " + t);
            }
            try {
                Key key = keyStore.getKey(alias, null);
                out.put("keyDirect", key != null ? "yes" : "null");
            } catch (Throwable t) {
                out.put("keyDirect", "error: " + t);
            }
            java.security.cert.Certificate[] cached = certificateChainForAlias(alias);
            out.put("cacheChain", cached != null ? cached.length : -1);
            boolean forged = false;
            String issuer = "";
            String subject = "";
            if (chain != null && chain.length > 0 && chain[0] instanceof X509Certificate) {
                X509Certificate leaf = (X509Certificate) chain[0];
                if (leaf.getIssuerDN() != null) issuer = leaf.getIssuerDN().getName();
                if (leaf.getSubjectDN() != null) subject = leaf.getSubjectDN().getName();
                Keybox.Entry kb = Keybox.forAlgorithm(cfg, leaf.getPublicKey().getAlgorithm());
                forged = kb != null && Keybox.isIssuedBy(leaf, kb);
            }
            out.put("forged", forged);
            out.put("issuer", issuer);
            out.put("subject", subject);
            out.put("stats", new org.json.JSONObject(getStats()));
            out.put("events", new org.json.JSONArray(getEvents()));
            out.put("ok", forged);
            if (!forged) {
                out.put("hint", "hook inactive in this process, keybox missing/invalid "
                        + "or attestation forge failed");
            }
        } catch (Throwable t) {
            try {
                out.put("ok", false);
                out.put("error", t.toString());
                out.put("stats", new org.json.JSONObject(getStats()));
                out.put("events", new org.json.JSONArray(getEvents()));
            } catch (Throwable ignored) {
            }
        } finally {
            sSelfTest.remove();
            try {
                if (keyStore == null) {
                    keyStore = KeyStore.getInstance("AndroidKeyStore");
                    keyStore.load(null);
                }
                keyStore.deleteEntry(alias);
            } catch (Throwable ignored) {
            }
        }
        return out.toString();
    }

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

    /** Called from Instrumentation.newApplication(...) for every app process. */
    public static void initContext(Context context) {
        try {
            Config.setContext(context);
            Config.Snapshot cfg = Config.get();
            if (!cfg.enabled) return;
            String pkg = Config.currentPackage();
            String process = currentProcessName();
            if (cfg.debug) debug("initContext " + pkg + ":" + process);
            recordEvent("init", pkg + ":" + process
                    + " target=" + cfg.isTarget(pkg, process)
                    + " mode=" + cfg.mode + " flags=" + cfg.flags);
            ensureProcessInit();
            installProviderOnce(cfg);
        } catch (Throwable t) {
            Config.log("initContext failed", t);
        }
    }

    /**
     * Applies the Build/signature spoof exactly once per process.
     *
     * initContext() is a one-shot call from Instrumentation and can be skipped when the
     * bootstrap gate is not readable yet in a fresh process, which left GMS/DroidGuard with the
     * real POCO fingerprint and no MEETS_DEVICE_INTEGRITY. Every hook entry point calls this
     * lazily instead, before any value is read.
     */
    static void ensureProcessInit() {
        if (sPropsApplied.get()) return;
        try {
            Config.Snapshot cfg = Config.get();
            if (cfg == null || !cfg.enabled) return;
            String pkg = Config.currentPackage();
            if (pkg == null) return;
            String process = currentProcessName();
            if (!cfg.propsFor(pkg, process)) {
                sPropsApplied.set(true);
                return;
            }
            if (!sPropsApplied.compareAndSet(false, true)) return;
            Props.applyBuildFields(cfg.profileFor(pkg));
            if (cfg.signatureSpoof()) Props.installSignatureSpoof();
            if (cfg.debug) debug("props applied " + pkg + ":" + process);
        } catch (Throwable t) {
            sPropsApplied.set(false);
            Config.log("ensureProcessInit failed", t);
        }
    }

    /** Called once from SystemServer before startOtherServices(). */
    public static void initSystemServer() {
        try {
            Config.setSystemServer(true);
            Config.get();
        } catch (Throwable ignored) {
        }
    }

    /** Called from ApplicationPackageManager.hasSystemFeature(String, int). */
    public static Boolean hasSystemFeature(String name, int version) {
        try {
            ensureProcessInit();
            Config.Snapshot cfg = Config.get();
            if (!cfg.enabled) return null;
            String pkg = Config.currentPackage();
            if (pkg == null) return null;
            if (!cfg.propsFor(pkg, currentProcessName())) return null;
            return cfg.featureOverride(pkg, name);
        } catch (Throwable t) {
            return null;
        }
    }

    /** Called from android.security.KeyStore2.getKeyEntry(KeyDescriptor). */
    public static KeyEntryResponse getKeyEntry(KeyEntryResponse response) {
        try {
            ensureProcessInit();
            Config.Snapshot cfg = Config.get();
            if (!keyboxApplicable(cfg)) return response;
            if (response == null) return response;
            Object metadata = field(response, "metadata");
            if (metadata == null) return response;
            Props.reapply();
            byte[] leaf = (byte[]) field(metadata, "certificate");
            if (leaf == null) return response;
            X509Certificate real = Attestation.parseCertificate(leaf);
            if (real == null) return response;
            Keybox.Entry kb = Keybox.forAlgorithm(cfg, real.getPublicKey().getAlgorithm());
            if (kb == null) return response;
            Object keyDescriptor = field(metadata, "key");
            String alias = keyDescriptor != null ? asString(field(keyDescriptor, "alias")) : null;
            Generated generated = alias != null ? sGenerated.get(alias) : null;
            byte[] challenge = generated != null ? generated.challenge : null;
            boolean ids = generated != null && generated.deviceProperties;
            byte[] forged = Attestation.forgeLeaf(real, kb, cfg, challenge, ids,
                    Attestation.KeyParams.DEFAULT_EC);
            if (forged == null) {
                recordEvent("keyEntry", (alias != null ? alias : "?") + " no-forward");
                return response;
            }
            set(metadata, "certificate", forged);
            set(metadata, "certificateChain", kb.chainBytes());
            sStatKeyEntry.incrementAndGet();
            recordEvent("keyEntry", (alias != null ? alias : "?") + " forged alg=" + kb.algorithm);
            return response;
        } catch (Throwable t) {
            Config.log("getKeyEntry failed", t);
            recordEvent("keyEntry", "error " + t);
            return response;
        }
    }

    /** Called at the start of keystore2.AndroidKeyStoreSpi.engineGetCertificateChain(String). */
    public static Certificate[] certificateChainForAlias(String alias) {
        try {
            ensureProcessInit();
            sStatChainAlias.incrementAndGet();
            if (alias == null) return null;
            Generated generated = sGenerated.get(alias);
            if (generated == null) return null;
            X509Certificate[] chain = generated.chain;
            Certificate[] result = chain != null ? chain.clone() : null;
            if (result != null && Config.get().debug) {
                debug("chain served " + alias + " (" + result.length + ")");
            }
            return result;
        } catch (Throwable t) {
            return null;
        }
    }

    /** Called at the start of keystore2.AndroidKeyStoreSpi.engineGetKey(String, char[]). */
    public static Key softwareKeyForAlias(String alias) {
        try {
            ensureProcessInit();
            sStatKeyAlias.incrementAndGet();
            if (alias == null) return null;
            Generated generated = sGenerated.get(alias);
            if (generated != null && generated.privateKey != null && Config.get().debug) {
                debug("key served " + alias);
            }
            return generated != null ? generated.privateKey : null;
        } catch (Throwable t) {
            return null;
        }
    }

    /** Called at the start of keystore2.AndroidKeyStoreSpi.engineGetCertificate(String). */
    public static Certificate certificateForAlias(String alias) {
        try {
            ensureProcessInit();
            sStatCertAlias.incrementAndGet();
            if (alias == null) return null;
            Generated generated = sGenerated.get(alias);
            if (generated == null || generated.chain == null || generated.chain.length == 0) {
                return null;
            }
            return generated.chain[0];
        } catch (Throwable t) {
            return null;
        }
    }

    // ---- java SystemProperties spoof (rootless resetprop, Java readers only) ----

    /** Called at the start of SystemProperties.get(String) and get(String, String). */
    public static String property(String key, String def) {
        try {
            ensureProcessInit();
            Config.Snapshot cfg = Config.get();
            if (cfg == null || !cfg.enabled) return null;
            String pkg = Config.currentPackage();
            String process = currentProcessName();
            if (!cfg.propsFor(pkg, process)) {
                // Locked-bootloader state is spoofed globally, even in processes whose
                // fingerprint stays real (Play Store on SDK <= 32, Settings, GMS main).
                if (!Config.Snapshot.isBootStateKey(key)) {
                    return null;
                }
            }
            String value = cfg.spoofProperty(key);
            if (value != null) sStatProperty.incrementAndGet();
            return value != null ? value : null;
        } catch (Throwable t) {
            return null;
        }
    }

    public static Integer propertyInt(String key, int def) {
        String value = property(key, null);
        if (value == null) return null;
        try {
            return Integer.valueOf(Integer.parseInt(value.trim()));
        } catch (Throwable t) {
            return null;
        }
    }

    public static Long propertyLong(String key, long def) {
        String value = property(key, null);
        if (value == null) return null;
        try {
            return Long.valueOf(Long.parseLong(value.trim()));
        } catch (Throwable t) {
            return null;
        }
    }

    public static Boolean propertyBoolean(String key, boolean def) {
        String value = property(key, null);
        if (value == null) return null;
        String normalized = value.trim();
        if (normalized.equals("1") || normalized.equalsIgnoreCase("true")
                || normalized.equalsIgnoreCase("yes")) {
            return Boolean.TRUE;
        }
        if (normalized.equals("0") || normalized.equalsIgnoreCase("false")
                || normalized.equalsIgnoreCase("no")) {
            return Boolean.FALSE;
        }
        return null;
    }

    /**
     * Self-test for the controller app. Runs inside the calling process (the app process is not a
     * spoof target, so target-specific work is reported but not applied).
     */
    public static String diagnose() {
        try {
            Config.Snapshot cfg = Config.get();
            org.json.JSONObject out = new org.json.JSONObject();
            out.put("enabled", cfg.enabled);
            out.put("flags", cfg.flags);
            out.put("mode", cfg.mode == Config.MODE_GENERATE ? "generate"
                    : cfg.mode == Config.MODE_LEAF ? "leaf" : "auto");
            out.put("package", Config.currentPackage());
            out.put("process", currentProcessName());
            out.put("target", cfg.isTarget(Config.currentPackage(), currentProcessName()));
            out.put("attestationVersion", cfg.attestationVersion());
            out.put("keymasterVersion", cfg.keymasterVersion());
            out.put("fingerprint", cfg.profileString("FINGERPRINT"));
            out.put("tee", sTeeState == 1 ? "works" : sTeeState == 2 ? "broken" : "unknown");
            org.json.JSONArray keyboxes = new org.json.JSONArray();
            java.util.List<Keybox.Entry> entries = Keybox.parseAll(cfg.keyboxList);
            if (entries != null) {
                for (int i = 0; i < entries.size(); i++) {
                    org.json.JSONObject entry = new org.json.JSONObject();
                    entry.put("index", i);
                    entry.put("algorithm", entries.get(i).algorithm);
                    String problem = entries.get(i).problem();
                    entry.put("problem", problem == null ? "" : problem);
                    keyboxes.put(entry);
                }
            }
            out.put("keyboxes", keyboxes);
            out.put("stats", new org.json.JSONObject(getStats()));
            try {
                Class<?> spi = Class.forName(
                        "android.security.keystore2.AndroidKeyStoreKeyPairGeneratorSpi");
                java.lang.reflect.Field aliasField = spi.getDeclaredField("mEntryAlias");
                aliasField.setAccessible(true);
                out.put("spiField", "ok");
            } catch (Throwable t) {
                out.put("spiField", "error: " + t);
            }
            try {
                out.put("activityThread",
                        String.valueOf(android.app.ActivityThread.currentPackageName()));
            } catch (Throwable t) {
                out.put("activityThread", "error: " + t);
            }
            return out.toString();
        } catch (Throwable t) {
            return "{\"error\":\"" + t + "\"}";
        }
    }

    /** Called at the end of keystore2.AndroidKeyStoreSpi.engineGetCertificateChain(String). */
    public static Certificate[] certificateChainIfNeeded(Certificate[] chain) {
        try {
            if (chain == null || chain.length == 0) return chain;
            Config.Snapshot cfg = Config.get();
            if (!keyboxApplicable(cfg)) return chain;
            Props.reapply();
            if (!(chain[0] instanceof X509Certificate)) return chain;
            X509Certificate real = (X509Certificate) chain[0];
            Keybox.Entry kb = Keybox.forAlgorithm(cfg, real.getPublicKey().getAlgorithm());
            if (kb == null) return chain;
            if (Keybox.isIssuedBy(real, kb)) return chain;
            byte[] forged = Attestation.forgeLeaf(real, kb, cfg, null, false,
                    Attestation.KeyParams.DEFAULT_EC);
            if (forged == null) return chain;
            X509Certificate forgedCert = Attestation.parseCertificate(forged);
            if (forgedCert == null) return chain;
            X509Certificate[] out = new X509Certificate[kb.chain.length + 1];
            out[0] = forgedCert;
            System.arraycopy(kb.chain, 0, out, 1, kb.chain.length);
            sStatChain.incrementAndGet();
            recordEvent("chain", "forged alg=" + kb.algorithm);
            return out;
        } catch (Throwable t) {
            Config.log("certificateChainIfNeeded failed", t);
            return chain;
        }
    }

    /**
     * Called from keystore2.AndroidKeyStoreKeyPairGeneratorSpi.generateKeyPair().
     *
     * Returns null in patch mode (or when the TEE works) so the original method continues and the
     * forged chain is built from the genuine hardware leaf. In generate mode a software key pair
     * is minted and cached together with a keybox-signed chain.
     */
    public static KeyPair softwareKeyPair(Object spi) {
        try {
            ensureProcessInit();
            Config.Snapshot cfg = Config.get();
            if (!cfg.enabled || !cfg.keyboxEnabled()) return null;
            if (!keyboxApplicable(cfg)) return null;
            if (Boolean.TRUE.equals(sProbeActive.get())) {
                // Inside the TEE probe: bypass the hook so the genuine keystore path runs and the
                // probe measures real hardware behaviour (including attestation refusal).
                return null;
            }
            String packageName = Config.currentPackage();
            int mode = cfg.modeFor(packageName);
            if (mode == Config.MODE_LEAF) {
                recordEvent("keygen", "mode=leaf, keeping TEE key");
                return null;
            }
            if (mode == Config.MODE_AUTO && teeWorks()) {
                recordEvent("keygen", "auto: TEE works, keeping TEE key");
                return null;
            }

            String alias = asString(field(spi, "mEntryAlias"));
            KeyGenParameterSpec spec = (KeyGenParameterSpec) field(spi, "mSpec");
            int kmAlgorithm = asInt(field(spi, "mKeymasterAlgorithm"), 3);
            int keySize = asInt(field(spi, "mKeySizeBits"), kmAlgorithm == 3 ? 256 : 2048);
            Object exponentObj = field(spi, "mRSAPublicExponent");

            KeyPair keyPair = generateKeyPair(kmAlgorithm, keySize, exponentObj);
            if (keyPair == null) return null;

            Keybox.Entry kb = Keybox.forAlgorithm(cfg, kmAlgorithm == 3 ? "EC" : "RSA");
            if (kb == null) return null;

            byte[] challenge = spec != null ? spec.getAttestationChallenge() : null;
            boolean ids = spec != null && spec.isDevicePropertiesAttestationIncluded();
            Attestation.KeyParams keyParams = Attestation.KeyParams.from(spec, kmAlgorithm, keySize);
            byte[] leafDer = Attestation.forgeSoftwareLeaf(
                    keyPair.getPublic(), kb, cfg, challenge, ids, keyParams);
            if (leafDer == null) return null;
            X509Certificate leaf = Attestation.parseCertificate(leafDer);
            if (leaf == null) return null;

            X509Certificate[] chain = new X509Certificate[kb.chain.length + 1];
            chain[0] = leaf;
            System.arraycopy(kb.chain, 0, chain, 1, kb.chain.length);
            if (alias != null) {
                sGenerated.put(alias, new Generated(
                        keyPair.getPrivate(), chain, challenge, ids));
            }
            byte[] chainDer = chainBytes(chain);
            if (alias != null && chainDer != null) {
                tryKeystoreImport(spi, keyPair, alias, leafDer, chainDer);
            }
            sStatKeygen.incrementAndGet();
            recordEvent("keygen", "generated alias=" + alias + " alg="
                    + (kmAlgorithm == 3 ? "EC" : "RSA"));
            if (cfg.debug) HookImpl.debug("generated software key for " + alias);
            return keyPair;
        } catch (Throwable t) {
            Config.log("softwareKeyPair failed", t);
            return null;
        }
    }

    /** Called from services.jar secure-flag patch points. */
    public static boolean isSecureFlag() {
        try {
            ensureProcessInit();
            Config.Snapshot cfg = Config.get();
            return cfg.enabled && cfg.secureFlag();
        } catch (Throwable t) {
            return false;
        }
    }

    private static boolean keyboxApplicable(Config.Snapshot cfg) {
        if (cfg == null || !cfg.enabled || !cfg.keyboxEnabled()) return false;
        if (Boolean.TRUE.equals(sSelfTest.get())) return true;
        return cfg.attestationFor(Config.currentPackage(), currentProcessName());
    }

    private static byte[] chainBytes(java.security.cert.Certificate[] chain) {
        try {
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            for (java.security.cert.Certificate cert : chain) out.write(cert.getEncoded());
            out.flush();
            return out.toByteArray();
        } catch (Throwable t) {
            return null;
        }
    }

    /**
     * Best-effort import of the generated software key into keystore2 so native keystore paths
     * (engineGetKey via loadAndroidKeyStoreKeyFromKeystore, containsAlias, getCreationDate) work
     * in generate mode. Parameters come from the SPI's own constructKeyGenerationArguments();
     * attestation-only tags are stripped (same range Kaorios filters). Failure is non-fatal:
     * the per-alias override cache already covers the main DroidGuard flow.
     */
    private static void tryKeystoreImport(Object spi, KeyPair keyPair, String alias,
                                          byte[] leafDer, byte[] chainDer) {
        try {
            Object keyStore = field(spi, "mKeyStore");
            if (keyStore == null) return;
            Object namespaceObject = field(spi, "mEntryNamespace");
            long namespace = namespaceObject instanceof Number
                    ? ((Number) namespaceObject).longValue() : 0L;

            Object params = callDeclared(spi, "constructKeyGenerationArguments", new Class<?>[0]);
            if (!(params instanceof java.util.Collection)) return;

            java.util.List<Object> filtered = new java.util.ArrayList<Object>();
            for (Object param : (java.util.Collection<?>) params) {
                Object tagObject = field(param, "tag");
                if (tagObject instanceof Integer) {
                    int tag = ((Integer) tagObject).intValue();
                    // 0x90000004..0x9000000D: challenge + device id attestation parameters.
                    if (tag >= -1879047484 && tag <= -1879047475) continue;
                }
                filtered.add(param);
            }

            Object descriptor = newKeyDescriptor(0, namespace, alias);
            if (descriptor == null) return;

            byte[] pkcs8 = keyPair.getPrivate().getEncoded();
            boolean imported = false;
            for (int candidate : new int[]{1, 100, 2}) {
                Object level = call(keyStore, "getSecurityLevel", new Class<?>[]{int.class},
                        Integer.valueOf(candidate));
                if (level == null) continue;
                boolean ok = callVoid(level, "importKey", new Class<?>[]{
                                android.system.keystore2.KeyDescriptor.class,
                                android.system.keystore2.KeyDescriptor.class,
                                java.util.Collection.class, int.class, byte[].class},
                        descriptor, null, filtered, Integer.valueOf(0), pkcs8);
                if (ok) {
                    imported = true;
                    break;
                }
            }
            if (!imported) return;
            callVoid(keyStore, "updateSubcomponents", new Class<?>[]{
                            android.system.keystore2.KeyDescriptor.class, byte[].class, byte[].class},
                    descriptor, leafDer, chainDer);
            recordEvent("import", "keystore import ok alias=" + alias);
            sStatImport.incrementAndGet();
            if (Config.get().debug) HookImpl.debug("software key imported into keystore");
        } catch (Throwable t) {
            Config.log("keystore import skipped", t);
        }
    }

    private static boolean teeWorks() {
        if (Boolean.TRUE.equals(sProbeActive.get())) return true;
        int state = sTeeState;
        if (state != 0) return state == 1;
        synchronized (HookImpl.class) {
            if (sTeeState != 0) return sTeeState == 1;
            boolean works = false;
            String alias = "farewell_probe_" + Process.myPid();
            sProbeActive.set(Boolean.TRUE);
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
                sProbeActive.remove();
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

    private static KeyPair generateKeyPair(int kmAlgorithm, int keySize, Object exponentObj) {
        try {
            if (kmAlgorithm == 3) {
                KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
                generator.initialize(256);
                return generator.generateKeyPair();
            }
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            java.math.BigInteger exponent = java.math.BigInteger.valueOf(65537);
            if (exponentObj instanceof Long) {
                exponent = java.math.BigInteger.valueOf(((Long) exponentObj).longValue());
            }
            generator.initialize(new java.security.spec.RSAKeyGenParameterSpec(keySize, exponent));
            return generator.generateKeyPair();
        } catch (Throwable t) {
            Config.log("software key generation failed", t);
            return null;
        }
    }

    /**
     * Field access goes through the bootstrap when available: the impl dex is loaded in-memory and
     * counts as untrusted for hidden API enforcement, so blacklisted members (mEntryAlias, mSpec,
     * ...) cannot be reflected on from here. The boot-classpath bridge is exempt.
     */
    private static Object field(Object target, String name) {
        if (target == null) return null;
        try {
            Class<?> hook = Class.forName("dev.farewell.pif.FarewellHook");
            Object value = hook.getMethod("getField", Object.class, String.class)
                    .invoke(null, target, name);
            if (value != null) return value;
        } catch (Throwable ignored) {
        }
        Class<?> type = target.getClass();
        while (type != null) {
            try {
                Field field = type.getDeclaredField(name);
                field.setAccessible(true);
                return field.get(target);
            } catch (NoSuchFieldException ignored) {
                type = type.getSuperclass();
            } catch (Throwable t) {
                Config.logOnce("field " + name + " blocked: " + t);
                return null;
            }
        }
        return null;
    }

    private static String asString(Object value) {
        return value instanceof String ? (String) value : null;
    }

    /** Writes a field through the boot-classpath bridge (hidden API exempt). */
    private static boolean set(Object target, String name, Object value) {
        try {
            Class<?> hook = Class.forName("dev.farewell.pif.FarewellHook");
            Object result = hook.getMethod("setField", Object.class, String.class, Object.class)
                    .invoke(null, target, name, value);
            return Boolean.TRUE.equals(result);
        } catch (Throwable ignored) {
            return false;
        }
    }

    /** Invokes a public method through the boot-classpath bridge. */
    private static Object call(Object target, String name, Class<?>[] types, Object... args) {
        try {
            Class<?> hook = Class.forName("dev.farewell.pif.FarewellHook");
            return hook.getMethod("invokeMethod", Object.class, String.class,
                    Class[].class, Object[].class).invoke(null, target, name, types, args);
        } catch (Throwable ignored) {
            return null;
        }
    }

    /** Invokes a declared (possibly inherited) method through the boot-classpath bridge. */
    private static Object callDeclared(Object target, String name, Class<?>[] types, Object... args) {
        try {
            Class<?> hook = Class.forName("dev.farewell.pif.FarewellHook");
            return hook.getMethod("invokeDeclared", Object.class, String.class,
                    Class[].class, Object[].class).invoke(null, target, name, types, args);
        } catch (Throwable ignored) {
            return null;
        }
    }

    /** Invokes a void method through the bridge, reporting whether it succeeded. */
    private static boolean callVoid(Object target, String name, Class<?>[] types, Object... args) {
        try {
            Class<?> hook = Class.forName("dev.farewell.pif.FarewellHook");
            Object result = hook.getMethod("tryInvoke", Object.class, String.class,
                    Class[].class, Object[].class).invoke(null, target, name, types, args);
            return Boolean.TRUE.equals(result);
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static Object newKeyDescriptor(int domain, long namespace, String alias) {
        try {
            Class<?> hook = Class.forName("dev.farewell.pif.FarewellHook");
            return hook.getMethod("newKeyDescriptor", int.class, long.class, String.class)
                    .invoke(null, Integer.valueOf(domain), Long.valueOf(namespace), alias);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static int asInt(Object value, int fallback) {
        return value instanceof Integer ? ((Integer) value).intValue() : fallback;
    }

    private static void installProviderOnce(Config.Snapshot cfg) {
        if (!cfg.providerSpoof()) return;
        if (!sProviderInstalled.compareAndSet(false, true)) return;
        try {
            Props.installProviderSpoof();
        } catch (Throwable t) {
            Config.log("provider spoof failed", t);
        }
    }

    static String currentProcessName() {
        try {
            String name = ActivityThread.currentProcessName();
            if (name != null) return name;
        } catch (Throwable ignored) {
        }
        try {
            return ActivityThread.currentPackageName();
        } catch (Throwable ignored) {
        }
        return null;
    }

    static void debug(String message) {
        try {
            Log.d(TAG, message);
        } catch (Throwable ignored) {
        }
    }
}

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
            recordEvent("init", pkg + ":" + process
                    + " target=" + cfg.isTarget(pkg, process)
                    + " mode=" + cfg.mode + " flags=" + cfg.flags);
            Props.onProcessStart(cfg, context, process);
            installProviderOnce(cfg);
        } catch (Throwable t) {
            Config.log("initContext failed", t);
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
            Config.Snapshot cfg = Config.get();
            if (!cfg.enabled) return null;
            String pkg = Config.currentPackage();
            if (pkg == null) return null;
            return cfg.featureOverride(pkg, name);
        } catch (Throwable t) {
            return null;
        }
    }

    /** Called from android.security.KeyStore2.getKeyEntry(KeyDescriptor). */
    public static KeyEntryResponse getKeyEntry(KeyEntryResponse response) {
        try {
            if (response == null || response.metadata == null) return response;
            Config.Snapshot cfg = Config.get();
            if (!keyboxApplicable(cfg)) return response;
            Props.reapply();
            byte[] leaf = response.metadata.certificate;
            if (leaf == null) return response;
            X509Certificate real = Attestation.parseCertificate(leaf);
            if (real == null) return response;
            Keybox.Entry kb = Keybox.forAlgorithm(cfg, real.getPublicKey().getAlgorithm());
            if (kb == null) return response;
            String alias = response.metadata.key != null ? response.metadata.key.alias : null;
            Generated generated = alias != null ? sGenerated.get(alias) : null;
            byte[] challenge = generated != null ? generated.challenge : null;
            boolean ids = generated != null && generated.deviceProperties;
            byte[] forged = Attestation.forgeLeaf(real, kb, cfg, challenge, ids);
            if (forged == null) {
                recordEvent("keyEntry", (alias != null ? alias : "?") + " no-forward");
                return response;
            }
            response.metadata.certificate = forged;
            response.metadata.certificateChain = kb.chainBytes();
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
            if (alias == null) return null;
            Generated generated = sGenerated.get(alias);
            if (generated == null) return null;
            X509Certificate[] chain = generated.chain;
            return chain != null ? chain.clone() : null;
        } catch (Throwable t) {
            return null;
        }
    }

    /** Called at the start of keystore2.AndroidKeyStoreSpi.engineGetKey(String, char[]). */
    public static Key softwareKeyForAlias(String alias) {
        try {
            if (alias == null) return null;
            Generated generated = sGenerated.get(alias);
            return generated != null ? generated.privateKey : null;
        } catch (Throwable t) {
            return null;
        }
    }

    /** Called at the start of keystore2.AndroidKeyStoreSpi.engineGetCertificate(String). */
    public static Certificate certificateForAlias(String alias) {
        try {
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
            Config.Snapshot cfg = Config.get();
            if (cfg == null || !cfg.enabled) return null;
            if (!cfg.isTarget(Config.currentPackage(), currentProcessName())) return null;
            String value = cfg.spoofProperty(key);
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
            byte[] forged = Attestation.forgeLeaf(real, kb, cfg, null, false);
            if (forged == null) return chain;
            X509Certificate forgedCert = Attestation.parseCertificate(forged);
            if (forgedCert == null) return chain;
            X509Certificate[] out = new X509Certificate[kb.chain.length + 1];
            out[0] = forgedCert;
            System.arraycopy(kb.chain, 0, out, 1, kb.chain.length);
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
            Config.Snapshot cfg = Config.get();
            if (!cfg.enabled || !cfg.keyboxEnabled()) return null;
            if (!keyboxApplicable(cfg)) return null;
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
            byte[] leafDer = Attestation.forgeSoftwareLeaf(
                    keyPair.getPublic(), kb, cfg, challenge, ids);
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
            Config.Snapshot cfg = Config.get();
            return cfg.enabled && cfg.secureFlag();
        } catch (Throwable t) {
            return false;
        }
    }

    private static boolean keyboxApplicable(Config.Snapshot cfg) {
        if (cfg == null || !cfg.enabled || !cfg.keyboxEnabled()) return false;
        return cfg.isTarget(Config.currentPackage(), currentProcessName());
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

            java.lang.reflect.Method builder = null;
            Class<?> type = spi.getClass();
            while (type != null && builder == null) {
                try {
                    builder = type.getDeclaredMethod("constructKeyGenerationArguments");
                } catch (NoSuchMethodException ignored) {
                    type = type.getSuperclass();
                }
            }
            if (builder == null) return;
            builder.setAccessible(true);
            java.util.Collection<?> params = (java.util.Collection<?>) builder.invoke(spi);
            if (params == null) return;

            java.util.List<Object> filtered = new java.util.ArrayList<Object>();
            for (Object param : params) {
                Object tagObject = field(param, "tag");
                if (tagObject instanceof Integer) {
                    int tag = ((Integer) tagObject).intValue();
                    // 0x90000004..0x9000000D: challenge + device id attestation parameters.
                    if (tag >= -1879047484 && tag <= -1879047475) continue;
                }
                filtered.add(param);
            }

            android.system.keystore2.KeyDescriptor descriptor =
                    new android.system.keystore2.KeyDescriptor();
            descriptor.domain = 0;
            descriptor.nspace = namespace;
            descriptor.alias = alias;

            byte[] pkcs8 = keyPair.getPrivate().getEncoded();
            java.lang.reflect.Method getLevel = keyStore.getClass()
                    .getMethod("getSecurityLevel", int.class);

            boolean imported = false;
            for (int candidate : new int[]{1, 100, 2}) {
                Object level;
                try {
                    level = getLevel.invoke(keyStore, candidate);
                } catch (Throwable t) {
                    continue;
                }
                if (level == null) continue;
                try {
                    java.lang.reflect.Method importKey = level.getClass().getMethod("importKey",
                            android.system.keystore2.KeyDescriptor.class,
                            android.system.keystore2.KeyDescriptor.class,
                            java.util.Collection.class, int.class, byte[].class);
                    importKey.invoke(level, descriptor, null, filtered, 0, pkcs8);
                    imported = true;
                    break;
                } catch (Throwable ignored) {
                }
            }
            if (!imported) return;
            try {
                ((android.security.KeyStore2) keyStore)
                        .updateSubcomponents(descriptor, leafDer, chainDer);
            } catch (Throwable ignored) {
            }
            recordEvent("import", "keystore import ok alias=" + alias);
            if (Config.get().debug) HookImpl.debug("software key imported into keystore");
        } catch (Throwable t) {
            Config.log("keystore import skipped", t);
        }
    }

    private static boolean teeWorks() {
        int state = sTeeState;
        if (state != 0) return state == 1;
        synchronized (HookImpl.class) {
            if (sTeeState != 0) return sTeeState == 1;
            boolean works = false;
            String alias = "farewell_probe_" + Process.myPid();
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
            }
            try {
                KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
                keyStore.load(null);
                keyStore.deleteEntry(alias);
            } catch (Throwable ignored) {
            }
            sTeeState = works ? 1 : 2;
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

    private static Object field(Object target, String name) {
        if (target == null) return null;
        Class<?> type = target.getClass();
        while (type != null) {
            try {
                Field field = type.getDeclaredField(name);
                field.setAccessible(true);
                return field.get(target);
            } catch (NoSuchFieldException ignored) {
                type = type.getSuperclass();
            } catch (Throwable t) {
                return null;
            }
        }
        return null;
    }

    private static String asString(Object value) {
        return value instanceof String ? (String) value : null;
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

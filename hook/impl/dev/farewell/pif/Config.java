package dev.farewell.pif;

import android.app.ActivityThread;
import android.content.Context;
import android.os.Build;
import android.os.SystemClock;
import android.os.SystemProperties;
import android.provider.Settings;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Configuration reader.
 *
 * Primary channel is ONE neutral Settings.Global key ("sys_thermal_profile") holding an
 * obfuscated envelope (F1: + base64 + repeating-key XOR of a compact JSON). A plain JSON
 * value is also accepted for manual provisioning. Legacy individual farewell_* keys are
 * still read as a fallback.
 *
 * Envelope JSON:
 * <pre>
 * {
 *   "en": 1, "fl": 3, "md": "auto", "dbg": 0,
 *   "pf": { profile },
 *   "tg": ["com.google.android.gms:com.google.android.gms.unstable", "com.android.vending"],
 *   "nb": ["package:process"],
 *   "kb": ["base64 keybox xml", ...], "kbi": -1,
 *   "ft": {"pkg": {"feature": true}},
 *   "ap": {"pkg": {"pf": { profile override }}}
 * }
 * </pre>
 */
final class Config {
    static final int FLAG_PROPS = 1;
    static final int FLAG_KEYBOX = 2;
    static final int FLAG_SECURE = 4;
    static final int FLAG_SIGNATURE = 8;
    static final int FLAG_PROVIDER = 16;

    static final int MODE_AUTO = 0;
    static final int MODE_LEAF = 1;
    static final int MODE_GENERATE = 2;

    static final String KEY_NEUTRAL = "sys_thermal_profile";

    static final String KEY_ENABLE = "farewell_enable";
    static final String KEY_FLAGS = "farewell_flags";
    static final String KEY_MODE = "farewell_mode";
    static final String KEY_PROFILE = "farewell_profile";
    static final String KEY_TARGETS = "farewell_targets";
    static final String KEY_KEYBOX = "farewell_keybox";
    static final String KEY_KEYBOX_INDEX = "farewell_keybox_index";
    static final String KEY_FEATURES = "farewell_features";
    static final String KEY_DEBUG = "farewell_debug";

    static final String DEFAULT_TARGETS =
            "[\"com.google.android.gms:com.google.android.gms.unstable\",\"com.android.vending\"]";

    static final byte[] XOR_KEY = {
            0x46, 0x61, 0x72, 0x65, 0x77, 0x65, 0x6C, 0x6C,
            0x50, 0x49, 0x46, 0x2D, 0x53, 0x31, 0x21, 0x50,
            0x72, 0x6F, 0x66, 0x69, 0x6C, 0x65, 0x2D, 0x4B,
            0x65, 0x79, 0x62, 0x6F, 0x78, 0x2D, 0x30, 0x31
    };

    private static final long TTL_MS = 3000L;

    private static volatile Snapshot sSnapshot = Snapshot.DISABLED;
    private static volatile long sLastRead = -TTL_MS;
    private static volatile Context sContext;
    private static volatile String sPackage;
    private static volatile boolean sSystemServer;

    private Config() {
    }

    static void setContext(Context context) {
        if (context == null) return;
        Context app = context.getApplicationContext();
        sContext = app != null ? app : context;
        try {
            sPackage = sContext.getPackageName();
        } catch (Throwable ignored) {
        }
    }

    static void setSystemServer(boolean value) {
        sSystemServer = value;
    }

    static Context context() {
        Context c = sContext;
        if (c != null) return c;
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

    static String currentPackage() {
        if (sSystemServer) return null;
        String pkg = sPackage;
        if (pkg != null) return pkg;
        try {
            pkg = ActivityThread.currentPackageName();
        } catch (Throwable ignored) {
        }
        return pkg;
    }

    static void invalidate() {
        sLastRead = -TTL_MS;
    }

    static Snapshot get() {
        long now = SystemClock.uptimeMillis();
        Snapshot snapshot = sSnapshot;
        if (snapshot != null && now - sLastRead < TTL_MS) return snapshot;
        synchronized (Config.class) {
            now = SystemClock.uptimeMillis();
            if (sSnapshot != null && now - sLastRead < TTL_MS) return sSnapshot;
            Snapshot loaded = load();
            sSnapshot = loaded;
            sLastRead = SystemClock.uptimeMillis();
            return loaded;
        }
    }

    private static Snapshot load() {
        try {
            Context context = context();
            if (context == null) return Snapshot.DISABLED;
            String envelope = getString(context, KEY_NEUTRAL, null);
            if (envelope != null) {
                Snapshot fromEnvelope = Snapshot.fromEnvelope(envelope);
                if (fromEnvelope != null) return fromEnvelope;
            }
            return Snapshot.fromLegacy(context);
        } catch (Throwable t) {
            Log.e(HookImpl.TAG, "config load failed", t);
            return Snapshot.DISABLED;
        }
    }

    private static int getInt(Context c, String key, int def) {
        try {
            return Settings.Global.getInt(c.getContentResolver(), key, def);
        } catch (Throwable t) {
            return def;
        }
    }

    private static String getString(Context c, String key, String def) {
        try {
            String value = Settings.Global.getString(c.getContentResolver(), key);
            return value != null ? value : def;
        } catch (Throwable t) {
            return def;
        }
    }

    static byte[] xor(byte[] data) {
        if (data == null) return null;
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            out[i] = (byte) (data[i] ^ XOR_KEY[i % XOR_KEY.length]);
        }
        return out;
    }

    // ------------------------------------------------------------- VINTF versions

    private static volatile boolean sVintfLoaded;
    private static volatile boolean sVintfPresent;
    private static volatile boolean sVintfExact;
    private static volatile int sVintfVersion;

    private static final java.util.regex.Pattern HAL_BLOCK =
            java.util.regex.Pattern.compile("<hal\\b[^>]*>.*?</hal>",
                    java.util.regex.Pattern.DOTALL);
    private static final java.util.regex.Pattern VERSION_INT =
            java.util.regex.Pattern.compile("<version>\\s*(\\d+)\\s*</version>");
    private static final java.util.regex.Pattern HIDL_FQNAME =
            java.util.regex.Pattern.compile("@(\\d+)\\.(\\d+)::IKeymasterDevice/");
    private static final java.util.regex.Pattern VERSION_DOTTED =
            java.util.regex.Pattern.compile("<version>\\s*(\\d+)\\.(\\d+)\\s*</version>");

    private static final String[] VINTF_PATHS = {
            "/vendor/etc/vintf/manifest.xml", "/vendor/etc/vintf/manifest",
            "/odm/etc/vintf/manifest.xml", "/odm/etc/vintf/manifest",
            "/system/etc/vintf/manifest.xml", "/system/etc/vintf/manifest",
            "/system_ext/etc/vintf/manifest.xml", "/system_ext/etc/vintf/manifest",
            "/product/etc/vintf/manifest.xml", "/product/etc/vintf/manifest",
            "/vendor/manifest.xml"
    };

    /**
     * Reconciles the attestation version with the keystore HAL declared in VINTF, following
     * TEESimulator: AIDL KeyMint @N is a ceiling (N*100), legacy HIDL Keymaster is exact
     * (@2.0 -> 1, @3.0 -> 2, @4.0 -> 3, @4.1 -> 4).
     */
    private static void loadVintf() {
        if (sVintfLoaded) return;
        synchronized (Config.class) {
            if (sVintfLoaded) return;
            int bestKeymint = -1;
            int bestKeymaster = -1;
            List<java.io.File> files = new ArrayList<java.io.File>();
            for (String path : VINTF_PATHS) {
                java.io.File file = new java.io.File(path);
                if (file.isDirectory()) {
                    java.io.File[] children = file.listFiles();
                    if (children != null) {
                        for (java.io.File child : children) {
                            if (child.isFile() && child.getName().endsWith(".xml")) files.add(child);
                        }
                    }
                } else if (file.isFile()) {
                    files.add(file);
                }
            }
            for (java.io.File file : files) {
                try {
                    byte[] bytes = new byte[(int) Math.min(file.length(), 512 * 1024)];
                    java.io.FileInputStream input = new java.io.FileInputStream(file);
                    int read = input.read(bytes);
                    input.close();
                    if (read <= 0) continue;
                    String text = new String(bytes, 0, read, "UTF-8");
                    java.util.regex.Matcher blocks = HAL_BLOCK.matcher(text);
                    while (blocks.find()) {
                        String block = blocks.group();
                        if (block.contains("android.hardware.security.keymint")
                                && block.contains("IKeyMintDevice")) {
                            java.util.regex.Matcher version = VERSION_INT.matcher(block);
                            while (version.find()) {
                                try {
                                    int value = Integer.parseInt(version.group(1));
                                    if (value > bestKeymint) bestKeymint = value;
                                } catch (Throwable ignored) {
                                }
                            }
                        } else if (block.contains("android.hardware.keymaster")
                                && block.contains("IKeymasterDevice")) {
                            Integer value = keymasterAttestationFromBlock(block);
                            if (value != null && value > bestKeymaster) bestKeymaster = value;
                        }
                    }
                } catch (Throwable ignored) {
                }
            }
            if (bestKeymint > 0) {
                sVintfVersion = bestKeymint * 100;
                sVintfExact = false;
                sVintfPresent = true;
            } else if (bestKeymaster > 0) {
                sVintfVersion = bestKeymaster;
                sVintfExact = true;
                sVintfPresent = true;
            }
            sVintfLoaded = true;
        }
    }

    private static Integer keymasterAttestationFromBlock(String block) {
        java.util.regex.Matcher fqname = HIDL_FQNAME.matcher(block);
        if (fqname.find()) {
            return keymasterToAttestation(Integer.parseInt(fqname.group(1)),
                    Integer.parseInt(fqname.group(2)));
        }
        java.util.regex.Matcher dotted = VERSION_DOTTED.matcher(block);
        if (dotted.find()) {
            return keymasterToAttestation(Integer.parseInt(dotted.group(1)),
                    Integer.parseInt(dotted.group(2)));
        }
        return null;
    }

    private static Integer keymasterToAttestation(int major, int minor) {
        if (major == 2) return Integer.valueOf(1);
        if (major == 3) return Integer.valueOf(2);
        if (major == 4) return Integer.valueOf(minor >= 1 ? 4 : 3);
        return null;
    }

    static void log(String message, Throwable t) {
        try {
            Snapshot snapshot = sSnapshot;
            if (snapshot != null && snapshot.debug) Log.e(HookImpl.TAG, message, t);
        } catch (Throwable ignored) {
        }
    }

    private static final Set<String> LOGGED = new HashSet<String>();

    static void logOnce(String message) {
        try {
            if (LOGGED.add(message)) Log.e(HookImpl.TAG, message);
        } catch (Throwable ignored) {
        }
    }

    static final class TargetRule {
        final String packageName;
        final String process;
        final boolean wildcard;

        TargetRule(String packageName, String process) {
            this.packageName = packageName;
            this.process = process;
            this.wildcard = packageName.endsWith("*");
        }

        boolean matches(String pkg, String proc) {
            if (pkg == null) return false;
            if (wildcard) {
                if (!pkg.startsWith(packageName.substring(0, packageName.length() - 1))) {
                    return false;
                }
            } else if (!packageName.equals(pkg)) {
                return false;
            }
            return process == null || process.equals(proc);
        }
    }

    static final class Snapshot {
        static final Snapshot DISABLED = new Snapshot();

        boolean enabled;
        boolean debug;
        int flags;
        int mode = MODE_AUTO;
        int keyboxIndex = -1;
        JSONObject profile;
        JSONObject features;
        List<String> keyboxList = new ArrayList<String>();
        List<TargetRule> targets = new ArrayList<TargetRule>();
        List<TargetRule> blacklist = new ArrayList<TargetRule>();
        Map<String, JSONObject> appProfiles = new HashMap<String, JSONObject>();
        private final Map<String, JSONObject> mergedProfiles = new HashMap<String, JSONObject>();

        boolean propsEnabled() {
            return enabled && (flags & FLAG_PROPS) != 0;
        }

        boolean signatureSpoof() {
            return enabled && (flags & FLAG_SIGNATURE) != 0;
        }

        boolean providerSpoof() {
            return enabled && (flags & FLAG_PROVIDER) != 0;
        }

        boolean keyboxEnabled() {
            return enabled && (flags & FLAG_KEYBOX) != 0 && !keyboxList.isEmpty();
        }

        boolean secureFlag() {
            return enabled && (flags & FLAG_SECURE) != 0;
        }

        boolean isTarget(String pkg, String process) {
            if (pkg == null) return false;
            for (TargetRule rule : blacklist) {
                if (rule.matches(pkg, process)) return false;
            }
            for (TargetRule rule : targets) {
                if (rule.matches(pkg, process)) return true;
            }
            return false;
        }

        /**
         * Whether Build/property spoofing applies to this process.
         *
         * On Android 12L and below, spoofing the Play Store (Vending) fingerprint breaks Play
         * Integrity / GMS instead of helping, so Vending stays a target for attestation only.
         * Mirrors PlayIntegrityFork's spoofVendingFinger=0 default for SDK &lt;= 32 (audited from
         * AlwaysStrong engine.sh).
         */
        boolean propsFor(String pkg, String process) {
            if (!isTarget(pkg, process)) return false;
            if (android.os.Build.VERSION.SDK_INT <= 32
                    && "com.android.vending".equals(pkg)) {
                return false;
            }
            return true;
        }

        JSONObject profileFor(String pkg) {
            JSONObject entry = pkg != null ? appProfiles.get(pkg) : null;
            JSONObject override = entry != null ? entry.optJSONObject("pf") : null;
            if (override == null) return profile;
            if (profile == null) return override;
            String cacheKey = pkg + ":" + profile.hashCode() + ":" + override.hashCode();
            JSONObject cached = mergedProfiles.get(cacheKey);
            if (cached != null) return cached;
            try {
                JSONObject merged = new JSONObject(profile.toString());
                java.util.Iterator<String> keys = override.keys();
                while (keys.hasNext()) {
                    String key = keys.next();
                    merged.put(key, override.get(key));
                }
                if (mergedProfiles.size() > 32) mergedProfiles.clear();
                mergedProfiles.put(cacheKey, merged);
                return merged;
            } catch (Throwable t) {
                return profile;
            }
        }

        /** Per-app attestation mode override ("md" in the ap entry), else the global mode. */
        int modeFor(String pkg) {
            JSONObject entry = pkg != null ? appProfiles.get(pkg) : null;
            if (entry != null && entry.has("md")) {
                return parseMode(entry.optString("md", null));
            }
            return mode;
        }

        /** Per-app keybox index override ("kbi" in the ap entry), else the global index. */
        int keyboxIndexFor(String pkg) {
            JSONObject entry = pkg != null ? appProfiles.get(pkg) : null;
            if (entry != null && entry.has("kbi")) {
                return entry.optInt("kbi", keyboxIndex);
            }
            return keyboxIndex;
        }

        /**
         * Rootless resetprop: the spoofed value for a Java SystemProperties read, or null when
         * there is no override (caller falls back to the real value). Only consulted for target
         * processes by HookImpl.property().
         */
        String spoofProperty(String key) {
            if (key == null) return null;
            switch (key) {
                case "ro.boot.verifiedbootstate":
                case "ro.boot.verifiedbootstate.color":
                    return "green";
                case "ro.boot.flash.locked":
                    return "1";
                case "ro.boot.veritymode":
                case "ro.boot.veritymode.managed":
                    return "enforcing";
                case "ro.debuggable":
                    return "0";
                case "ro.secure":
                    return "1";
                case "ro.build.type":
                    return "user";
                case "ro.build.tags":
                    return "release-keys";
                case "sys.usb.state":
                    return "mtp";
                case "init.svc.adbd":
                    return "stopped";
                default:
                    break;
            }
            if (key.endsWith(".security_patch")) {
                String patch = profileString("SECURITY_PATCH");
                if (patch != null) return patch;
                String build = Build.VERSION.SECURITY_PATCH;
                return build != null && !build.isEmpty() ? build : null;
            }
            if (key.endsWith(".build.id")) return profileString("ID");
            if (key.endsWith(".api_level")) return profileString("DEVICE_INITIAL_SDK_INT");
            switch (key) {
                case "ro.build.fingerprint":
                case "ro.bootimage.build.fingerprint":
                case "ro.vendor.build.fingerprint":
                case "ro.system.build.fingerprint":
                case "ro.product.build.fingerprint":
                case "ro.odm.build.fingerprint":
                    return profileString("FINGERPRINT");
                case "ro.product.model":
                    return profileString("MODEL");
                case "ro.product.brand":
                    return profileString("BRAND");
                case "ro.product.device":
                    return profileString("DEVICE");
                case "ro.product.name":
                    return profileString("PRODUCT");
                case "ro.product.manufacturer":
                    return profileString("MANUFACTURER");
                case "ro.build.id":
                    return profileString("ID");
                case "ro.build.version.incremental":
                    return profileString("INCREMENTAL");
                case "ro.build.version.release":
                    return profileString("RELEASE");
                case "ro.build.description":
                    return buildDescription();
                default:
                    return null;
            }
        }

        private String buildDescription() {
            String product = profileString("PRODUCT");
            String type = profileString("TYPE");
            String release = profileString("RELEASE");
            String id = profileString("ID");
            String incremental = profileString("INCREMENTAL");
            String tags = profileString("TAGS");
            if (product == null || type == null) return null;
            return product + "-" + type + " " + (release != null ? release : "")
                    + " " + (id != null ? id : "") + " " + (incremental != null ? incremental : "")
                    + " " + (tags != null ? tags : "");
        }

        Boolean featureOverride(String pkg, String name) {
            if (features == null || pkg == null || name == null) return null;
            JSONObject pkgObject = features.optJSONObject(pkg);
            if (pkgObject == null) return null;
            if (!pkgObject.has(name)) return null;
            return Boolean.valueOf(pkgObject.optBoolean(name));
        }

        String profileString(String key) {
            return profileString(profile, key);
        }

        static String profileString(JSONObject object, String key) {
            if (object == null) return null;
            String value = object.optString(key, null);
            return value == null || value.isEmpty() ? null : value;
        }

        void expandFingerprint() {
            expandFingerprint(profile);
            for (JSONObject entry : appProfiles.values()) {
                expandFingerprint(entry.optJSONObject("pf"));
            }
        }

        static void expandFingerprint(JSONObject object) {
            if (object == null) return;
            String fingerprint = object.optString("FINGERPRINT", null);
            if (fingerprint == null || fingerprint.isEmpty()) return;
            String[] parts = fingerprint.split("[/:]");
            String[] keys = {"BRAND", "PRODUCT", "DEVICE", "RELEASE", "ID",
                    "INCREMENTAL", "TYPE", "TAGS"};
            try {
                for (int i = 0; i < keys.length && i < parts.length; i++) {
                    if (!object.has(keys[i]) || object.optString(keys[i], "").isEmpty()) {
                        object.put(keys[i], parts[i]);
                    }
                }
            } catch (Throwable ignored) {
            }
        }

        int osVersion() {
            try {
                String release = Build.VERSION.RELEASE;
                if (release != null) {
                    String[] parts = release.split("\\.");
                    int major = Integer.parseInt(parts[0].trim());
                    int minor = parts.length > 1 ? Integer.parseInt(parts[1].trim()) : 0;
                    return major * 10000 + minor * 100;
                }
            } catch (Throwable ignored) {
            }
            return Build.VERSION.SDK_INT;
        }

        /** Attestation version for the KeyDescription meta field (VINTF-reconciled). */
        int attestationVersion() {
            int fabricated = fabricatedAttestationVersion();
            loadVintf();
            if (!sVintfPresent) return fabricated;
            if (sVintfExact) return sVintfVersion;
            return Math.min(fabricated, sVintfVersion);
        }

        /** Keymaster version matching the attestation version (AOSP cert.rs mapping). */
        int keymasterVersion() {
            int attestation = attestationVersion();
            if (attestation >= 100) return attestation;
            if (attestation == 2) return 3;
            if (attestation == 3) return 4;
            if (attestation == 4) return 41;
            return attestation;
        }

        private static int fabricatedAttestationVersion() {
            int sdk = Build.VERSION.SDK_INT;
            if (sdk <= 32) return 100;
            if (sdk == 33) return 200;
            if (sdk <= 35) return 300;
            if (sdk == 36) return 400;
            return 500;
        }

        int osPatchLevel(JSONObject profile) {
            int[] date = parseYmd(profileString(profile, "SECURITY_PATCH"));
            if (date != null) return date[0] * 100 + date[1];
            date = parseYmd(Build.VERSION.SECURITY_PATCH);
            if (date != null) return date[0] * 100 + date[1];
            return 202404;
        }

        int patchLevelDay(JSONObject profile) {
            int[] date = parseYmd(profileString(profile, "SECURITY_PATCH"));
            if (date != null && date[2] > 0) return date[0] * 10000 + date[1] * 100 + date[2];
            if (date != null) return date[0] * 10000 + date[1] * 100 + 5;
            date = parseYmd(Build.VERSION.SECURITY_PATCH);
            if (date != null) return date[0] * 10000 + date[1] * 100 + 5;
            return 20240405;
        }

        String devicePropForTag(int tag, JSONObject profile) {
            switch (tag) {
                case Attestation.TAG_ID_BRAND:
                    return profileString(profile, "BRAND");
                case Attestation.TAG_ID_DEVICE:
                    return profileString(profile, "DEVICE");
                case Attestation.TAG_ID_PRODUCT:
                    return profileString(profile, "PRODUCT");
                case Attestation.TAG_ID_MANUFACTURER:
                    return profileString(profile, "MANUFACTURER");
                case Attestation.TAG_ID_MODEL:
                    return profileString(profile, "MODEL");
                default:
                    return null;
            }
        }

        private byte[] sVbKey;
        private byte[] sVbHash;

        byte[] verifiedBootKey() {
            if (sVbKey == null) sVbKey = vbBytes();
            return sVbKey;
        }

        byte[] verifiedBootHash() {
            if (sVbHash == null) sVbHash = vbBytes();
            return sVbHash;
        }

        private static byte[] vbBytes() {
            try {
                String digest = SystemProperties.get("ro.boot.vbmeta.digest", "");
                if (digest != null && digest.length() == 64) {
                    byte[] out = new byte[32];
                    for (int i = 0; i < 32; i++) {
                        out[i] = (byte) Integer.parseInt(digest.substring(i * 2, i * 2 + 2), 16);
                    }
                    return out;
                }
            } catch (Throwable ignored) {
            }
            return new byte[32];
        }

        private static int[] parseYmd(String value) {
            if (value == null) return null;
            try {
                String[] parts = value.split("[-/]");
                if (parts.length < 2) return null;
                int year = Integer.parseInt(parts[0].trim());
                int month = Integer.parseInt(parts[1].trim());
                int day = parts.length > 2 ? Integer.parseInt(parts[2].trim()) : 0;
                if (year < 2000 || month < 1 || month > 12) return null;
                return new int[]{year, month, day};
            } catch (Throwable t) {
                return null;
            }
        }

        // ------------------------------------------------------------ parsing

        static Snapshot fromEnvelope(String raw) {
            try {
                String json;
                if (raw.startsWith("{")) {
                    json = raw;
                } else if (raw.startsWith("F1:")) {
                    byte[] decoded = java.util.Base64.getDecoder().decode(raw.substring(3).trim());
                    json = new String(xor(decoded), "UTF-8");
                } else {
                    return null;
                }
                JSONObject object = new JSONObject(json);
                Snapshot snapshot = new Snapshot();
                snapshot.enabled = object.optInt("en", 0) == 1;
                if (!snapshot.enabled) return DISABLED;
                snapshot.debug = object.optInt("dbg", 0) == 1;
                snapshot.flags = object.optInt("fl", FLAG_KEYBOX | FLAG_PROPS);
                snapshot.mode = parseMode(object.optString("md", "auto"));
                snapshot.keyboxIndex = object.optInt("kbi", -1);
                snapshot.profile = object.optJSONObject("pf");
                snapshot.features = object.optJSONObject("ft");
                snapshot.targets = parseRules(object.opt("tg"));
                snapshot.blacklist = parseRules(object.opt("nb"));
                snapshot.keyboxList = parseKeyboxList(object.opt("kb"));
                JSONObject apps = object.optJSONObject("ap");
                if (apps != null) {
                    java.util.Iterator<String> keys = apps.keys();
                    while (keys.hasNext()) {
                        String pkg = keys.next();
                        JSONObject entry = apps.optJSONObject(pkg);
                        if (entry == null) continue;
                        snapshot.appProfiles.put(pkg, entry);
                        JSONObject features = entry.optJSONObject("ft");
                        if (features != null) {
                            if (snapshot.features == null) snapshot.features = new JSONObject();
                            snapshot.features.put(pkg, features);
                        }
                    }
                }
                if (snapshot.targets.isEmpty()) snapshot.targets = parseRules(parseArray(DEFAULT_TARGETS));
                snapshot.expandFingerprint();
                return snapshot;
            } catch (Throwable t) {
                Log.e(HookImpl.TAG, "envelope parse failed", t);
                return null;
            }
        }

        static Snapshot fromLegacy(Context context) {
            if (getInt(context, KEY_ENABLE, 0) != 1) return DISABLED;
            Snapshot snapshot = new Snapshot();
            snapshot.enabled = true;
            snapshot.debug = getInt(context, KEY_DEBUG, 0) == 1;
            snapshot.flags = getInt(context, KEY_FLAGS, FLAG_KEYBOX | FLAG_PROPS);
            snapshot.mode = parseMode(getString(context, KEY_MODE, null));
            snapshot.keyboxIndex = getInt(context, KEY_KEYBOX_INDEX, -1);
            snapshot.profile = parseObject(getString(context, KEY_PROFILE, null));
            snapshot.features = parseObject(getString(context, KEY_FEATURES, null));
            snapshot.targets = parseRules(parseArray(getString(context, KEY_TARGETS, null)));
            String keybox = getString(context, KEY_KEYBOX, null);
            if (keybox != null && !keybox.isEmpty()) snapshot.keyboxList.add(keybox);
            if (snapshot.targets.isEmpty()) {
                snapshot.targets = parseRules(parseArray(DEFAULT_TARGETS));
            }
            snapshot.expandFingerprint();
            return snapshot;
        }

        private static JSONObject parseObject(String json) {
            if (json == null || json.isEmpty()) return null;
            try {
                return new JSONObject(json);
            } catch (Throwable t) {
                return null;
            }
        }

        private static JSONArray parseArray(String json) {
            if (json == null || json.isEmpty()) return null;
            try {
                return new JSONArray(json);
            } catch (Throwable t) {
                JSONArray array = new JSONArray();
                for (String part : json.split("[,\\s]+")) {
                    if (!part.isEmpty()) array.put(part);
                }
                return array;
            }
        }

        private static List<TargetRule> parseRules(Object value) {
            List<TargetRule> rules = new ArrayList<TargetRule>();
            if (value == null) return rules;
            JSONArray array;
            if (value instanceof JSONArray) {
                array = (JSONArray) value;
            } else {
                array = parseArray(String.valueOf(value));
                if (array == null) return rules;
            }
            for (int i = 0; i < array.length(); i++) {
                String entry = array.optString(i, null);
                if (entry == null || entry.isEmpty()) continue;
                String pkg = entry;
                String process = null;
                int separator = entry.indexOf(':');
                if (separator > 0) {
                    pkg = entry.substring(0, separator);
                    process = entry.substring(separator + 1);
                    if (process.isEmpty()) process = null;
                }
                rules.add(new TargetRule(pkg, process));
            }
            return rules;
        }

        private static List<String> parseKeyboxList(Object value) {
            List<String> list = new ArrayList<String>();
            if (value == null) return list;
            if (value instanceof String) {
                String single = ((String) value).trim();
                if (!single.isEmpty()) list.add(single);
                return list;
            }
            if (value instanceof JSONArray) {
                JSONArray array = (JSONArray) value;
                for (int i = 0; i < array.length(); i++) {
                    String entry = array.optString(i, null);
                    if (entry != null && !entry.isEmpty()) list.add(entry);
                }
            }
            return list;
        }

        private static int parseMode(String value) {
            if (value == null) return MODE_AUTO;
            String normalized = value.trim().toLowerCase();
            if (normalized.equals("leaf") || normalized.equals("1")) return MODE_LEAF;
            if (normalized.equals("generate") || normalized.equals("gen") || normalized.equals("2")) {
                return MODE_GENERATE;
            }
            return MODE_AUTO;
        }
    }
}

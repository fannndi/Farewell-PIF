package dev.farewell.pif.app;

import android.content.Context;
import android.provider.Settings;
import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Shared Settings.Global channel: config envelope and hook dex sideload.
 *
 * Used by MainActivity (UI/ops) and BootReceiver (restores the hook after a reboot when the ROM
 * drops unknown settings keys). Contains no UI, no network.
 */
final class HookStore {
    static final String KEY = "sys_thermal_profile";
    static final String HOOK_META = "sys_perf_dex_meta";
    static final String HOOK_CHUNK = "sys_perf_dex_";
    static final String HOOK_GATE = "sys_perf_dex_pkgs";
    static final int HOOK_MAX_CHUNKS = 32;
    static final int HOOK_CHUNK_SIZE = 140 * 1024;

    static final String[] LEGACY_KEYS = {
            "farewell_enable", "farewell_flags", "farewell_mode", "farewell_profile",
            "farewell_targets", "farewell_keybox", "farewell_keybox_index",
            "farewell_features", "farewell_debug"
    };

    static final byte[] XOR_KEY = {
            0x46, 0x61, 0x72, 0x65, 0x77, 0x65, 0x6C, 0x6C,
            0x50, 0x49, 0x46, 0x2D, 0x53, 0x31, 0x21, 0x50,
            0x72, 0x6F, 0x66, 0x69, 0x6C, 0x65, 0x2D, 0x4B,
            0x65, 0x79, 0x62, 0x6F, 0x78, 0x2D, 0x30, 0x31
    };

    static final String DEFAULT_CONFIG =
            "{\"v\":1,\"en\":0,\"fl\":3,\"md\":\"auto\",\"dbg\":0,"
            + "\"pf\":{},\"tg\":[\"com.google.android.gms:com.google.android.gms.unstable\","
            + "\"com.android.vending\"],\"nb\":[],\"kb\":[],\"kbi\":-1,\"ft\":{},\"ap\":{}}";

    private HookStore() {
    }

    // ------------------------------------------------------------------ settings

    static String getString(Context context, String key) {
        try {
            return Settings.Global.getString(context.getContentResolver(), key);
        } catch (Throwable t) {
            return null;
        }
    }

    static void putString(Context context, String key, String value) {
        Settings.Global.putString(context.getContentResolver(), key, value);
    }

    static void deleteKey(Context context, String key) {
        try {
            Settings.Global.putString(context.getContentResolver(), key, null);
        } catch (Throwable ignored) {
        }
    }

    // -------------------------------------------------------------------- config

    /**
     * Private copy of the config, including the keybox.
     *
     * MIUI's settings provider does not persist the large (23 KB) envelope across reboots: the
     * write is served from memory for the session and the disk keeps the last small value. The
     * app therefore keeps the authoritative copy here and re-seeds Settings.Global on boot.
     */
    private static File channelFile(Context context) {
        return new File(context.getFilesDir(), "channel.json");
    }

    static JSONObject loadStored(Context context) {
        try {
            File file = channelFile(context);
            if (!file.exists()) return null;
            byte[] data = readAll(new FileInputStream(file));
            return new JSONObject(new String(data, StandardCharsets.UTF_8));
        } catch (Throwable t) {
            return null;
        }
    }

    private static void saveStored(Context context, JSONObject config) {
        try {
            FileOutputStream out = new FileOutputStream(channelFile(context));
            out.write(config.toString().getBytes(StandardCharsets.UTF_8));
            out.close();
        } catch (Throwable ignored) {
        }
    }

    static JSONObject readConfig(Context context) {
        JSONObject config;
        try {
            String raw = getString(context, KEY);
            String json = null;
            if (raw != null && !raw.isEmpty()) {
                if (raw.startsWith("{")) {
                    json = raw;
                } else if (raw.startsWith("F1:")) {
                    byte[] decoded = Base64.decode(raw.substring(3), Base64.DEFAULT);
                    json = new String(xor(decoded), StandardCharsets.UTF_8);
                }
            }
            if (json == null) json = migrateLegacy(context);
            if (json == null) json = DEFAULT_CONFIG;
            config = new JSONObject(json);
        } catch (Throwable t) {
            try {
                config = new JSONObject(DEFAULT_CONFIG);
            } catch (Throwable ignored) {
                throw new RuntimeException(t);
            }
        }
        JSONArray keyboxes = config.optJSONArray("kb");
        if (keyboxes == null || keyboxes.length() == 0) {
            JSONObject stored = loadStored(context);
            JSONArray storedKb = stored != null ? stored.optJSONArray("kb") : null;
            if (storedKb != null && storedKb.length() > 0) {
                try {
                    config.put("kb", storedKb);
                    if (!config.has("pf") && stored.has("pf")) config.put("pf", stored.get("pf"));
                } catch (Throwable ignored) {
                }
            }
        }
        return config;
    }

    static boolean writeConfig(Context context, JSONObject config) {
        try {
            byte[] encoded = xor(config.toString().getBytes(StandardCharsets.UTF_8));
            putString(context, KEY, "F1:" + Base64.encodeToString(encoded, Base64.NO_WRAP));
            for (String legacy : LEGACY_KEYS) deleteKey(context, legacy);
            saveStored(context, config);
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    private static String migrateLegacy(Context context) {
        try {
            if (!"1".equals(getString(context, "farewell_enable"))) return null;
            JSONObject config = new JSONObject(DEFAULT_CONFIG);
            config.put("en", 1);
            String flags = getString(context, "farewell_flags");
            if (flags != null) config.put("fl", Integer.parseInt(flags.trim()));
            String mode = getString(context, "farewell_mode");
            if (mode != null) config.put("md", mode);
            String profile = getString(context, "farewell_profile");
            if (profile != null && !profile.isEmpty()) config.put("pf", new JSONObject(profile));
            String targets = getString(context, "farewell_targets");
            if (targets != null && !targets.isEmpty()) config.put("tg", new JSONArray(targets));
            String keybox = getString(context, "farewell_keybox");
            if (keybox != null && !keybox.isEmpty()) config.put("kb", new JSONArray().put(keybox));
            String features = getString(context, "farewell_features");
            if (features != null && !features.isEmpty()) config.put("ft", new JSONObject(features));
            if ("1".equals(getString(context, "farewell_debug"))) config.put("dbg", 1);
            return config.toString();
        } catch (Throwable t) {
            return null;
        }
    }

    // ----------------------------------------------------------------- hook dex

    /** ",android,self,<target packages>," allowlist for the bootstrap (non-targets skip the dex). */
    static String gateValue(Context context, JSONObject config) {
        java.util.LinkedHashSet<String> set = new java.util.LinkedHashSet<String>();
        set.add("android");
        set.add(context.getPackageName());
        // Boot-state spoofing and the "all apps" mode need these loaded too.
        set.add("com.android.settings");
        set.add("com.google.android.gsf");
        JSONArray targets = config.optJSONArray("tg");
        if (targets != null) {
            for (int i = 0; i < targets.length(); i++) {
                String rule = targets.optString(i, "");
                if (rule.isEmpty()) continue;
                String pkg = rule.contains(":") ? rule.substring(0, rule.indexOf(':')) : rule;
                if (!pkg.endsWith("*")) set.add(pkg);
            }
        }
        StringBuilder builder = new StringBuilder(",");
        for (String pkg : set) builder.append(pkg).append(',');
        return builder.toString();
    }

    static void removeHook(Context context) {
        deleteKey(context, HOOK_META);
        deleteKey(context, HOOK_GATE);
        for (int i = 0; i < HOOK_MAX_CHUNKS; i++) {
            deleteKey(context, HOOK_CHUNK + i);
        }
    }

    /**
     * Writes the bundled hook dex into Settings.Global for the bootstrap to hot-load.
     * Idempotent: skips the chunk rewrite when the current meta already matches. Never restarts
     * GMS; the caller decides (the boot receiver must not kill anything).
     */
    static String installHook(Context context) {
        try {
            byte[] dex = readAll(context.getAssets().open("hook.dex"));
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(dex);
            StringBuilder sha = new StringBuilder();
            for (byte value : hash) sha.append(String.format("%02x", value));
            String shaHex = sha.toString();

            int chunks = (dex.length + HOOK_CHUNK_SIZE - 1) / HOOK_CHUNK_SIZE;
            if (chunks > HOOK_MAX_CHUNKS) {
                return "{\"ok\":false,\"error\":\"hook dex too large\"}";
            }
            String version = "1";
            try {
                version = context.getPackageManager()
                        .getPackageInfo(context.getPackageName(), 0).versionName;
            } catch (Throwable ignored) {
            }

            String current = getString(context, HOOK_META);
            if (current != null && current.startsWith(shaHex + ":")
                    && current.endsWith(":" + version)) {
                putString(context, HOOK_GATE, gateValue(context, readConfig(context)));
                JSONObject cached = new JSONObject();
                cached.put("ok", true);
                cached.put("cached", true);
                cached.put("sha", shaHex);
                cached.put("chunks", chunks);
                cached.put("version", version);
                cached.put("size", dex.length);
                return cached.toString();
            }

            for (int i = 0; i < chunks; i++) {
                int from = i * HOOK_CHUNK_SIZE;
                int to = Math.min(dex.length, from + HOOK_CHUNK_SIZE);
                byte[] part = java.util.Arrays.copyOfRange(dex, from, to);
                putString(context, HOOK_CHUNK + i,
                        Base64.encodeToString(xor(part), Base64.NO_WRAP));
            }
            for (int i = chunks; i < HOOK_MAX_CHUNKS; i++) {
                deleteKey(context, HOOK_CHUNK + i);
            }
            putString(context, HOOK_META, shaHex + ":" + chunks + ":" + version);
            putString(context, HOOK_GATE, gateValue(context, readConfig(context)));

            JSONObject out = new JSONObject();
            out.put("ok", true);
            out.put("sha", shaHex);
            out.put("chunks", chunks);
            out.put("version", version);
            out.put("size", dex.length);
            return out.toString();
        } catch (Throwable t) {
            return "{\"ok\":false,\"error\":\"" + t.getMessage() + "\"}";
        }
    }

    // ------------------------------------------------------------------- helpers

    static byte[] xor(byte[] data) {
        if (data == null) return new byte[0];
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            out[i] = (byte) (data[i] ^ XOR_KEY[i % XOR_KEY.length]);
        }
        return out;
    }

    private static byte[] readAll(InputStream input) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = input.read(buffer)) > 0) output.write(buffer, 0, read);
        input.close();
        return output.toByteArray();
    }
}

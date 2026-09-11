package dev.farewell.pif.app;

import org.json.JSONObject;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/**
 * Optional online profile update (the OemPorts10T "pif-updater" idea, user initiated only).
 *
 * The framework stays offline by default; this helper is invoked from the Advanced tab or over
 * ADB (op/task {@code update_profile}) and only fetches a profile JSON. It accepts both the
 * Pif-props.json format and the OemPorts10T / PIFork pif.json shape (JSON or KEY=VALUE).
 */
final class Updater {
    /** Bundled default source: this repository's reference profile. */
    static final String DEFAULT_PROFILE_URL =
            "https://raw.githubusercontent.com/fannndi/Farewell-PIF/main/"
                    + "reference/profile/Pif-props.json";

    private Updater() {
    }

    /**
     * Opt-in boot fetch (config "au"=1): refreshes the profile when the device is online.
     * Rootless counterpart of the OemPorts10T init service: runs inside this app's process,
     * only on boot, never in the background, and does nothing when unchanged or offline.
     */
    static void autoUpdate(final android.content.Context context) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    JSONObject config = HookStore.readConfig(context);
                    if (config.optInt("au", 0) != 1) return;
                    android.net.ConnectivityManager manager =
                            (android.net.ConnectivityManager) context.getSystemService(
                                    android.content.Context.CONNECTIVITY_SERVICE);
                    android.net.NetworkInfo network = manager != null
                            ? manager.getActiveNetworkInfo() : null;
                    if (network == null || !network.isConnected()) return;
                    String url = config.optString("auUrl", DEFAULT_PROFILE_URL);
                    JSONObject profile = parseProfile(fetch(url));
                    if (profile == null || profile.optString("FINGERPRINT", "").isEmpty()) return;
                    JSONObject current = config.optJSONObject("pf");
                    if (current != null && profile.optString("FINGERPRINT", "")
                            .equals(current.optString("FINGERPRINT", ""))) {
                        return;
                    }
                    config.put("pf", profile);
                    HookStore.writeConfig(context, config);
                    android.util.Log.i("FarewellPIF",
                            "auto-updated profile -> " + profile.optString("FINGERPRINT"));
                } catch (Throwable t) {
                    android.util.Log.i("FarewellPIF", "auto-update skipped: " + t);
                }
            }
        }, "farewell-autoupdate").start();
    }

    static String updateProfile(MainActivity activity, String url) {
        JSONObject out = new JSONObject();
        try {
            String source = url == null || url.isEmpty() ? DEFAULT_PROFILE_URL : url;
            JSONObject profile = parseProfile(fetch(source));
            if (profile == null || profile.optString("FINGERPRINT", "").isEmpty()) {
                out.put("ok", false);
                out.put("error", "response has no FINGERPRINT");
                return out.toString();
            }
            JSONObject config = activity.readConfig();
            config.put("pf", profile);
            activity.writeConfig(config);
            out.put("ok", true);
            out.put("url", source);
            out.put("model", profile.optString("MODEL", ""));
            out.put("fingerprint", profile.optString("FINGERPRINT", ""));
            return out.toString();
        } catch (Throwable t) {
            try {
                out.put("ok", false);
                out.put("error", String.valueOf(t));
            } catch (Throwable ignored) {
            }
            return out.toString();
        }
    }

    private static String fetch(String source) throws Exception {
        HttpURLConnection connection = (HttpURLConnection) new URL(source).openConnection();
        connection.setConnectTimeout(10000);
        connection.setReadTimeout(15000);
        connection.setRequestProperty("User-Agent", "Farewell-PIF");
        try {
            int code = connection.getResponseCode();
            if (code != 200) throw new IllegalStateException("HTTP " + code);
            StringBuilder builder = new StringBuilder();
            InputStream input = connection.getInputStream();
            try {
                byte[] buffer = new byte[8192];
                int read;
                while ((read = input.read(buffer)) > 0) {
                    builder.append(new String(buffer, 0, read, StandardCharsets.UTF_8));
                }
            } finally {
                input.close();
            }
            return builder.toString();
        } finally {
            connection.disconnect();
        }
    }

    /** JSON object or KEY=VALUE lines, as shipped by PIFork / OemPorts10T tooling. */
    private static JSONObject parseProfile(String body) throws Exception {
        String trimmed = body == null ? "" : body.trim();
        if (trimmed.startsWith("{")) return new JSONObject(trimmed);
        JSONObject profile = new JSONObject();
        for (String line : trimmed.split("\\r?\\n")) {
            String clean = line.trim();
            if (clean.isEmpty() || clean.startsWith("#") || clean.startsWith("//")) continue;
            int eq = clean.indexOf('=');
            if (eq <= 0) continue;
            profile.put(clean.substring(0, eq).trim(), clean.substring(eq + 1).trim());
        }
        return profile.optString("FINGERPRINT", "").isEmpty() ? null : profile;
    }
}

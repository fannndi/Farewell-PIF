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

package dev.farewell.pif.app;

import android.app.Activity;
import android.app.ActivityManager;
import android.app.AlertDialog;
import android.content.ContentResolver;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.text.InputType;
import android.util.Base64;
import android.view.View;
import android.webkit.JavascriptInterface;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.widget.EditText;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeMap;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

/**
 * Farewell-PIF controller (manual/offline).
 *
 * No network calls: keybox and profile are loaded from files bundled in the APK or picked by
 * the user. The framework hook dex is installed into Settings.Global and hot-loaded by the
 * bootstrap in framework.jar, so hook updates no longer require a ROM repack.
 */
public class MainActivity extends Activity {
    private static final String KEY = "sys_thermal_profile";
    private static final String HOOK_META = "sys_perf_dex_meta";
    private static final String HOOK_CHUNK = "sys_perf_dex_";
    private static final int HOOK_MAX_CHUNKS = 32;
    private static final int HOOK_CHUNK_SIZE = 140 * 1024;

    private static final String[] LEGACY_KEYS = {
            "farewell_enable", "farewell_flags", "farewell_mode", "farewell_profile",
            "farewell_targets", "farewell_keybox", "farewell_keybox_index",
            "farewell_features", "farewell_debug"
    };

    private static final byte[] XOR_KEY = {
            0x46, 0x61, 0x72, 0x65, 0x77, 0x65, 0x6C, 0x6C,
            0x50, 0x49, 0x46, 0x2D, 0x53, 0x31, 0x21, 0x50,
            0x72, 0x6F, 0x66, 0x69, 0x6C, 0x65, 0x2D, 0x4B,
            0x65, 0x79, 0x62, 0x6F, 0x78, 0x2D, 0x30, 0x31
    };

    private static final String DEFAULT_CONFIG =
            "{\"v\":1,\"en\":0,\"fl\":3,\"md\":\"auto\",\"dbg\":0,"
            + "\"pf\":{},\"tg\":[\"com.google.android.gms:com.google.android.gms.unstable\","
            + "\"com.android.vending\"],\"nb\":[],\"kb\":[],\"kbi\":-1,\"ft\":{},\"ap\":{}}";

    private final Handler handler = new Handler(Looper.getMainLooper());
    private WebView webView;
    private ValueCallback<Uri[]> fileCallback;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        webView = new WebView(this);
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setAllowFileAccess(true);
        settings.setAllowContentAccess(false);
        try {
            settings.setAllowFileAccessFromFileURLs(false);
            settings.setAllowUniversalAccessFromFileURLs(false);
        } catch (Throwable ignored) {
        }
        webView.addJavascriptInterface(new Bridge(), "fsp");
        webView.setWebChromeClient(new WebChromeClient() {
            @Override
            public boolean onShowFileChooser(WebView view, ValueCallback<Uri[]> callback,
                                             FileChooserParams params) {
                if (fileCallback != null) fileCallback.onReceiveValue(null);
                fileCallback = callback;
                Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
                intent.addCategory(Intent.CATEGORY_OPENABLE);
                intent.setType("*/*");
                try {
                    startActivityForResult(Intent.createChooser(intent, "Select file"), 501);
                } catch (Throwable t) {
                    fileCallback = null;
                    return false;
                }
                return true;
            }
        });
        webView.loadUrl("file:///android_asset/index.html");
        setContentView(webView);

        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    JSONObject result = new JSONObject(installHook());
                    if (!result.optBoolean("ok", false)) {
                        // silent: the dashboard shows the hook state
                    }
                } catch (Throwable ignored) {
                }
            }
        }).start();
    }

    private ValueCallback<Uri[]> getFileCallback() {
        return fileCallback;
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == 501 && fileCallback != null) {
            Uri[] result = null;
            if (resultCode == RESULT_OK && data != null && data.getData() != null) {
                result = new Uri[]{data.getData()};
            }
            fileCallback.onReceiveValue(result);
            fileCallback = null;
        }
    }

    // ------------------------------------------------------------------ config

    private String getString(String key) {
        try {
            return Settings.Global.getString(getContentResolver(), key);
        } catch (Throwable t) {
            return null;
        }
    }

    private void putString(String key, String value) {
        Settings.Global.putString(getContentResolver(), key, value);
    }

    private void deleteKey(String key) {
        try {
            Settings.Global.putString(getContentResolver(), key, null);
        } catch (Throwable ignored) {
        }
    }

    private JSONObject readConfig() {
        try {
            String raw = getString(KEY);
            String json = null;
            if (raw != null && !raw.isEmpty()) {
                if (raw.startsWith("{")) {
                    json = raw;
                } else if (raw.startsWith("F1:")) {
                    byte[] decoded = Base64.decode(raw.substring(3), Base64.DEFAULT);
                    json = new String(xor(decoded), StandardCharsets.UTF_8);
                }
            }
            if (json == null) json = migrateLegacy();
            if (json == null) json = DEFAULT_CONFIG;
            return new JSONObject(json);
        } catch (Throwable t) {
            try {
                return new JSONObject(DEFAULT_CONFIG);
            } catch (Throwable ignored) {
                throw new RuntimeException(t);
            }
        }
    }

    private String migrateLegacy() {
        try {
            if (!"1".equals(getString("farewell_enable"))) return null;
            JSONObject config = new JSONObject(DEFAULT_CONFIG);
            config.put("en", 1);
            String flags = getString("farewell_flags");
            if (flags != null) config.put("fl", Integer.parseInt(flags.trim()));
            String mode = getString("farewell_mode");
            if (mode != null) config.put("md", mode);
            String profile = getString("farewell_profile");
            if (profile != null && !profile.isEmpty()) config.put("pf", new JSONObject(profile));
            String targets = getString("farewell_targets");
            if (targets != null && !targets.isEmpty()) config.put("tg", new JSONArray(targets));
            String keybox = getString("farewell_keybox");
            if (keybox != null && !keybox.isEmpty()) config.put("kb", new JSONArray().put(keybox));
            String features = getString("farewell_features");
            if (features != null && !features.isEmpty()) config.put("ft", new JSONObject(features));
            if ("1".equals(getString("farewell_debug"))) config.put("dbg", 1);
            return config.toString();
        } catch (Throwable t) {
            return null;
        }
    }

    private void writeConfig(JSONObject config) {
        try {
            byte[] encoded = xor(config.toString().getBytes(StandardCharsets.UTF_8));
            putString(KEY, "F1:" + Base64.encodeToString(encoded, Base64.NO_WRAP));
            for (String legacy : LEGACY_KEYS) deleteKey(legacy);
        } catch (Throwable t) {
            toast("Save failed: " + t.getMessage());
        }
    }

    private static byte[] xor(byte[] data) {
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            out[i] = (byte) (data[i] ^ XOR_KEY[i % XOR_KEY.length]);
        }
        return out;
    }

    // ------------------------------------------------------------------ bridge

    private final class Bridge {
        @JavascriptInterface
        public String getState() {
            try {
                JSONObject config = readConfig();
                JSONObject state = new JSONObject();
                state.put("config", config);
                state.put("model", android.os.Build.MANUFACTURER + " " + android.os.Build.MODEL);
                state.put("android", android.os.Build.VERSION.RELEASE);
                state.put("sdk", android.os.Build.VERSION.SDK_INT);
                state.put("patch", android.os.Build.VERSION.SECURITY_PATCH);
                state.put("device", android.os.Build.DEVICE);
                JSONArray keyboxes = new JSONArray();
                JSONArray list = config.optJSONArray("kb");
                if (list != null) {
                    for (int i = 0; i < list.length(); i++) {
                        JSONObject info = inspectKeybox(list.optString(i, ""));
                        info.put("index", i);
                        keyboxes.put(info);
                    }
                }
                state.put("keyboxes", keyboxes);
                state.put("hook", hookState());
                return state.toString();
            } catch (Throwable t) {
                return "{\"error\":\"" + escape(t.getMessage()) + "\"}";
            }
        }

        @JavascriptInterface
        public void saveConfig(String json) {
            try {
                JSONObject config = new JSONObject(json);
                sanitize(config);
                writeConfig(config);
                callback("saved", "{\"ok\":true}");
            } catch (Throwable t) {
                callback("saved", "{\"ok\":false,\"error\":\"" + escape(t.getMessage()) + "\"}");
            }
        }

        @JavascriptInterface
        public String listApps() {
            try {
                PackageManager pm = getPackageManager();
                JSONObject config = readConfig();
                List<String> targets = new ArrayList<String>();
                JSONArray array = config.optJSONArray("tg");
                if (array != null) {
                    for (int i = 0; i < array.length(); i++) targets.add(array.optString(i, ""));
                }
                TreeMap<String, JSONObject> sorted = new TreeMap<String, JSONObject>();
                for (ApplicationInfo info : pm.getInstalledApplications(0)) {
                    JSONObject entry = new JSONObject();
                    String label;
                    try {
                        label = String.valueOf(pm.getApplicationLabel(info));
                    } catch (Throwable t) {
                        label = info.packageName;
                    }
                    entry.put("label", label);
                    entry.put("pkg", info.packageName);
                    entry.put("sys", (info.flags & ApplicationInfo.FLAG_SYSTEM) != 0);
                    boolean targeted = false;
                    for (String rule : targets) {
                        String base = rule.contains(":")
                                ? rule.substring(0, rule.indexOf(':')) : rule;
                        if (base.equals(info.packageName)) targeted = true;
                    }
                    entry.put("target", targeted);
                    sorted.put(label.toLowerCase() + " " + info.packageName, entry);
                }
                JSONArray result = new JSONArray();
                for (JSONObject entry : sorted.values()) result.put(entry);
                return result.toString();
            } catch (Throwable t) {
                return "[]";
            }
        }

        @JavascriptInterface
        public String selfTest() {
            return invokeHook("diagnose");
        }

        @JavascriptInterface
        public String getEvents() {
            return invokeHook("getEvents");
        }

        @JavascriptInterface
        public String getDebugState() {
            try {
                JSONObject out = new JSONObject();
                out.put("adb", Settings.Global.getInt(getContentResolver(),
                        Settings.Global.ADB_ENABLED, -1));
                out.put("development", Settings.Global.getInt(getContentResolver(),
                        Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, -1));
                out.put("debug", readConfig().optInt("dbg", 0));
                out.put("hook", hookState());
                File dir = getExternalFilesDir(null);
                out.put("dir", dir != null ? dir.getAbsolutePath()
                        : getFilesDir().getAbsolutePath());
                return out.toString();
            } catch (Throwable t) {
                return "{\"error\":\"" + escape(t.getMessage()) + "\"}";
            }
        }

        @JavascriptInterface
        public String getLogcat(int lines) {
            try {
                ProcessBuilder builder = new ProcessBuilder("logcat", "-d", "-t",
                        String.valueOf(lines), "-v", "time",
                        "-s", "FarewellPIF:V", "AndroidRuntime:E", "*:S");
                builder.redirectErrorStream(true);
                Process process = builder.start();
                byte[] data = readAll(process.getInputStream());
                process.waitFor();
                return new String(data, StandardCharsets.UTF_8);
            } catch (Throwable t) {
                return "logcat failed: " + t;
            }
        }

        @JavascriptInterface
        public String exportDebugBundle() {
            try {
                File dir = getExternalFilesDir(null);
                if (dir == null) dir = getFilesDir();
                if (!dir.exists()) dir.mkdirs();
                String stamp = new java.text.SimpleDateFormat("yyyyMMdd-HHmmss",
                        java.util.Locale.US).format(new java.util.Date());
                File target = new File(dir, "FarewellPIF-debug-" + stamp + ".zip");
                ZipOutputStream zip = new ZipOutputStream(new java.io.FileOutputStream(target));
                try {
                    putZipEntry(zip, "self-test.json", selfTest());
                    putZipEntry(zip, "events.json", getEvents());
                    JSONObject redacted = new JSONObject(readConfig().toString());
                    JSONArray keyboxes = redacted.optJSONArray("kb");
                    if (keyboxes != null) {
                        JSONArray sizes = new JSONArray();
                        for (int i = 0; i < keyboxes.length(); i++) {
                            sizes.put(keyboxes.optString(i, "").length());
                        }
                        redacted.put("kb", sizes);
                    }
                    putZipEntry(zip, "config-redacted.json", redacted.toString(2));
                    putZipEntry(zip, "debug-state.json", getDebugState());
                    putZipEntry(zip, "device.txt", deviceText());
                    putZipEntry(zip, "logcat.txt", getLogcat(3000));
                } finally {
                    zip.close();
                }
                return target.getAbsolutePath();
            } catch (Throwable t) {
                return "export failed: " + t;
            }
        }

        @JavascriptInterface
        public String checkRomSignature() {
            try {
                JSONObject out = new JSONObject();
                JSONArray names = new JSONArray();
                boolean testkey = false;
                ZipFile zip = new ZipFile("/system/etc/security/otacerts.zip");
                java.util.Enumeration<? extends ZipEntry> entries = zip.entries();
                while (entries.hasMoreElements()) {
                    String name = entries.nextElement().getName();
                    names.put(name);
                    if (name.toLowerCase().contains("testkey")) testkey = true;
                }
                zip.close();
                out.put("testkey", testkey);
                out.put("names", names);
                return out.toString();
            } catch (Throwable t) {
                return "{\"error\":\"" + escape(t.getMessage()) + "\"}";
            }
        }

        @JavascriptInterface
        public String installHookNow() {
            return installHook();
        }

        @JavascriptInterface
        public void runTask(String task, String arg) {
            final String name = task == null ? "" : task;
            final String value = arg == null ? "" : arg;
            new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        handleTask(name, value);
                    } catch (Throwable t) {
                        callback(name, "{\"ok\":false,\"error\":\"" + escape(t.getMessage()) + "\"}");
                    }
                }
            }).start();
        }

        @JavascriptInterface
        public void toast(String message) {
            MainActivity.this.toast(message);
        }
    }

    // ------------------------------------------------------------------ tasks

    private void handleTask(String task, String arg) {
        if ("quick_fix".equals(task)) {
            quickFix();
        } else if ("default_profile".equals(task)) {
            loadDefaultProfileTask();
        } else if ("update_patch".equals(task)) {
            updatePatch();
        } else if ("validate_keybox".equals(task)) {
            validateKeyboxes();
        } else if ("kill_gms".equals(task)) {
            killGms("clear".equals(arg));
            callback(task, "{\"ok\":true}");
        } else if ("set_adb".equals(task)) {
            setAdbDisabled("1".equals(arg));
            callback(task, "{\"ok\":true}");
        } else if ("photos".equals(task)) {
            applyPhotosPreset(!"off".equals(arg));
        } else if ("import_keybox".equals(task)) {
            importKeybox(arg);
        } else if ("install_hook".equals(task)) {
            callback(task, installHook());
        }
    }

    /** Offline one-button flow: enable, defaults, bundled profile, validate keybox, hook. */
    private void quickFix() {
        try {
            JSONObject config = readConfig();
            boolean changed = false;

            JSONObject profile = config.optJSONObject("pf");
            if (profile == null || profile.optString("FINGERPRINT", "").isEmpty()) {
                JSONObject bundled = loadDefaultProfile();
                if (bundled != null) {
                    config.put("pf", bundled);
                    changed = true;
                }
            }

            boolean keyboxOk = false;
            JSONArray list = config.optJSONArray("kb");
            if (list != null) {
                for (int i = 0; i < list.length(); i++) {
                    JSONObject info = inspectKeybox(list.optString(i, ""));
                    if (info.optBoolean("valid", false)) {
                        keyboxOk = true;
                        break;
                    }
                }
            }

            if (config.optInt("en", 0) != 1) {
                config.put("en", 1);
                changed = true;
            }
            if (config.optInt("fl", 0) == 0) {
                config.put("fl", 3);
                changed = true;
            }
            if (changed) writeConfig(config);

            JSONObject hook = new JSONObject(installHook());
            killGms(false);

            JSONObject out = new JSONObject();
            out.put("ok", keyboxOk);
            out.put("keybox", keyboxOk);
            out.put("hook", hook.optBoolean("ok", false));
            if (!keyboxOk) out.put("error", "no valid keybox, import keybox.xml first");
            callback("quick_fix", out.toString());
        } catch (Throwable t) {
            callback("quick_fix", "{\"ok\":false,\"error\":\"" + escape(t.getMessage()) + "\"}");
        }
    }

    private void loadDefaultProfileTask() {
        try {
            JSONObject profile = loadDefaultProfile();
            if (profile == null) {
                callback("default_profile", "{\"ok\":false,\"error\":\"default profile asset missing\"}");
                return;
            }
            JSONObject config = readConfig();
            config.put("pf", profile);
            writeConfig(config);
            callback("default_profile", "{\"ok\":true,\"profile\":" + profile + "}");
        } catch (Throwable t) {
            callback("default_profile", "{\"ok\":false,\"error\":\"" + escape(t.getMessage()) + "\"}");
        }
    }

    private JSONObject loadDefaultProfile() {
        try {
            InputStream input = getAssets().open("default-profile.json");
            String text = new String(readAll(input), StandardCharsets.UTF_8);
            return new JSONObject(text);
        } catch (Throwable t) {
            return null;
        }
    }

    private void updatePatch() {
        try {
            JSONObject config = readConfig();
            String patch = derivePatch(config.optJSONObject("pf"));
            JSONObject out = new JSONObject();
            out.put("ok", true);
            out.put("patch", patch);
            callback("update_patch", out.toString());
        } catch (Throwable t) {
            callback("update_patch", "{\"ok\":false,\"error\":\"" + escape(t.getMessage()) + "\"}");
        }
    }

    private String derivePatch(JSONObject profile) {
        String candidate = null;
        try {
            String fingerprint = profile != null ? profile.optString("FINGERPRINT", "") : "";
            java.util.regex.Matcher matcher = java.util.regex.Pattern
                    .compile("\\.(\\d{2})(\\d{2})(\\d{2})\\.").matcher(fingerprint);
            if (matcher.find()) {
                candidate = "20" + matcher.group(1) + "-" + matcher.group(2) + "-05";
            }
        } catch (Throwable ignored) {
        }
        if (candidate == null || isFuture(candidate)) {
            java.util.Calendar calendar = java.util.Calendar.getInstance();
            for (int i = 0; i < 12; i++) {
                candidate = String.format(java.util.Locale.US, "%04d-%02d-05",
                        calendar.get(java.util.Calendar.YEAR),
                        calendar.get(java.util.Calendar.MONTH) + 1);
                if (!isFuture(candidate)) break;
                calendar.add(java.util.Calendar.MONTH, -1);
            }
        }
        String devicePatch = android.os.Build.VERSION.SECURITY_PATCH;
        if (devicePatch != null && candidate != null && candidate.compareTo(devicePatch) < 0) {
            candidate = devicePatch;
        }
        return candidate;
    }

    private boolean isFuture(String patch) {
        try {
            java.text.SimpleDateFormat format =
                    new java.text.SimpleDateFormat("yyyy-MM-dd", java.util.Locale.US);
            format.setLenient(false);
            return format.parse(patch).after(new java.util.Date());
        } catch (Throwable t) {
            return false;
        }
    }

    private void applyPhotosPreset(boolean enable) {
        try {
            JSONObject config = readConfig();
            String photos = "com.google.android.apps.photos";
            JSONArray targets = config.optJSONArray("tg");
            if (targets == null) targets = new JSONArray();
            JSONObject apps = config.optJSONObject("ap");
            if (apps == null) apps = new JSONObject();

            if (enable) {
                JSONObject global = config.optJSONObject("pf");
                if (global == null || global.optString("FINGERPRINT", "").isEmpty()) {
                    global = loadDefaultProfile();
                    if (global != null) config.put("pf", global);
                }
                JSONObject entry = apps.optJSONObject(photos);
                if (entry == null) entry = new JSONObject();
                if (global != null) entry.put("pf", new JSONObject(global.toString()));
                JSONObject features = entry.optJSONObject("ft");
                if (features == null) features = new JSONObject();
                String[] grants = {
                        "com.google.android.apps.photos.PIXEL_2017",
                        "com.google.android.apps.photos.PIXEL_2018",
                        "com.google.android.apps.photos.PIXEL_2019",
                        "com.google.android.apps.photos.PIXEL_2019_MIDYEAR_PRELOAD",
                        "photos.nexus_preload", "PIXEL_EXPERIENCE",
                        "GOOGLE_BUILD", "GOOGLE_EXPERIENCE"
                };
                for (String grant : grants) features.put(grant, true);
                entry.put("ft", features);
                apps.put(photos, entry);
                config.put("ap", apps);

                boolean present = false;
                for (int i = 0; i < targets.length(); i++) {
                    if (photos.equals(targets.optString(i, ""))) present = true;
                }
                if (!present) targets.put(photos);
                config.put("tg", targets);
                writeConfig(config);
                callback("photos", "{\"ok\":true,\"enabled\":true}");
            } else {
                apps.remove(photos);
                config.put("ap", apps);
                JSONArray updated = new JSONArray();
                for (int i = 0; i < targets.length(); i++) {
                    String target = targets.optString(i, "");
                    if (!photos.equals(target)) updated.put(target);
                }
                config.put("tg", updated);
                writeConfig(config);
                callback("photos", "{\"ok\":true,\"enabled\":false}");
            }
        } catch (Throwable t) {
            callback("photos", "{\"ok\":false,\"error\":\"" + escape(t.getMessage()) + "\"}");
        }
    }

    private void importKeybox(String base64Xml) {
        try {
            if (base64Xml == null || base64Xml.isEmpty()) throw new IllegalArgumentException("empty");
            JSONObject info = inspectKeybox(base64Xml);
            if (!info.optBoolean("valid", false)) {
                callback("import_keybox", "{\"ok\":false,\"error\":\""
                        + escape(info.optString("error", "invalid")) + "\"}");
                return;
            }
            JSONObject config = readConfig();
            JSONArray keyboxes = config.optJSONArray("kb");
            if (keyboxes == null) keyboxes = new JSONArray();
            JSONArray updated = new JSONArray();
            updated.put(base64Xml);
            for (int i = 0; i < keyboxes.length() && i < 3; i++) {
                updated.put(keyboxes.optString(i, ""));
            }
            config.put("kb", dedupe(updated));
            writeConfig(config);
            callback("import_keybox", "{\"ok\":true,\"serial\":\""
                    + escape(info.optString("serial", "")) + "\"}");
        } catch (Throwable t) {
            callback("import_keybox", "{\"ok\":false,\"error\":\"" + escape(t.getMessage()) + "\"}");
        }
    }

    private void validateKeyboxes() {
        try {
            JSONObject config = readConfig();
            JSONArray list = config.optJSONArray("kb");
            JSONArray results = new JSONArray();
            if (list != null) {
                for (int i = 0; i < list.length(); i++) {
                    JSONObject info = inspectKeybox(list.optString(i, ""));
                    info.put("index", i);
                    results.put(info);
                }
            }
            JSONObject out = new JSONObject();
            out.put("ok", true);
            out.put("keyboxes", results);
            callback("validate_keybox", out.toString());
        } catch (Throwable t) {
            callback("validate_keybox", "{\"ok\":false,\"error\":\"" + escape(t.getMessage()) + "\"}");
        }
    }

    // ------------------------------------------------------------- hook install

    private JSONObject hookState() {
        try {
            JSONObject out = new JSONObject();
            String meta = getString(HOOK_META);
            out.put("meta", meta != null ? meta : "");
            out.put("installed", meta != null && !meta.isEmpty());
            out.put("assetSha", assetHookSha());
            out.put("upToDate", meta != null && meta.startsWith(assetHookSha()));
            return out;
        } catch (Throwable t) {
            try {
                return new JSONObject().put("error", String.valueOf(t));
            } catch (Throwable ignored) {
                return new JSONObject();
            }
        }
    }

    private String assetHookSha() {
        try {
            byte[] dex = readAll(getAssets().open("hook.dex"));
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(dex);
            StringBuilder builder = new StringBuilder();
            for (byte value : hash) builder.append(String.format("%02x", value));
            return builder.toString();
        } catch (Throwable t) {
            return "";
        }
    }

    /** Writes the bundled hook dex into Settings.Global for the bootstrap to hot-load. */
    private String installHook() {
        try {
            byte[] dex = readAll(getAssets().open("hook.dex"));
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(dex);
            StringBuilder sha = new StringBuilder();
            for (byte value : hash) sha.append(String.format("%02x", value));
            String shaHex = sha.toString();

            int chunks = (dex.length + HOOK_CHUNK_SIZE - 1) / HOOK_CHUNK_SIZE;
            if (chunks > HOOK_MAX_CHUNKS) {
                return "{\"ok\":false,\"error\":\"hook dex too large\"}";
            }
            for (int i = 0; i < chunks; i++) {
                int from = i * HOOK_CHUNK_SIZE;
                int to = Math.min(dex.length, from + HOOK_CHUNK_SIZE);
                byte[] part = java.util.Arrays.copyOfRange(dex, from, to);
                putString(HOOK_CHUNK + i, Base64.encodeToString(xor(part), Base64.NO_WRAP));
            }
            for (int i = chunks; i < HOOK_MAX_CHUNKS; i++) {
                deleteKey(HOOK_CHUNK + i);
            }
            String version = "1";
            try {
                version = getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
            } catch (Throwable ignored) {
            }
            putString(HOOK_META, shaHex + ":" + chunks + ":" + version);
            killGms(false);

            JSONObject out = new JSONObject();
            out.put("ok", true);
            out.put("sha", shaHex);
            out.put("chunks", chunks);
            out.put("version", version);
            out.put("size", dex.length);
            return out.toString();
        } catch (Throwable t) {
            return "{\"ok\":false,\"error\":\"" + escape(t.getMessage()) + "\"}";
        }
    }

    // ------------------------------------------------------------------ helpers

    private static JSONArray dedupe(JSONArray array) throws Exception {
        JSONArray out = new JSONArray();
        List<String> seen = new ArrayList<String>();
        for (int i = 0; i < array.length(); i++) {
            String value = array.optString(i, "");
            if (value.isEmpty() || seen.contains(value)) continue;
            seen.add(value);
            out.put(value);
        }
        return out;
    }

    private void killGms(boolean clearPlayStore) {
        String[] packages = {
                "com.google.android.gms", "com.google.android.gms.unstable",
                "com.android.vending", "com.google.android.gsf",
                "com.google.android.apps.gcs", "com.google.android.gms.location.history"
        };
        for (String pkg : packages) forceStop(pkg);
        if (clearPlayStore) {
            try {
                ActivityManager manager = (ActivityManager) getSystemService(ACTIVITY_SERVICE);
                manager.killBackgroundProcesses("com.android.vending");
            } catch (Throwable ignored) {
            }
        }
    }

    private void setAdbDisabled(boolean disabled) {
        try {
            Settings.Global.putInt(getContentResolver(),
                    Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, disabled ? 0 : 1);
            Settings.Global.putInt(getContentResolver(),
                    Settings.Global.ADB_ENABLED, disabled ? 0 : 1);
        } catch (Throwable t) {
            toast("ADB toggle failed: " + t.getMessage());
        }
    }

    private void forceStop(String pkg) {
        try {
            ActivityManager manager = (ActivityManager) getSystemService(ACTIVITY_SERVICE);
            Method method = ActivityManager.class.getMethod("forceStopPackage", String.class);
            method.invoke(manager, pkg);
        } catch (Throwable ignored) {
        }
    }

    private void callback(String event, String json) {
        try {
            final String script = "window.__cb(" + JSONObject.quote(event) + ","
                    + JSONObject.quote(json) + ")";
            handler.post(new Runnable() {
                @Override
                public void run() {
                    try {
                        webView.evaluateJavascript(script, null);
                    } catch (Throwable ignored) {
                    }
                }
            });
        } catch (Throwable ignored) {
        }
    }

    private String invokeHook(String method) {
        try {
            Class<?> hook = Class.forName("dev.farewell.pif.FarewellHook");
            Object result = hook.getMethod(method).invoke(null);
            return result != null ? result.toString() : "[]";
        } catch (Throwable t) {
            return "[]";
        }
    }

    private static byte[] readAll(InputStream input) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = input.read(buffer)) > 0) output.write(buffer, 0, read);
        input.close();
        return output.toByteArray();
    }

    private JSONObject inspectKeybox(String base64Xml) {
        JSONObject result = new JSONObject();
        try {
            if (base64Xml == null || base64Xml.isEmpty()) {
                result.put("valid", false);
                result.put("error", "empty");
                return result;
            }
            byte[] xml = Base64.decode(base64Xml, Base64.DEFAULT);
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(false);
            try {
                factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            } catch (Throwable ignored) {
            }
            try {
                factory.setFeature("http://xml.org/sax/features/external-general-entities",
                        false);
            } catch (Throwable ignored) {
            }
            Document document = factory.newDocumentBuilder()
                    .parse(new java.io.ByteArrayInputStream(xml));
            NodeList certs = document.getElementsByTagName("Certificate");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            List<X509Certificate> chain = new ArrayList<X509Certificate>();
            for (int i = 0; i < certs.getLength() && chain.size() < 8; i++) {
                try {
                    chain.add((X509Certificate) cf.generateCertificate(
                            new java.io.ByteArrayInputStream(
                                    certs.item(i).getTextContent()
                                            .getBytes(StandardCharsets.UTF_8))));
                } catch (Throwable ignored) {
                }
            }
            if (chain.isEmpty()) {
                result.put("valid", false);
                result.put("error", "no certificates");
                return result;
            }
            result.put("serial", chain.get(0).getSerialNumber().toString(16));
            result.put("subject", chain.get(0).getSubjectX500Principal().getName());
            if (chain.size() < 2) {
                result.put("valid", false);
                result.put("error", "chain has one certificate");
                return result;
            }
            chain.get(0).checkValidity();
            chain.get(0).verify(chain.get(1).getPublicKey());
            result.put("valid", true);
            result.put("error", "");
        } catch (Throwable t) {
            try {
                result.put("valid", false);
                result.put("error", String.valueOf(t.getMessage()));
            } catch (Throwable ignored) {
            }
        }
        return result;
    }

    private static void sanitize(JSONObject config) throws Exception {
        JSONObject profile = config.optJSONObject("pf");
        if (profile != null && profile.toString().length() > 65536) {
            throw new IllegalArgumentException("profile too large");
        }
        JSONArray keyboxes = config.optJSONArray("kb");
        if (keyboxes != null) {
            if (keyboxes.length() > 5) throw new IllegalArgumentException("too many keyboxes");
            for (int i = 0; i < keyboxes.length(); i++) {
                if (keyboxes.optString(i, "").length() > 512 * 1024) {
                    throw new IllegalArgumentException("keybox too large");
                }
            }
        }
        config.put("v", 1);
    }

    private static void putZipEntry(ZipOutputStream zip, String name, String text)
            throws Exception {
        zip.putNextEntry(new ZipEntry(name));
        zip.write((text == null ? "" : text).getBytes(StandardCharsets.UTF_8));
        zip.closeEntry();
    }

    private String deviceText() {
        StringBuilder builder = new StringBuilder();
        builder.append("manufacturer=").append(android.os.Build.MANUFACTURER).append('\n');
        builder.append("brand=").append(android.os.Build.BRAND).append('\n');
        builder.append("model=").append(android.os.Build.MODEL).append('\n');
        builder.append("device=").append(android.os.Build.DEVICE).append('\n');
        builder.append("fingerprint=").append(android.os.Build.FINGERPRINT).append('\n');
        builder.append("android=").append(android.os.Build.VERSION.RELEASE)
                .append(" sdk=").append(android.os.Build.VERSION.SDK_INT).append('\n');
        builder.append("security_patch=").append(android.os.Build.VERSION.SECURITY_PATCH)
                .append('\n');
        builder.append("adb_enabled=").append(Settings.Global.getInt(getContentResolver(),
                Settings.Global.ADB_ENABLED, -1)).append('\n');
        builder.append("development_settings=").append(Settings.Global.getInt(
                getContentResolver(), Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, -1))
                .append('\n');
        return builder.toString();
    }

    private static String escape(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", " ").replace("\r", " ");
    }

    private void toast(final String message) {
        handler.post(new Runnable() {
            @Override
            public void run() {
                Toast.makeText(MainActivity.this, message, Toast.LENGTH_SHORT).show();
            }
        });
    }
}

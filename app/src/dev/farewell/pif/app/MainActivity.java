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
    private static final String HOOK_GATE = "sys_perf_dex_pkgs";
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
                    // Only load the hook in every process when the feature is actually enabled.
                    if (readConfig().optInt("en", 0) == 1) {
                        installHook();
                    }
                } catch (Throwable ignored) {
                }
            }
        }).start();
        handleIntentOps(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleIntentOps(intent);
    }

    /**
     * Provisioning entry point for ADB on ROMs whose shell lacks WRITE_SECURE_SETTINGS (MIUI):
     *   adb shell am start -n dev.farewell.pif/.app.MainActivity --es op remove_hook
     *   adb shell am start -n dev.farewell.pif/.app.MainActivity --es op set_config --es json '{...}'
     */
    private void handleIntentOps(final Intent intent) {
        if (intent == null) return;
        final String op = intent.getStringExtra("op");
        if (op == null || op.isEmpty()) return;
        new Thread(new Runnable() {
            @Override
            public void run() {
                String result;
                try {
                    result = runOp(op, intent);
                } catch (Throwable t) {
                    result = "error: " + t;
                }
                android.util.Log.i("FarewellPIF", "op " + op + " -> " + result);
                handler.post(new Runnable() {
                    @Override
                    public void run() {
                        toast("op done: see logcat");
                        finish();
                    }
                });
            }
        }).start();
    }

    /** ",android,self,<target packages>," allowlist for the bootstrap (non-targets skip the dex). */
    private String gateValue(JSONObject config) {
        return HookStore.gateValue(this, config);
    }

    /** Replicates the bootstrap dex load to pinpoint failures over ADB (no repack needed). */
    private String dexProbe() {
        JSONObject out = new JSONObject();
        try {
            String meta = getString(HOOK_META);
            out.put("meta", meta);
            if (meta == null || meta.isEmpty()) {
                out.put("error", "no meta");
                return out.toString();
            }
            String[] parts = meta.split(":");
            int chunks = Integer.parseInt(parts[1]);
            out.put("chunks", chunks);
            java.io.ByteArrayOutputStream buffer = new java.io.ByteArrayOutputStream();
            for (int i = 0; i < chunks; i++) {
                String encoded = getString(HOOK_CHUNK + i);
                if (encoded == null || encoded.isEmpty()) {
                    out.put("error", "chunk " + i + " missing");
                    return out.toString();
                }
                buffer.write(xor(Base64.decode(encoded, Base64.DEFAULT)));
            }
            byte[] dex = buffer.toByteArray();
            out.put("bytes", dex.length);
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(dex);
            StringBuilder hex = new StringBuilder();
            for (byte value : hash) hex.append(String.format("%02x", value));
            out.put("shaMatch", hex.toString().equalsIgnoreCase(parts[0]));
            ClassLoader loader = new dalvik.system.InMemoryDexClassLoader(
                    java.nio.ByteBuffer.wrap(dex), getClassLoader());
            Class<?> impl = Class.forName("dev.farewell.pif.HookImpl", true, loader);
            out.put("impl", impl.getName());
        } catch (Throwable t) {
            try {
                out.put("exception", t.toString());
            } catch (Throwable ignored) {
            }
        }
        return out.toString();
    }

    /** Reflects into the on-device bootstrap to expose why the impl did not load. */
    private String hookProbe() {
        JSONObject out = new JSONObject();
        try {
            Class<?> hook = Class.forName("dev.farewell.pif.FarewellHook");
            java.lang.reflect.Field implField = hook.getDeclaredField("sImplClass");
            implField.setAccessible(true);
            java.lang.reflect.Field failedField = hook.getDeclaredField("sLoadFailed");
            failedField.setAccessible(true);
            java.lang.reflect.Field metaField = hook.getDeclaredField("sLoadedMeta");
            metaField.setAccessible(true);
            out.put("sImplClass", String.valueOf(implField.get(null)));
            out.put("sLoadFailed", String.valueOf(failedField.get(null)));
            out.put("sLoadedMeta", String.valueOf(metaField.get(null)));
            java.lang.reflect.Method read = hook.getDeclaredMethod("readSetting", String.class);
            read.setAccessible(true);
            Object meta = read.invoke(null, HOOK_META);
            out.put("bootstrapMetaLen", meta == null ? -1 : meta.toString().length());
            Object chunk0 = read.invoke(null, HOOK_CHUNK + 0);
            out.put("bootstrapChunk0Len", chunk0 == null ? -1 : chunk0.toString().length());
            java.lang.reflect.Method ctxMethod = hook.getDeclaredMethod("context");
            ctxMethod.setAccessible(true);
            Object context = ctxMethod.invoke(null);
            out.put("context", context == null ? "null" : context.getClass().getName());
            if (context instanceof android.content.Context) {
                android.content.Context ctx = (android.content.Context) context;
                out.put("ctxPackage", ctx.getPackageName());
                out.put("ctxOpPackage", ctx.getOpPackageName());
                try {
                    Object user = ctx.getClass().getMethod("getUserId").invoke(ctx);
                    out.put("ctxUserId", String.valueOf(user));
                } catch (Throwable t) {
                    out.put("ctxUserId", "error:" + t);
                }
                try {
                    String direct = android.provider.Settings.Global.getString(
                            ctx.getContentResolver(), HOOK_META);
                    out.put("directReadLen", direct == null ? -1 : direct.length());
                } catch (Throwable t) {
                    out.put("directReadError", t.toString());
                }
                try {
                    String viaApp = android.provider.Settings.Global.getString(
                            getContentResolver(), HOOK_META);
                    out.put("activityReadLen", viaApp == null ? -1 : viaApp.length());
                } catch (Throwable t) {
                    out.put("activityReadError", t.toString());
                }
            }
            java.lang.reflect.Method refresh = hook.getDeclaredMethod("refresh");
            refresh.setAccessible(true);
            refresh.invoke(null);
            out.put("afterRefresh", String.valueOf(implField.get(null)));
            out.put("failedAfter", String.valueOf(failedField.get(null)));
            try {
                java.lang.reflect.Method stateMethod = hook.getMethod("state");
                out.put("bootstrapState", String.valueOf(stateMethod.invoke(null)));
            } catch (Throwable t) {
                out.put("bootstrapState", "unavailable (old bootstrap)");
            }
        } catch (Throwable t) {
            try {
                out.put("error", t.toString());
            } catch (Throwable ignored) {
            }
        }
        return out.toString();
    }

    private static String joinChunks(Intent intent, String prefix) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < 32; i++) {
            String part = intent.getStringExtra(prefix + i);
            if (part == null) break;
            builder.append(part);
        }
        return builder.length() == 0 ? null : builder.toString();
    }

    /**
     * Reflective refresh + invoke with retries. A freshly started process can be transiently
     * denied by the bootstrap gate (package name not bound yet), and the decision is cached per
     * process for a few seconds; retrying makes self-test/verify deterministic.
     */
    private String invokeHookLoaded(String method) {
        String result = null;
        for (int attempt = 0; attempt < 4; attempt++) {
            try {
                Class<?> hook = Class.forName("dev.farewell.pif.FarewellHook");
                hook.getMethod("refresh").invoke(null);
            } catch (Throwable ignored) {
            }
            result = invokeHook(method);
            boolean fallback = result == null || result.isEmpty() || result.equals("[]")
                    || result.contains("\"bootstrap\":true")
                    || result.contains("\"impl\":false");
            if (!fallback) return result;
            try {
                Thread.sleep(6000);
            } catch (InterruptedException ignored) {
                break;
            }
        }
        return result;
    }

    private String runOp(String op, Intent intent) throws Exception {
        if ("remove_hook".equals(op)) {
            removeHook();
            return "hook removed";
        }
        if ("install_hook".equals(op)) {
            if (readConfig().optInt("en", 0) != 1) return "refused: config disabled";
            return installHook();
        }
        if ("set_config".equals(op)) {
            String json = intent.getStringExtra("json");
            if (json == null || json.isEmpty()) json = joinChunks(intent, "cfg_");
            if (json == null || json.isEmpty()) return "missing json";
            JSONObject config = new JSONObject(json);
            sanitize(config);
            writeConfig(config);
            return "config written";
        }
        if ("set_keybox".equals(op)) {
            String base64 = intent.getStringExtra("b64xml");
            if (base64 == null || base64.isEmpty()) base64 = joinChunks(intent, "kb_");
            if (base64 == null || base64.isEmpty()) return "missing b64xml";
            JSONObject info = inspectKeybox(base64);
            if (!info.optBoolean("valid", false)) return "invalid keybox";
            JSONObject config = readConfig();
            JSONArray keyboxes = new JSONArray();
            keyboxes.put(base64);
            JSONArray existing = config.optJSONArray("kb");
            if (existing != null) {
                for (int i = 0; i < existing.length() && i < 3; i++) {
                    keyboxes.put(existing.optString(i, ""));
                }
            }
            config.put("kb", dedupe(keyboxes));
            writeConfig(config);
            return "keybox installed";
        }
        if ("kill_gms".equals(op)) {
            killGms(false);
            return "gms restarted";
        }
        if ("selftest".equals(op)) {
            return invokeHookLoaded("diagnose");
        }
        if ("verify".equals(op)) {
            return invokeHookLoaded("selfTest");
        }
        if ("dexprobe".equals(op)) {
            return dexProbe();
        }
        if ("hookprobe".equals(op)) {
            return hookProbe();
        }
        return "unknown op";
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
        return HookStore.getString(this, key);
    }

    private void putString(String key, String value) {
        HookStore.putString(this, key, value);
    }

    private void deleteKey(String key) {
        HookStore.deleteKey(this, key);
    }

    private JSONObject readConfig() {
        return HookStore.readConfig(this);
    }

    private void writeConfig(JSONObject config) {
        if (!HookStore.writeConfig(this, config)) {
            toast("Save failed");
        }
    }

    private static byte[] xor(byte[] data) {
        return HookStore.xor(data);
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
            return invokeHookLoaded("diagnose");
        }

        @JavascriptInterface
        public String verifyHook() {
            return invokeHookLoaded("selfTest");
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
                    putZipEntry(zip, "hook-live-test.json", verifyHook());
                    putZipEntry(zip, "hook-state.json", hookProbe());
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
        public String removeHookNow() {
            removeHook();
            return "{\"ok\":true}";
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
        } else if ("remove_hook".equals(task)) {
            removeHook();
            callback(task, "{\"ok\":true}");
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

    /** Removes the hot-loaded hook so no process pays the dex load cost while disabled. */
    private void removeHook() {
        HookStore.removeHook(this);
        killGms(false);
    }

    /** Writes the bundled hook dex; restarts GMS only when the channel actually changed. */
    private String installHook() {
        String result = HookStore.installHook(this);
        try {
            JSONObject json = new JSONObject(result);
            if (json.optBoolean("ok", false) && !json.optBoolean("cached", false)) {
                killGms(false);
            }
        } catch (Throwable ignored) {
            killGms(false);
        }
        return result;
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

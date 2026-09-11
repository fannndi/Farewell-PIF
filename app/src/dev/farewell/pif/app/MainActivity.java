package dev.farewell.pif.app;

import android.app.Activity;
import android.app.ActivityManager;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.Calendar;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Farewell-PIF controller (manual/offline).
 *
 * No network calls: keybox and profile are loaded from files bundled in the APK or picked by
 * the user. The framework hook dex is installed into Settings.Global and hot-loaded by the
 * bootstrap in framework.jar, so hook updates no longer require a ROM repack.
 *
 * This class owns the WebView lifecycle, ADB ops and config tasks; the modules live in
 * Bridge (JS interface), Keyboxes (keybox parsing) and Diag (probes/logcat/bundle).
 */
public class MainActivity extends Activity {
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
        webView.addJavascriptInterface(new Bridge(this), "fsp");
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

    private static String joinChunks(Intent intent, String prefix) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < 32; i++) {
            String part = intent.getStringExtra(prefix + i);
            if (part == null) break;
            builder.append(part);
        }
        return builder.length() == 0 ? null : builder.toString();
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
            try {
                String serial = Keyboxes.importKeybox(this, base64);
                return "keybox installed serial=" + serial;
            } catch (Throwable t) {
                return "invalid keybox: " + t.getMessage();
            }
        }
        if ("kill_gms".equals(op)) {
            killGms(false);
            return "gms restarted";
        }
        if ("selftest".equals(op)) {
            return Diag.invokeHookLoaded("diagnose");
        }
        if ("verify".equals(op)) {
            return Diag.invokeHookLoaded("selfTest");
        }
        if ("dexprobe".equals(op)) {
            return Diag.dexProbe(this);
        }
        if ("hookprobe".equals(op)) {
            return Diag.hookProbe(this);
        }
        if ("nativeprobe".equals(op)) {
            return Diag.nativeProbeTest(this);
        }
        return "unknown op";
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

    JSONObject readConfig() {
        return HookStore.readConfig(this);
    }

    void writeConfig(JSONObject config) {
        if (!HookStore.writeConfig(this, config)) {
            toast("Save failed");
        }
    }

    // ------------------------------------------------------------------ tasks

    void handleTask(String task, String arg) {
        if ("quick_fix".equals(task)) {
            quickFix();
        } else if ("default_profile".equals(task)) {
            loadDefaultProfileTask();
        } else if ("update_patch".equals(task)) {
            updatePatch();
        } else if ("audit".equals(task)) {
            callback(task, Security.audit(this));
        } else if ("update_profile".equals(task)) {
            String url = arg != null && arg.startsWith("http") ? arg : null;
            callback(task, Updater.updateProfile(this, url));
        } else if ("validate_keybox".equals(task)) {
            callback(task, Keyboxes.validate(this).toString());
        } else if ("kill_gms".equals(task)) {
            killGms("clear".equals(arg));
            callback(task, "{\"ok\":true}");
        } else if ("set_adb".equals(task)) {
            setAdbDisabled("1".equals(arg));
            callback(task, "{\"ok\":true}");
        } else if ("photos".equals(task)) {
            applyPhotosPreset(!"off".equals(arg));
        } else if ("import_keybox".equals(task)) {
            try {
                String serial = Keyboxes.importKeybox(this, arg);
                callback(task, "{\"ok\":true,\"serial\":\"" + escape(serial) + "\"}");
            } catch (Throwable t) {
                callback(task, "{\"ok\":false,\"error\":\""
                        + escape(t.getMessage()) + "\"}");
            }
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
            boolean keyboxStale = false;
            JSONArray list = config.optJSONArray("kb");
            if (list != null) {
                for (int i = 0; i < list.length(); i++) {
                    JSONObject info = Keyboxes.inspect(list.optString(i, ""));
                    if (info.optBoolean("valid", false)) {
                        if (info.optBoolean("anchored", false)) {
                            keyboxOk = true;
                            break;
                        }
                        keyboxStale = true;
                    }
                }
            }

            int flags = config.optInt("fl", 0) | 1;
            if (keyboxOk) {
                flags |= 2;
            } else {
                flags &= ~2;
            }
            if (flags != config.optInt("fl", 0)) {
                config.put("fl", flags);
                changed = true;
            }

            if (config.optInt("en", 0) != 1) {
                config.put("en", 1);
                changed = true;
            }
            if (changed) writeConfig(config);

            JSONObject hook = new JSONObject(installHook());
            killGms(false);

            JSONObject out = new JSONObject();
            out.put("ok", true);
            out.put("keybox", keyboxOk);
            out.put("hook", hook.optBoolean("ok", false));
            if (!keyboxOk) out.put("mode", "pif-profile");
            if (keyboxStale && !keyboxOk) {
                out.put("keyboxWarning",
                        "keybox root is retired/unknown - STRONG cannot pass; PIF profile mode kept");
            }
            callback("quick_fix", out.toString());
        } catch (Throwable t) {
            callback("quick_fix", "{\"ok\":false,\"error\":\"" + escape(t.getMessage()) + "\"}");
        }
    }

    private void loadDefaultProfileTask() {
        try {
            JSONObject profile = loadDefaultProfile();
            if (profile == null) {
                callback("default_profile",
                        "{\"ok\":false,\"error\":\"default profile asset missing\"}");
                return;
            }
            JSONObject config = readConfig();
            config.put("pf", profile);
            writeConfig(config);
            callback("default_profile", "{\"ok\":true,\"profile\":" + profile + "}");
        } catch (Throwable t) {
            callback("default_profile",
                    "{\"ok\":false,\"error\":\"" + escape(t.getMessage()) + "\"}");
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
            Matcher matcher = Pattern
                    .compile("\\.(\\d{2})(\\d{2})(\\d{2})\\.").matcher(fingerprint);
            if (matcher.find()) {
                candidate = "20" + matcher.group(1) + "-" + matcher.group(2) + "-05";
            }
        } catch (Throwable ignored) {
        }
        if (candidate == null || isFuture(candidate)) {
            Calendar calendar = Calendar.getInstance();
            for (int i = 0; i < 12; i++) {
                candidate = String.format(Locale.US, "%04d-%02d-05",
                        calendar.get(Calendar.YEAR),
                        calendar.get(Calendar.MONTH) + 1);
                if (!isFuture(candidate)) break;
                calendar.add(Calendar.MONTH, -1);
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
                    new java.text.SimpleDateFormat("yyyy-MM-dd", Locale.US);
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

    // ------------------------------------------------------------- hook install

    /** Removes the hot-loaded hook so no process pays the dex load cost while disabled. */
    void removeHook() {
        HookStore.removeHook(this);
        killGms(false);
    }

    /** Writes the bundled hook dex; restarts GMS only when the channel actually changed. */
    String installHook() {
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

    void callback(String event, String json) {
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

    void toast(final String message) {
        handler.post(new Runnable() {
            @Override
            public void run() {
                Toast.makeText(MainActivity.this, message, Toast.LENGTH_SHORT).show();
            }
        });
    }

    static void sanitize(JSONObject config) throws Exception {
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

    static String escape(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", " ").replace("\r", " ");
    }

    static byte[] readAll(InputStream input) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = input.read(buffer)) > 0) output.write(buffer, 0, read);
        input.close();
        return output.toByteArray();
    }
}

package dev.farewell.pif.app;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.webkit.JavascriptInterface;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.TreeMap;

/** WebView bridge (the {@code fsp} JavaScript interface). Thin layer over the app modules. */
final class Bridge {
    private final MainActivity activity;

    Bridge(MainActivity activity) {
        this.activity = activity;
    }

    @JavascriptInterface
    public String getState() {
        try {
            JSONObject config = activity.readConfig();
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
                    JSONObject info = Keyboxes.inspect(list.optString(i, ""));
                    info.put("index", i);
                    keyboxes.put(info);
                }
            }
            state.put("keyboxes", keyboxes);
            state.put("hook", Diag.hookState(activity));
            return state.toString();
        } catch (Throwable t) {
            return "{\"error\":\"" + MainActivity.escape(t.getMessage()) + "\"}";
        }
    }

    @JavascriptInterface
    public void saveConfig(String json) {
        try {
            JSONObject config = new JSONObject(json);
            MainActivity.sanitize(config);
            activity.writeConfig(config);
            activity.callback("saved", "{\"ok\":true}");
        } catch (Throwable t) {
            activity.callback("saved",
                    "{\"ok\":false,\"error\":\"" + MainActivity.escape(t.getMessage()) + "\"}");
        }
    }

    @JavascriptInterface
    public String listApps() {
        try {
            PackageManager pm = activity.getPackageManager();
            JSONObject config = activity.readConfig();
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
        return Diag.invokeHookLoaded("diagnose");
    }

    @JavascriptInterface
    public String verifyHook() {
        return Diag.invokeHookLoaded("selfTest");
    }

    @JavascriptInterface
    public String getEvents() {
        return Diag.invokeHook("getEvents");
    }

    @JavascriptInterface
    public String getDebugState() {
        return Diag.getDebugState(activity);
    }

    @JavascriptInterface
    public String getLogcat(int lines) {
        return Diag.getLogcat(lines);
    }

    @JavascriptInterface
    public String exportDebugBundle() {
        return Diag.exportDebugBundle(activity);
    }

    @JavascriptInterface
    public String checkRomSignature() {
        return Diag.checkRomSignature();
    }

    @JavascriptInterface
    public String installHookNow() {
        return activity.installHook();
    }

    @JavascriptInterface
    public String removeHookNow() {
        activity.removeHook();
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
                    activity.handleTask(name, value);
                } catch (Throwable t) {
                    activity.callback(name,
                            "{\"ok\":false,\"error\":\""
                                    + MainActivity.escape(t.getMessage()) + "\"}");
                }
            }
        }).start();
    }

    @JavascriptInterface
    public void toast(String message) {
        activity.toast(message);
    }
}

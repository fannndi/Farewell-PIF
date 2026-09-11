package dev.farewell.pif.app;

import android.content.Context;
import android.provider.Settings;
import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

/**
 * Diagnostics module: dex/hook/native probes, logcat capture and the debug bundle.
 * Every op here is exposed over ADB (see docs/MODULES.md) and never requires a repack.
 */
final class Diag {
    private Diag() {
    }

    static String invokeHook(String method) {
        try {
            Class<?> hook = Class.forName("dev.farewell.pif.FarewellHook");
            Object result = hook.getMethod(method).invoke(null);
            return result != null ? result.toString() : "[]";
        } catch (Throwable t) {
            return "[]";
        }
    }

    /**
     * Reflective refresh + invoke with retries. A freshly started process can be transiently
     * denied by the bootstrap gate (package name not bound yet), and the decision is cached per
     * process for a few seconds; retrying makes self-test/verify deterministic.
     */
    static String invokeHookLoaded(String method) {
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

    static JSONObject hookState(Context context) {
        try {
            JSONObject out = new JSONObject();
            String meta = HookStore.getString(context, HookStore.HOOK_META);
            out.put("meta", meta != null ? meta : "");
            out.put("installed", meta != null && !meta.isEmpty());
            out.put("assetSha", assetHookSha(context));
            out.put("upToDate", meta != null && meta.startsWith(assetHookSha(context)));
            return out;
        } catch (Throwable t) {
            try {
                return new JSONObject().put("error", String.valueOf(t));
            } catch (Throwable ignored) {
                return new JSONObject();
            }
        }
    }

    private static String assetHookSha(Context context) {
        try {
            byte[] dex = MainActivity.readAll(context.getAssets().open("hook.dex"));
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(dex);
            StringBuilder builder = new StringBuilder();
            for (byte value : hash) builder.append(String.format("%02x", value));
            return builder.toString();
        } catch (Throwable t) {
            return "";
        }
    }

    /** Replicates the bootstrap dex load to pinpoint failures over ADB (no repack needed). */
    static String dexProbe(Context context) {
        JSONObject out = new JSONObject();
        try {
            String meta = HookStore.getString(context, HookStore.HOOK_META);
            out.put("meta", meta);
            if (meta == null || meta.isEmpty()) {
                out.put("error", "no meta");
                return out.toString();
            }
            String[] parts = meta.split(":");
            int chunks = Integer.parseInt(parts[1]);
            out.put("chunks", chunks);
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            for (int i = 0; i < chunks; i++) {
                String encoded = HookStore.getString(context, HookStore.HOOK_CHUNK + i);
                if (encoded == null || encoded.isEmpty()) {
                    out.put("error", "chunk " + i + " missing");
                    return out.toString();
                }
                buffer.write(HookStore.xor(Base64.decode(encoded, Base64.DEFAULT)));
            }
            byte[] dex = buffer.toByteArray();
            out.put("bytes", dex.length);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(dex);
            StringBuilder hex = new StringBuilder();
            for (byte value : hash) hex.append(String.format("%02x", value));
            out.put("shaMatch", hex.toString().equalsIgnoreCase(parts[0]));
            ClassLoader loader = new dalvik.system.InMemoryDexClassLoader(
                    java.nio.ByteBuffer.wrap(dex), context.getClassLoader());
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
    static String hookProbe(Context context) {
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
            Object meta = read.invoke(null, HookStore.HOOK_META);
            out.put("bootstrapMetaLen", meta == null ? -1 : meta.toString().length());
            Object chunk0 = read.invoke(null, HookStore.HOOK_CHUNK + 0);
            out.put("bootstrapChunk0Len", chunk0 == null ? -1 : chunk0.toString().length());
            java.lang.reflect.Method ctxMethod = hook.getDeclaredMethod("context");
            ctxMethod.setAccessible(true);
            Object hookContext = ctxMethod.invoke(null);
            out.put("context", hookContext == null ? "null" : hookContext.getClass().getName());
            if (hookContext instanceof android.content.Context) {
                android.content.Context ctx = (android.content.Context) hookContext;
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
                            ctx.getContentResolver(), HookStore.HOOK_META);
                    out.put("directReadLen", direct == null ? -1 : direct.length());
                } catch (Throwable t) {
                    out.put("directReadError", t.toString());
                }
                try {
                    String viaApp = android.provider.Settings.Global.getString(
                            context.getContentResolver(), HookStore.HOOK_META);
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

    /** Native property hook probe: loads the library bundled in the APK and verifies it. */
    static String nativeProbeTest(Context context) {
        JSONObject out = new JSONObject();
        try {
            File lib = new File(context.getFilesDir(), "libfarewell.so");
            InputStream in = context.getAssets().open("libfarewell.so");
            java.io.FileOutputStream fileOut = new java.io.FileOutputStream(lib);
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) > 0) fileOut.write(buffer, 0, read);
            fileOut.close();
            in.close();
            System.load(lib.getAbsolutePath());
            out.put("native", nativeProbe());
        } catch (Throwable t) {
            try {
                out.put("error", t.toString());
            } catch (Throwable ignored) {
            }
        }
        return out.toString();
    }

    private static native String nativeProbe();

    static String getLogcat(int lines) {
        try {
            ProcessBuilder builder = new ProcessBuilder("logcat", "-d", "-t",
                    String.valueOf(lines), "-v", "time",
                    "-s", "FarewellPIF:V", "AndroidRuntime:E", "*:S");
            builder.redirectErrorStream(true);
            Process process = builder.start();
            byte[] data = MainActivity.readAll(process.getInputStream());
            process.waitFor();
            return new String(data, StandardCharsets.UTF_8);
        } catch (Throwable t) {
            return "logcat failed: " + t;
        }
    }

    static String getDebugState(Context context) {
        try {
            JSONObject out = new JSONObject();
            out.put("adb", Settings.Global.getInt(context.getContentResolver(),
                    Settings.Global.ADB_ENABLED, -1));
            out.put("development", Settings.Global.getInt(context.getContentResolver(),
                    Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, -1));
            out.put("debug", HookStore.readConfig(context).optInt("dbg", 0));
            out.put("hook", hookState(context));
            File dir = context.getExternalFilesDir(null);
            out.put("dir", dir != null ? dir.getAbsolutePath()
                    : context.getFilesDir().getAbsolutePath());
            return out.toString();
        } catch (Throwable t) {
            return "{\"error\":\"" + MainActivity.escape(t.getMessage()) + "\"}";
        }
    }

    static String exportDebugBundle(MainActivity activity) {
        try {
            File dir = activity.getExternalFilesDir(null);
            if (dir == null) dir = activity.getFilesDir();
            if (!dir.exists()) dir.mkdirs();
            String stamp = new java.text.SimpleDateFormat("yyyyMMdd-HHmmss",
                    java.util.Locale.US).format(new java.util.Date());
            File target = new File(dir, "FarewellPIF-debug-" + stamp + ".zip");
            ZipOutputStream zip = new ZipOutputStream(new java.io.FileOutputStream(target));
            try {
                putZipEntry(zip, "self-test.json", invokeHookLoaded("diagnose"));
                putZipEntry(zip, "hook-live-test.json", invokeHookLoaded("selfTest"));
                putZipEntry(zip, "hook-state.json", hookProbe(activity));
                putZipEntry(zip, "events.json", invokeHook("getEvents"));
                JSONObject redacted = new JSONObject(activity.readConfig().toString());
                JSONArray keyboxes = redacted.optJSONArray("kb");
                if (keyboxes != null) {
                    JSONArray sizes = new JSONArray();
                    for (int i = 0; i < keyboxes.length(); i++) {
                        sizes.put(keyboxes.optString(i, "").length());
                    }
                    redacted.put("kb", sizes);
                }
                putZipEntry(zip, "config-redacted.json", redacted.toString(2));
                putZipEntry(zip, "debug-state.json", getDebugState(activity));
                putZipEntry(zip, "device.txt", deviceText(activity));
                putZipEntry(zip, "logcat.txt", getLogcat(3000));
            } finally {
                zip.close();
            }
            return target.getAbsolutePath();
        } catch (Throwable t) {
            return "export failed: " + t;
        }
    }

    static String checkRomSignature() {
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
            return "{\"error\":\"" + MainActivity.escape(t.getMessage()) + "\"}";
        }
    }

    private static String deviceText(Context context) {
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
        builder.append("adb_enabled=").append(Settings.Global.getInt(context.getContentResolver(),
                Settings.Global.ADB_ENABLED, -1)).append('\n');
        builder.append("development_settings=").append(Settings.Global.getInt(
                context.getContentResolver(), Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, -1))
                .append('\n');
        return builder.toString();
    }

    private static void putZipEntry(ZipOutputStream zip, String name, String text)
            throws Exception {
        zip.putNextEntry(new ZipEntry(name));
        zip.write((text == null ? "" : text).getBytes(StandardCharsets.UTF_8));
        zip.closeEntry();
    }
}

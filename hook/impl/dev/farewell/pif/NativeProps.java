package dev.farewell.pif;

/**
 * Native property spoof ("internal zygisk", no root).
 *
 * The boot-classpath hook loads libfarewell.so in target processes; the library inline-hooks
 * libc's __system_property_get so native readers (DroidGuard VM, Play services) see the same
 * spoofed identity as the Java layer. Rootless equivalent of AlwaysStrong's native prop spoof.
 *
 * The library lives in /system/lib64 after the repack; without it the loader silently does
 * nothing and the Java spoof keeps working alone.
 */
final class NativeProps {
    private static final String[] PATHS = {
            "/system/lib64/libfarewell.so",
            "/system_ext/lib64/libfarewell.so",
    };

    /** Property keys handed to the native layer, resolved through Config.spoofProperty(). */
    private static final String[] KEYS = {
            "ro.boot.verifiedbootstate", "ro.boot.verifiedbootstate.color",
            "ro.boot.flash.locked", "ro.boot.vbmeta.device_state",
            "ro.boot.veritymode", "ro.boot.veritymode.managed",
            "vendor.boot.verifiedbootstate", "vendor.boot.vbmeta.device_state",
            "ro.debuggable", "ro.secure", "ro.adb.secure",
            "sys.usb.state", "init.svc.adbd",
            "ro.build.type", "ro.build.tags",
            "ro.build.fingerprint", "ro.bootimage.build.fingerprint",
            "ro.vendor.build.fingerprint", "ro.system.build.fingerprint",
            "ro.product.build.fingerprint", "ro.odm.build.fingerprint",
            "ro.product.model", "ro.product.brand", "ro.product.device",
            "ro.product.name", "ro.product.manufacturer",
            "ro.build.id", "ro.build.version.incremental", "ro.build.version.release",
            "ro.build.description", "ro.build.version.security_patch",
            "ro.vendor.build.security_patch", "ro.system.build.version.security_patch",
            "ro.product.first_api_level",
    };

    private static volatile boolean sLoaded;
    private static volatile boolean sEnabled;

    private static native int enable(String[] keys, String[] values);

    static native String nativeGet(String key);

    private NativeProps() {
    }

    private static boolean load() {
        if (sLoaded) return true;
        for (String path : PATHS) {
            try {
                System.load(path);
                sLoaded = true;
                return true;
            } catch (Throwable ignored) {
            }
        }
        return false;
    }

    /** Called once per process for props targets; no-op when the library is absent. */
    static void enableFrom(Config.Snapshot cfg) {
        if (sEnabled || cfg == null) return;
        if (!load()) return;
        try {
            java.util.List<String> keys = new java.util.ArrayList<String>();
            java.util.List<String> values = new java.util.ArrayList<String>();
            for (String key : KEYS) {
                String value = cfg.spoofProperty(key);
                if (value == null || value.isEmpty()) continue;
                keys.add(key);
                values.add(value);
            }
            if (keys.isEmpty()) return;
            int state = enable(keys.toArray(new String[0]), values.toArray(new String[0]));
            sEnabled = state == 1;
            if (cfg.debug) {
                HookImpl.debug("native props state=" + state + " entries=" + keys.size());
            }
        } catch (Throwable t) {
            Config.log("native props enable failed", t);
        }
    }
}

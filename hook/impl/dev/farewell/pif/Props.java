package dev.farewell.pif;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.Base64;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.KeyStore;
import java.security.KeyStoreSpi;
import java.security.Provider;
import java.security.Security;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Play Integrity style spoofing applied per target process.
 *
 * - Build / Build.VERSION fields from the profile
 * - platform ("android") package signature (optional)
 * - AndroidKeyStore provider wrapper (optional)
 */
final class Props {
    private static final String[] BUILD_FIELDS = {
            "MANUFACTURER", "BRAND", "DEVICE", "PRODUCT", "MODEL",
            "FINGERPRINT", "ID", "INCREMENTAL", "TYPE", "TAGS", "HOST", "DISPLAY"
    };
    private static final String[] VERSION_FIELDS = {"RELEASE", "INCREMENTAL", "SECURITY_PATCH"};

    private static final AtomicBoolean sSignatureInstalled = new AtomicBoolean(false);

    private Props() {
    }

    static void onProcessStart(Config.Snapshot cfg, Context context, String process) {
        String pkg = null;
        try {
            pkg = context.getPackageName();
        } catch (Throwable ignored) {
        }
        if (pkg == null) return;
        if (!cfg.isTarget(pkg, process)) return;
        if (cfg.propsEnabled()) {
            applyBuildFields(cfg.profileFor(pkg));
        }
        if (cfg.signatureSpoof()) {
            installSignatureSpoof();
        }
    }

    static void reapply() {
        try {
            Config.Snapshot cfg = Config.get();
            if (cfg == null || !cfg.enabled || !cfg.propsEnabled()) return;
            String pkg = Config.currentPackage();
            if (pkg == null) return;
            if (!cfg.isTarget(pkg, HookImpl.currentProcessName())) return;
            applyBuildFields(cfg.profileFor(pkg));
        } catch (Throwable ignored) {
        }
    }

    static void applyBuildFields(org.json.JSONObject profile) {
        if (profile == null) return;
        for (String name : BUILD_FIELDS) {
            String value = Config.Snapshot.profileString(profile, name);
            if (value == null) continue;
            setStaticField(Build.class, name, value);
        }
        for (String name : VERSION_FIELDS) {
            String value = Config.Snapshot.profileString(profile, name);
            if (value == null) continue;
            setStaticField(Build.VERSION.class, name, value);
        }
        // Build.VERSION.DEVICE_INITIAL_SDK_INT is an int field (API 31+).
        String initialSdk = Config.Snapshot.profileString(profile, "DEVICE_INITIAL_SDK_INT");
        if (initialSdk != null) {
            try {
                setStaticIntField(Build.VERSION.class, "DEVICE_INITIAL_SDK_INT",
                        Integer.parseInt(initialSdk.trim()));
            } catch (Throwable t) {
                Config.log("failed to spoof DEVICE_INITIAL_SDK_INT", t);
            }
        }
    }

    private static void setStaticIntField(Class<?> target, String name, int value) {
        try {
            Field field = target.getField(name);
            field.setAccessible(true);
            Object current = field.get(null);
            if (current instanceof Integer && ((Integer) current).intValue() == value) {
                field.setAccessible(false);
                return;
            }
            field.setInt(null, value);
            field.setAccessible(false);
        } catch (Throwable t) {
            Config.log("failed to spoof int field " + name, t);
        }
    }

    private static void setStaticField(Class<?> target, String name, String value) {
        try {
            Field field = target.getField(name);
            field.setAccessible(true);
            Object current = field.get(null);
            if (value.equals(current)) {
                field.setAccessible(false);
                return;
            }
            field.set(null, value);
            field.setAccessible(false);
            if (Config.get().debug) HookImpl.debug("spoofed " + name + "=" + value);
        } catch (Throwable t) {
            Config.log("failed to spoof " + name, t);
        }
    }

    static void installProviderSpoof() {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            Field spiField = keyStore.getClass().getDeclaredField("keyStoreSpi");
            spiField.setAccessible(true);
            CustomKeyStoreSpi.keyStoreSpi = (KeyStoreSpi) spiField.get(keyStore);
            spiField.setAccessible(false);
        } catch (Throwable t) {
            Config.log("could not capture KeyStoreSpi", t);
            return;
        }
        try {
            Provider original = Security.getProvider("AndroidKeyStore");
            if (original == null) return;
            Security.removeProvider("AndroidKeyStore");
            Security.insertProviderAt(new CustomProvider(original), 1);
        } catch (Throwable t) {
            Config.log("could not install custom provider", t);
        }
    }

    static void installSignatureSpoof() {
        if (!sSignatureInstalled.compareAndSet(false, true)) return;
        try {
            Signature spoofed = new Signature(
                    Base64.decode(AndroidSignature.DATA, Base64.DEFAULT));
            Parcelable.Creator<PackageInfo> original = PackageInfo.CREATOR;
            Field creator = findField(PackageInfo.class, "CREATOR");
            creator.setAccessible(true);
            creator.set(null, new CustomPackageInfoCreator(original, spoofed));
            creator.setAccessible(false);
            clearPackageCaches();
        } catch (Throwable t) {
            Config.log("signature spoof failed", t);
        }
    }

    private static void clearPackageCaches() {
        try {
            Field cacheField = findField(PackageManager.class, "sPackageInfoCache");
            cacheField.setAccessible(true);
            Object cache = cacheField.get(null);
            if (cache != null) {
                Method clear = cache.getClass().getMethod("clear");
                clear.invoke(cache);
            }
        } catch (Throwable ignored) {
        }
        try {
            Field creators = findField(Parcel.class, "mCreators");
            creators.setAccessible(true);
            Map<?, ?> map = (Map<?, ?>) creators.get(null);
            if (map != null) map.clear();
        } catch (Throwable ignored) {
        }
        try {
            Field paired = findField(Parcel.class, "sPairedCreators");
            paired.setAccessible(true);
            Map<?, ?> map = (Map<?, ?>) paired.get(null);
            if (map != null) map.clear();
        } catch (Throwable ignored) {
        }
    }

    static Field findField(Class<?> type, String name) throws NoSuchFieldException {
        Class<?> current = type;
        while (current != null && current != Object.class) {
            try {
                return current.getDeclaredField(name);
            } catch (NoSuchFieldException ignored) {
                current = current.getSuperclass();
            }
        }
        throw new NoSuchFieldException(name);
    }
}

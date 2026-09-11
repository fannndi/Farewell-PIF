package dev.farewell.pif;

/**
 * Reflective bridge to the boot-classpath shim.
 *
 * The impl dex is loaded in-memory and counts as untrusted for hidden API enforcement, so
 * blacklisted members (AndroidKeyStoreKeyPairGeneratorSpi fields, KeyEntryResponse.metadata,
 * keystore2 import methods, ...) cannot be reflected on directly. FarewellHook lives on the boot
 * classpath and is exempt; every reflective operation in this module routes through it and falls
 * back to local reflection only for non-hidden members.
 */
final class Bridge {
    private Bridge() {
    }

    /** Reads a field through the bootstrap; falls back to local reflection (non-hidden members). */
    static Object field(Object target, String name) {
        if (target == null) return null;
        try {
            Class<?> hook = Class.forName("dev.farewell.pif.FarewellHook");
            Object value = hook.getMethod("getField", Object.class, String.class)
                    .invoke(null, target, name);
            if (value != null) return value;
        } catch (Throwable ignored) {
        }
        Class<?> type = target.getClass();
        while (type != null) {
            try {
                java.lang.reflect.Field field = type.getDeclaredField(name);
                field.setAccessible(true);
                return field.get(target);
            } catch (NoSuchFieldException ignored) {
                type = type.getSuperclass();
            } catch (Throwable t) {
                Config.logOnce("field " + name + " blocked: " + t);
                return null;
            }
        }
        return null;
    }

    /** Writes a field through the boot-classpath bridge (hidden API exempt). */
    static boolean set(Object target, String name, Object value) {
        try {
            Class<?> hook = Class.forName("dev.farewell.pif.FarewellHook");
            Object result = hook.getMethod("setField", Object.class, String.class, Object.class)
                    .invoke(null, target, name, value);
            return Boolean.TRUE.equals(result);
        } catch (Throwable ignored) {
            return false;
        }
    }

    /** Invokes a public method through the boot-classpath bridge. */
    static Object call(Object target, String name, Class<?>[] types, Object... args) {
        try {
            Class<?> hook = Class.forName("dev.farewell.pif.FarewellHook");
            return hook.getMethod("invokeMethod", Object.class, String.class,
                    Class[].class, Object[].class).invoke(null, target, name, types, args);
        } catch (Throwable ignored) {
            return null;
        }
    }

    /** Invokes a declared (possibly inherited) method through the boot-classpath bridge. */
    static Object callDeclared(Object target, String name, Class<?>[] types, Object... args) {
        try {
            Class<?> hook = Class.forName("dev.farewell.pif.FarewellHook");
            return hook.getMethod("invokeDeclared", Object.class, String.class,
                    Class[].class, Object[].class).invoke(null, target, name, types, args);
        } catch (Throwable ignored) {
            return null;
        }
    }

    /** Invokes a void method through the bridge, reporting whether it succeeded. */
    static boolean callVoid(Object target, String name, Class<?>[] types, Object... args) {
        try {
            Class<?> hook = Class.forName("dev.farewell.pif.FarewellHook");
            Object result = hook.getMethod("tryInvoke", Object.class, String.class,
                    Class[].class, Object[].class).invoke(null, target, name, types, args);
            return Boolean.TRUE.equals(result);
        } catch (Throwable ignored) {
            return false;
        }
    }

    /** Builds a keystore2 KeyDescriptor in the boot classpath (hidden constructors). */
    static Object newKeyDescriptor(int domain, long namespace, String alias) {
        try {
            Class<?> hook = Class.forName("dev.farewell.pif.FarewellHook");
            return hook.getMethod("newKeyDescriptor", int.class, long.class, String.class)
                    .invoke(null, Integer.valueOf(domain), Long.valueOf(namespace), alias);
        } catch (Throwable ignored) {
            return null;
        }
    }

    static String asString(Object value) {
        return value instanceof String ? (String) value : null;
    }

    static int asInt(Object value, int fallback) {
        return value instanceof Integer ? ((Integer) value).intValue() : fallback;
    }
}

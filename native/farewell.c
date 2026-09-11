// Farewell-PIF native property spoof ("internal zygisk", no root).
//
// Loaded from the boot-classpath hook in target processes. Inline-hooks libc's
// __system_property_get so NATIVE readers (DroidGuard VM, Play services) see the spoofed
// identity, which Java-only spoofing cannot reach.
//
// Safety: if anything fails (dlsym, mprotect, PC-relative prologue), the hook is skipped and
// the original function keeps working.

#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define LOG_TAG "FarewellNative"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#define PROP_VALUE_MAX 92
#define MAX_PROPS 96
#define PAGE_SIZE 4096

// Bionic still exports this, but the NDK header hides it.
extern int __system_property_get(const char *name, char *value);

static char g_keys[MAX_PROPS][PROP_VALUE_MAX];
static char g_values[MAX_PROPS][PROP_VALUE_MAX];
static int g_count = 0;
static int g_ready = 0; // 0 idle, 1 installed, 2 failed

typedef int (*prop_get_t)(const char *, char *);
static prop_get_t g_orig_get = NULL;
static uint8_t g_tramp[32] __attribute__((aligned(16)));

static const char *lookup(const char *name) {
    if (name == NULL) return NULL;
    for (int i = 0; i < g_count; i++) {
        if (strcmp(g_keys[i], name) == 0) return g_values[i];
    }
    return NULL;
}

static int farewell_get(const char *name, char *value) {
    const char *spoofed = lookup(name);
    if (spoofed != NULL) {
        if (value == NULL) return 0;
        size_t len = strlen(spoofed);
        if (len > PROP_VALUE_MAX - 1) len = PROP_VALUE_MAX - 1;
        memcpy(value, spoofed, len);
        value[len] = '\0';
        return (int) len;
    }
    if (g_orig_get != NULL) return g_orig_get(name, value);
    return 0;
}

static int is_pc_relative(uint32_t insn) {
    // ADR/ADRP and literal loads would break when relocated into the trampoline.
    if ((insn & 0x9F000000) == 0x10000000) return 1; // ADR / ADRP
    if ((insn & 0x3B000000) == 0x18000000) return 1; // LDR (literal) 32/64/128
    if ((insn & 0x3B000000) == 0x38000000) return 0;
    return 0;
}

static void install_hook(void *target) {
    uint8_t *code = (uint8_t *) target;
    uintptr_t page = (uintptr_t) code & ~(uintptr_t) (PAGE_SIZE - 1);
    if (mprotect((void *) page, PAGE_SIZE * 2,
                 PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOGE("mprotect failed");
        return;
    }
    uint32_t first[4];
    memcpy(first, code, sizeof(first));
    for (int i = 0; i < 4; i++) {
        if (is_pc_relative(first[i])) {
            LOGE("prologue has PC-relative instruction, skipping hook");
            mprotect((void *) page, PAGE_SIZE * 2, PROT_READ | PROT_EXEC);
            return;
        }
    }
    // trampoline: copy 16 bytes then jump back to code+16
    memcpy(g_tramp, code, 16);
    uint32_t *t = (uint32_t *) (g_tramp + 16);
    t[0] = 0x58000051; // ldr x17, #8
    t[1] = 0xD61F0220; // br x17
    *(uint64_t *) (g_tramp + 24) = (uint64_t) (code + 16);
    g_orig_get = (prop_get_t) g_tramp;

    // overwrite entry: ldr x17, #8; br x17; .quad farewell_get
    uint32_t patch[2];
    patch[0] = 0x58000051;
    patch[1] = 0xD61F0220;
    memcpy(code, patch, sizeof(patch));
    *(uint64_t *) (code + 8) = (uint64_t) &farewell_get;
    __builtin___clear_cache((char *) code, (char *) code + 16);
    g_ready = 1;
    LOGI("__system_property_get hooked");
}

JNIEXPORT jint JNICALL
Java_dev_farewell_pif_NativeProps_enable(JNIEnv *env, jclass clazz,
                                         jobjectArray keys, jobjectArray values) {
    if (g_ready != 0) return g_ready;
    if (keys == NULL || values == NULL) return 2;
    jsize n = (*env)->GetArrayLength(env, keys);
    jsize m = (*env)->GetArrayLength(env, values);
    if (n > m) n = m;
    if (n > MAX_PROPS) n = MAX_PROPS;
    for (jsize i = 0; i < n; i++) {
        jstring key = (jstring) (*env)->GetObjectArrayElement(env, keys, i);
        jstring value = (jstring) (*env)->GetObjectArrayElement(env, values, i);
        if (key == NULL || value == NULL) continue;
        const char *keyText = (*env)->GetStringUTFChars(env, key, NULL);
        const char *valueText = (*env)->GetStringUTFChars(env, value, NULL);
        if (keyText != NULL && valueText != NULL) {
            strncpy(g_keys[g_count], keyText, PROP_VALUE_MAX - 1);
            strncpy(g_values[g_count], valueText, PROP_VALUE_MAX - 1);
            g_count++;
        }
        if (keyText != NULL) (*env)->ReleaseStringUTFChars(env, key, keyText);
        if (valueText != NULL) (*env)->ReleaseStringUTFChars(env, value, valueText);
        (*env)->DeleteLocalRef(env, key);
        (*env)->DeleteLocalRef(env, value);
    }
    void *target = dlsym(RTLD_DEFAULT, "__system_property_get");
    if (target == NULL) {
        void *libc = dlopen("libc.so", RTLD_NOW);
        if (libc != NULL) target = dlsym(libc, "__system_property_get");
    }
    if (target == NULL) {
        LOGE("__system_property_get not found");
        g_ready = 2;
        return 2;
    }
    install_hook(target);
    if (g_ready != 1) g_ready = 2;
    LOGI("native props enabled: %d entries, state=%d", g_count, g_ready);
    return g_ready;
}

// Test/entry helper: read through the (possibly hooked) libc function.
JNIEXPORT jstring JNICALL
Java_dev_farewell_pif_NativeProps_nativeGet(JNIEnv *env, jclass clazz, jstring key) {
    if (key == NULL) return NULL;
    const char *keyText = (*env)->GetStringUTFChars(env, key, NULL);
    char value[PROP_VALUE_MAX];
    value[0] = '\0';
    int len = __system_property_get(keyText, value);
    (*env)->ReleaseStringUTFChars(env, key, keyText);
    if (len <= 0) return NULL;
    return (*env)->NewStringUTF(env, value);
}

// Real value, bypassing the hook (for attestation defaults that must match the device).
JNIEXPORT jstring JNICALL
Java_dev_farewell_pif_NativeProps_nativeGetReal(JNIEnv *env, jclass clazz, jstring key) {
    if (key == NULL) return NULL;
    const char *keyText = (*env)->GetStringUTFChars(env, key, NULL);
    char value[PROP_VALUE_MAX];
    value[0] = '\0';
    int len = g_orig_get != NULL ? g_orig_get(keyText, value)
                                 : __system_property_get(keyText, value);
    (*env)->ReleaseStringUTFChars(env, key, keyText);
    if (len <= 0) return NULL;
    return (*env)->NewStringUTF(env, value);
}

// App-side probe: reads before, installs a one-key spoof, reads after. Proves the hook works
// end to end without a repack (lib loaded from the app's files dir).
JNIEXPORT jstring JNICALL
Java_dev_farewell_pif_app_MainActivity_nativeProbe(JNIEnv *env, jobject thiz) {
    char before[PROP_VALUE_MAX];
    before[0] = '\0';
    __system_property_get("ro.farewell.native.probe", before);
    if (g_count == 0) {
        strncpy(g_keys[g_count], "ro.farewell.native.probe", PROP_VALUE_MAX - 1);
        strncpy(g_values[g_count], "hooked", PROP_VALUE_MAX - 1);
        g_count++;
        void *target = dlsym(RTLD_DEFAULT, "__system_property_get");
        if (target == NULL) {
            void *libc = dlopen("libc.so", RTLD_NOW);
            if (libc != NULL) target = dlsym(libc, "__system_property_get");
        }
        if (target != NULL) install_hook(target);
    }
    char after[PROP_VALUE_MAX];
    after[0] = '\0';
    __system_property_get("ro.farewell.native.probe", after);
    char buffer[160];
    snprintf(buffer, sizeof(buffer), "before='%s' after='%s' state=%d", before, after, g_ready);
    return (*env)->NewStringUTF(env, buffer);
}

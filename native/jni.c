// JNI entry points used by dev.farewell.pif.NativeProps and the app probe.

#include "farewell.h"

#include <android/log.h>
#include <dlfcn.h>
#include <jni.h>
#include <stdio.h>
#include <string.h>

#define LOG_TAG "FarewellNative"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

extern int __system_property_get(const char *name, char *value);

JNIEXPORT jint JNICALL
Java_dev_farewell_pif_NativeProps_enable(JNIEnv *env, jclass clazz,
                                         jobjectArray keys, jobjectArray values) {
    if (hook_state() != 0) return hook_state();
    if (keys == NULL || values == NULL) return 2;
    jsize n = (*env)->GetArrayLength(env, keys);
    jsize m = (*env)->GetArrayLength(env, values);
    if (n > m) n = m;
    for (jsize i = 0; i < n; i++) {
        jstring key = (jstring) (*env)->GetObjectArrayElement(env, keys, i);
        jstring value = (jstring) (*env)->GetObjectArrayElement(env, values, i);
        if (key == NULL || value == NULL) continue;
        const char *keyText = (*env)->GetStringUTFChars(env, key, NULL);
        const char *valueText = (*env)->GetStringUTFChars(env, value, NULL);
        if (keyText != NULL && valueText != NULL) props_add(keyText, valueText);
        if (keyText != NULL) (*env)->ReleaseStringUTFChars(env, key, keyText);
        if (valueText != NULL) (*env)->ReleaseStringUTFChars(env, value, valueText);
        (*env)->DeleteLocalRef(env, key);
        (*env)->DeleteLocalRef(env, value);
    }
    int state = hooks_install_all();
    LOGI("native props enabled: %d entries, state=%d", props_count(), state);
    return state;
}

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

JNIEXPORT jstring JNICALL
Java_dev_farewell_pif_NativeProps_nativeGetReal(JNIEnv *env, jclass clazz, jstring key) {
    if (key == NULL) return NULL;
    const char *keyText = (*env)->GetStringUTFChars(env, key, NULL);
    char value[PROP_VALUE_MAX];
    value[0] = '\0';
    int len = props_get_real(keyText, value);
    (*env)->ReleaseStringUTFChars(env, key, keyText);
    if (len <= 0) return NULL;
    return (*env)->NewStringUTF(env, value);
}

// App-side probe (Diag module): reads a synthetic key before/after installing the hook.
JNIEXPORT jstring JNICALL
Java_dev_farewell_pif_app_Diag_nativeProbe(JNIEnv *env, jclass clazz) {
    char before[PROP_VALUE_MAX];
    before[0] = '\0';
    __system_property_get("ro.farewell.native.probe", before);
    if (props_count() == 0) {
        props_add("ro.farewell.native.probe", "hooked");
        hooks_install_all();
    }
    char after[PROP_VALUE_MAX];
    after[0] = '\0';
    __system_property_get("ro.farewell.native.probe", after);
    char buffer[160];
    snprintf(buffer, sizeof(buffer), "before='%s' after='%s' state=%d", before, after,
             hook_state());
    return (*env)->NewStringUTF(env, buffer);
}

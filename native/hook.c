// Minimal arm64 inline hook engine (in-process, no root).
//
// Entry is replaced with:  ldr x17, #8 ; br x17 ; .quad handler
// The first 16 bytes are copied to a trampoline that jumps back to target+16, so the original
// function can still be called. A PC-relative prologue is refused (would break when relocated).

#include "farewell.h"

#include <android/log.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/mman.h>

#define LOG_TAG "FarewellNative"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

#define PAGE_SIZE 4096

extern int __system_property_get(const char *name, char *value);

typedef int (*prop_get_t)(const char *, char *);
typedef void (*prop_cb_t)(void *, const char *, const char *, uint32_t);
typedef void (*prop_read_cb_t)(const void *, prop_cb_t, void *);

static prop_get_t g_orig_get;
static prop_read_cb_t g_orig_read_cb;
static uint8_t g_tramp_get[32] __attribute__((aligned(16)));
static uint8_t g_tramp_cb[32] __attribute__((aligned(16)));
static volatile int g_state;

// Handlers live in props.c.
extern int farewell_get(const char *, char *);
extern void farewell_read_callback(const void *, prop_cb_t, void *);

int hook_state(void) {
    return g_state;
}

static int is_pc_relative(uint32_t insn) {
    if ((insn & 0x9F000000) == 0x10000000) return 1; // ADR / ADRP
    if ((insn & 0x3B000000) == 0x18000000) return 1; // LDR (literal)
    return 0;
}

static int patch_entry(void *target, void *handler, uint8_t *tramp, void **original) {
    uint8_t *code = (uint8_t *) target;
    uintptr_t page = (uintptr_t) code & ~(uintptr_t) (PAGE_SIZE - 1);
    if (mprotect((void *) page, PAGE_SIZE * 2, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOGE("mprotect failed");
        return 0;
    }
    uint32_t first[4];
    memcpy(first, code, sizeof(first));
    for (int i = 0; i < 4; i++) {
        if (is_pc_relative(first[i])) {
            LOGE("prologue has PC-relative instruction, skipping hook");
            mprotect((void *) page, PAGE_SIZE * 2, PROT_READ | PROT_EXEC);
            return 0;
        }
    }
    memcpy(tramp, code, 16);
    uint32_t *t = (uint32_t *) (tramp + 16);
    t[0] = 0x58000051; // ldr x17, #8
    t[1] = 0xD61F0220; // br x17
    *(uint64_t *) (tramp + 24) = (uint64_t) (code + 16);
    *original = tramp;

    uint32_t patch[2];
    patch[0] = 0x58000051;
    patch[1] = 0xD61F0220;
    memcpy(code, patch, sizeof(patch));
    *(uint64_t *) (code + 8) = (uint64_t) handler;
    __builtin___clear_cache((char *) code, (char *) code + 16);
    return 1;
}

static void *resolve(const char *name) {
    void *target = dlsym(RTLD_DEFAULT, name);
    if (target == NULL) {
        void *libc = dlopen("libc.so", RTLD_NOW);
        if (libc != NULL) target = dlsym(libc, name);
    }
    return target;
}

static int hook_install(const char *name, void *handler, uint8_t *tramp, void **original) {
    void *target = resolve(name);
    if (target == NULL) return 0;
    return patch_entry(target, handler, tramp, original);
}

int props_get_real(const char *name, char *value) {
    if (g_orig_get != NULL) return g_orig_get(name, value);
    return __system_property_get(name, value);
}

int props_read_callback_real(const void *pi, prop_cb_t callback, void *cookie) {
    if (g_orig_read_cb == NULL) return 0;
    g_orig_read_cb(pi, callback, cookie);
    return 1;
}

int hooks_install_all(void) {
    if (g_state == 1) return 1;
    int ok = hook_install("__system_property_get", (void *) &farewell_get,
                          g_tramp_get, (void **) &g_orig_get);
    if (ok) {
        LOGI("__system_property_get hooked");
        hook_install("__system_property_read_callback", (void *) &farewell_read_callback,
                     g_tramp_cb, (void **) &g_orig_read_cb);
    }
    g_state = ok ? 1 : 2;
    return g_state;
}

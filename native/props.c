// Spoof table and the libc hook handlers.
//
// The table is filled once from Java (NativeProps.enable) with the same keys/values the Java
// layer uses, so native readers (DroidGuard VM, android::base::GetProperty users) see a
// consistent identity. Lookups are read-only afterwards, so no locking is needed.

#include "farewell.h"

#include <string.h>

extern int farewell_get(const char *name, char *value);
extern void farewell_read_callback(const void *pi, farewell_prop_cb_t callback, void *cookie);

static char g_keys[MAX_PROPS][PROP_VALUE_MAX];
static char g_values[MAX_PROPS][PROP_VALUE_MAX];
static int g_count;

const char *props_lookup(const char *name) {
    if (name == NULL) return NULL;
    for (int i = 0; i < g_count; i++) {
        if (strcmp(g_keys[i], name) == 0) return g_values[i];
    }
    return NULL;
}

int props_add(const char *key, const char *value) {
    if (key == NULL || value == NULL || g_count >= MAX_PROPS) return 0;
    strncpy(g_keys[g_count], key, PROP_VALUE_MAX - 1);
    strncpy(g_values[g_count], value, PROP_VALUE_MAX - 1);
    g_count++;
    return 1;
}

int props_count(void) {
    return g_count;
}

// ---- __system_property_get handler -----------------------------------------

int farewell_get(const char *name, char *value) {
    const char *spoofed = props_lookup(name);
    if (spoofed == NULL) return props_get_real(name, value);
    if (value == NULL) return 0;
    size_t len = strlen(spoofed);
    if (len > PROP_VALUE_MAX - 1) len = PROP_VALUE_MAX - 1;
    memcpy(value, spoofed, len);
    value[len] = '\0';
    return (int) len;
}

// ---- __system_property_read_callback handler --------------------------------

struct cb_ctx {
    farewell_prop_cb_t user;
    void *cookie;
};

static void farewell_cb_thunk(void *cookie, const char *name, const char *value,
                              uint32_t serial) {
    struct cb_ctx *ctx = (struct cb_ctx *) cookie;
    const char *spoofed = props_lookup(name);
    ctx->user(ctx->cookie, name, spoofed != NULL ? spoofed : value, serial);
}

void farewell_read_callback(const void *pi, farewell_prop_cb_t callback, void *cookie) {
    if (callback == NULL) {
        props_read_callback_real(pi, NULL, cookie);
        return;
    }
    struct cb_ctx ctx;
    ctx.user = callback;
    ctx.cookie = cookie;
    props_read_callback_real(pi, farewell_cb_thunk, &ctx);
}

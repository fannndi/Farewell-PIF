#ifndef FAREWELL_H
#define FAREWELL_H

// Shared declarations for the Farewell-PIF native modules.
//
//   props.c  spoof table + __system_property_get / read_callback handlers
//   hook.c   minimal arm64 inline hook engine (16-byte branch + trampoline)
//   jni.c    JNI entry points called by NativeProps.java

#include <stdint.h>

#define PROP_VALUE_MAX 92
#define MAX_PROPS 96

typedef int (*farewell_prop_get_t)(const char *, char *);
typedef void (*farewell_prop_cb_t)(void *, const char *, const char *, uint32_t);

// --- props.c ---
const char *props_lookup(const char *name);
int props_add(const char *key, const char *value);
int props_count(void);

// --- hook.c ---
int props_get_real(const char *name, char *value);
int props_read_callback_real(const void *pi, farewell_prop_cb_t callback, void *cookie);
int hooks_install_all(void);
int hook_state(void);

#endif

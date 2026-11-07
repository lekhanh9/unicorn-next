#ifndef RUNTIME_HOOKS_H
#define RUNTIME_HOOKS_H

#include <stdint.h>
#include <stdbool.h>
#include <unicorn/unicorn.h>
#include "darwin_env.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Hook Callback Signature for Unicorn-emulated C functions.
 * When CPU hits a stub trampoline, this function executes host logic,
 * inspects registers (X0..X7) and writes return values (X0, X1).
 */
typedef void (*darwin_hook_fn)(darwin_env_t *env, uc_engine *uc);

typedef struct darwin_hook_entry {
    const char *name;           /* Symbol name, e.g. "malloc", "free" */
    uint64_t addr;              /* Trampoline address in emulator space */
    darwin_hook_fn handler;     /* Host C handler */
} darwin_hook_entry_t;

/**
 * Initialize standard LibSystem hooks:
 * - Memory: malloc, calloc, realloc, free, posix_memalign
 * - Threading: pthread_self, pthread_mutex_*, pthread_key_*
 * - Time: mach_timebase_info, mach_absolute_time, gettimeofday
 * - Mach IPC: mach_msg, mach_msg_trap stub
 * - Strings/Utils: abort, __assert_rtn, os_log stubs
 */
int darwin_hooks_init(darwin_env_t *env);

/**
 * Register a custom symbol hook by name.
 */
uint64_t darwin_hooks_register(darwin_env_t *env, const char *symbol_name, darwin_hook_fn handler);

/**
 * Lookup the trampoline address of a hooked function.
 */
uint64_t darwin_hooks_find(darwin_env_t *env, const char *symbol_name);

#ifdef __cplusplus
}
#endif

#endif /* RUNTIME_HOOKS_H */

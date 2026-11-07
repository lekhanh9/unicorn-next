#ifndef RUNTIME_HOOKS_H
#define RUNTIME_HOOKS_H

#include <stdint.h>
#include <stdbool.h>
#include <unicorn/unicorn.h>
#include "darwin_env.h"
#include "../loader/macho.h"

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
    char *name;                 /* Symbol name, e.g. "malloc", "free" */
    uint64_t addr;              /* Trampoline address in emulator space */
    darwin_hook_fn handler;     /* Host C handler */
} darwin_hook_entry_t;

typedef struct darwin_hook_manager {
    darwin_hook_entry_t *entries;
    size_t count;
    size_t capacity;
    uc_hook uc_code_hook;       /* Unicorn code hook handle */
    uint64_t next_trampoline;
} darwin_hook_manager_t;

/**
 * Initialize standard LibSystem hooks:
 * - Memory & strings: malloc, calloc, realloc, free, posix_memalign, memcpy, memset, strlen, etc.
 * - Time: mach_timebase_info, mach_absolute_time, gettimeofday
 * - Threading: pthread_self, pthread_mutex_*, pthread_once, dispatch_once
 * - System: sysctlbyname, abort, getenv
 */
int darwin_hooks_init(darwin_env_t *env);

/**
 * Free hook manager and all registered entries.
 */
void darwin_hooks_cleanup(darwin_env_t *env);

/**
 * Register a custom symbol hook by name.
 * Allocates a unique trampoline in the trampoline page and records the handler.
 *
 * @param env Darwin environment context.
 * @param symbol_name Name of function to hook (e.g. "malloc" or "_malloc").
 * @param handler Host C handler function.
 * @return Mapped virtual address of the hook trampoline.
 */
uint64_t darwin_hooks_register(darwin_env_t *env, const char *symbol_name, darwin_hook_fn handler);

/**
 * Lookup the trampoline address of a hooked function.
 * Matches with or without leading underscore.
 */
uint64_t darwin_hooks_find(darwin_env_t *env, const char *symbol_name);

/**
 * Automatically bind all external symbols and stubs of a loaded Mach-O image
 * to registered hook trampolines (e.g. populates __got and __auth_got).
 *
 * @param env Darwin environment context.
 * @param img Loaded Mach-O image.
 * @return Number of symbols bound.
 */
int darwin_hooks_bind_macho(darwin_env_t *env, macho_image_t *img);

#ifdef __cplusplus
}
#endif

#endif /* RUNTIME_HOOKS_H */

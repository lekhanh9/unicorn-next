#ifndef DARWIN_ENV_H
#define DARWIN_ENV_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <unicorn/unicorn.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declaration */
struct darwin_hook_manager;

/*
 * Darwin Emulation Environment Context
 * Manages CPU ARM64 state, memory maps, stack, TLS, heap allocator, and hooks.
 */
typedef struct darwin_env {
    uc_engine *uc;                  /* Unicorn engine instance */

    /* Stack */
    uint64_t stack_base;            /* Bottom of stack mapping (0x7fff00000000) */
    uint64_t stack_size;            /* Size of stack (2MB default) */
    uint64_t stack_top;             /* Initial SP (top of stack, 16-byte aligned) */

    /* Heap allocator */
    uint64_t heap_base;             /* Base address of virtual heap (0x600000000000) */
    uint64_t heap_size;             /* Allocated heap capacity (64MB initial) */
    uint64_t heap_cur;              /* Current bump pointer */

    /* Thread-local storage (TLS) */
    uint64_t tls_addr;              /* Address of pthread/TLS structure mapped in UC */
    uint64_t tls_size;              /* Size of TLS block (64KB) */

    /* Hook Trampolines */
    uint64_t hook_trampoline_base;  /* Base address for hook trampolines (0x800000000000) */
    uint64_t hook_trampoline_size;  /* Size of trampoline memory (64KB) */
    struct darwin_hook_manager *hooks; /* Hook manager instance */

    /* Execution control */
    uint64_t magic_exit_addr;       /* Special LR address to terminate emulation cleanly */

    bool is_initialized;
} darwin_env_t;

/**
 * Initialize the Darwin environment with default ARM64 memory layout:
 * - Stack: 0x7fff00000000 - 0x7fff00200000 (2MB)
 * - Heap:  0x600000000000 (64MB)
 * - TLS:   0x700000000000 (64KB)
 * - Hooks: 0x800000000000 (64KB)
 * - Exit:  0x80000000f000 (Magic exit hook)
 *
 * @return Allocated darwin_env_t on success, NULL on failure.
 */
darwin_env_t *darwin_env_create(void);

/**
 * Destroy the Darwin environment and free all mapped memory and engine context.
 */
void darwin_env_destroy(darwin_env_t *env);

/**
 * Allocate memory from the virtual heap in the emulator (16-byte aligned).
 */
uint64_t darwin_env_malloc(darwin_env_t *env, size_t size);

/**
 * Free memory in the virtual heap (no-op for bump allocator).
 */
void darwin_env_free(darwin_env_t *env, uint64_t ptr);

/**
 * Setup ARM64 registers (SP, PC, LR, TLS in TPIDR_EL0).
 *
 * @param env Darwin environment context.
 * @param entry_point Initial PC address.
 * @return 0 on success, negative error code on failure.
 */
int darwin_env_setup_thread(darwin_env_t *env, uint64_t entry_point);

/*
 * Memory Access Helpers between Host and Guest
 */
int darwin_env_read_string(darwin_env_t *env, uint64_t addr, char *buf, size_t max_len);
int darwin_env_write_string(darwin_env_t *env, uint64_t addr, const char *str);
int darwin_env_read_mem(darwin_env_t *env, uint64_t addr, void *buf, size_t len);
int darwin_env_write_mem(darwin_env_t *env, uint64_t addr, const void *buf, size_t len);

/*
 * Register Access Helpers
 */
uint64_t darwin_env_get_reg(darwin_env_t *env, int regid);
void darwin_env_set_reg(darwin_env_t *env, int regid, uint64_t val);
void darwin_env_set_return(darwin_env_t *env, uint64_t ret_val);

#ifdef __cplusplus
}
#endif

#endif /* DARWIN_ENV_H */

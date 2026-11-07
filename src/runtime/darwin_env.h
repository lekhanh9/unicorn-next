#ifndef DARWIN_ENV_H
#define DARWIN_ENV_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <unicorn/unicorn.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Darwin Emulation Environment Context
 * Manages CPU ARM64 state, memory maps, stack, TLS, and simulated heap.
 */
typedef struct darwin_env {
    uc_engine *uc;              /* Unicorn engine instance */

    /* Stack */
    uint64_t stack_base;        /* Bottom of stack mapping */
    uint64_t stack_size;        /* Size of stack */
    uint64_t stack_top;         /* Initial SP (top of stack) */

    /* Heap allocator */
    uint64_t heap_base;         /* Base address of virtual heap */
    uint64_t heap_size;         /* Allocated heap capacity */
    uint64_t heap_cur;          /* Current bump/free pointer */

    /* Thread-local storage (TLS) */
    uint64_t tls_addr;          /* Address of pthread/TLS structure mapped in UC */
    uint64_t tls_size;          /* Size of TLS block */

    /* Dispatch / Hook table */
    uint64_t hook_trampoline_base;
    uint64_t hook_trampoline_size;

    bool is_initialized;
} darwin_env_t;

/**
 * Initialize the Darwin environment with default ARM64 memory layout:
 * - Stack: 0x7fff00000000 - 0x7fff00800000 (8MB)
 * - Heap:  0x600000000000 (512MB)
 * - TLS:   0x700000000000 (64KB)
 * - Hooks: 0x800000000000 (64KB)
 */
darwin_env_t *darwin_env_create(void);

/**
 * Destroy the Darwin environment and free all mapped memory and engine context.
 */
void darwin_env_destroy(darwin_env_t *env);

/**
 * Allocate memory from the virtual heap in the emulator.
 */
uint64_t darwin_env_malloc(darwin_env_t *env, size_t size);

/**
 * Free memory in the virtual heap (if supported).
 */
void darwin_env_free(darwin_env_t *env, uint64_t ptr);

/**
 * Setup ARM64 registers (SP, PC, LR, TLS in TPIDR_EL0).
 */
int darwin_env_setup_thread(darwin_env_t *env, uint64_t entry_point);

#ifdef __cplusplus
}
#endif

#endif /* DARWIN_ENV_H */

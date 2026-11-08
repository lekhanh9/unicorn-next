#include "darwin_env.h"
#include "hooks.h"
#if __has_include("../loader/macho.h")
#include "../loader/macho.h"
#else
#include "macho.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

darwin_env_t *darwin_env_create(void) {
    /* Apply iOS compatibility patch for Unicorn TCG */
    macho_init_unicorn_compat();

    darwin_env_t *env = (darwin_env_t *)calloc(1, sizeof(darwin_env_t));
    if (!env) return NULL;

    uc_err err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &env->uc);
    if (err != UC_ERR_OK) {
        fprintf(stderr, "[darwin_env] Error: uc_open failed: %d (%s)\n", err, uc_strerror(err));
        free(env);
        return NULL;
    }

    /* 1. Setup Stack: 2MB at 0x7fff00000000 */
    env->stack_base = 0x7fff00000000ULL;
    env->stack_size = 0x200000ULL; /* 2 MB */
    err = uc_mem_map(env->uc, env->stack_base, env->stack_size, UC_PROT_READ | UC_PROT_WRITE);
    if (err != UC_ERR_OK) {
        fprintf(stderr, "[darwin_env] Error: Mapping stack failed: %d (%s)\n", err, uc_strerror(err));
        uc_close(env->uc);
        free(env);
        return NULL;
    }
    /* SP aligned to 16-byte boundary, with 4KB guard red-zone at the top */
    env->stack_top = (env->stack_base + env->stack_size - 0x1000ULL) & ~15ULL;

    /* 2. Setup Heap: 64MB at 0x600000000000 */
    env->heap_base = 0x600000000000ULL;
    env->heap_size = 0x04000000ULL; /* 64 MB */
    err = uc_mem_map(env->uc, env->heap_base, env->heap_size, UC_PROT_READ | UC_PROT_WRITE);
    if (err != UC_ERR_OK) {
        fprintf(stderr, "[darwin_env] Error: Mapping heap failed: %d (%s)\n", err, uc_strerror(err));
        uc_close(env->uc);
        free(env);
        return NULL;
    }
    env->heap_cur = env->heap_base;

    /* 3. Setup TLS (Thread Local Storage): 64KB at 0x700000000000 */
    env->tls_addr = 0x700000000000ULL;
    env->tls_size = 0x10000ULL; /* 64 KB */
    err = uc_mem_map(env->uc, env->tls_addr, env->tls_size, UC_PROT_READ | UC_PROT_WRITE);
    if (err != UC_ERR_OK) {
        fprintf(stderr, "[darwin_env] Error: Mapping TLS failed: %d (%s)\n", err, uc_strerror(err));
        uc_close(env->uc);
        free(env);
        return NULL;
    }
    /* In Darwin pthread, pthread_t is the address of pthread structure (TPIDR_EL0) */
    /* Store self-pointer at offset 0 */
    darwin_env_write_mem(env, env->tls_addr, &env->tls_addr, 8);
    uc_reg_write(env->uc, UC_ARM64_REG_TPIDR_EL0, &env->tls_addr);

    /* 4. Setup Hook Trampoline page: 64KB at 0x500000000000 */
    env->hook_trampoline_base = 0x500000000000ULL;
    env->hook_trampoline_size = 0x10000ULL; /* 64 KB */
    err = uc_mem_map(env->uc, env->hook_trampoline_base, env->hook_trampoline_size,
                     UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC);
    if (err != UC_ERR_OK) {
        fprintf(stderr, "[darwin_env] Error: Mapping hook trampoline page failed: %d (%s)\n", err, uc_strerror(err));
        uc_close(env->uc);
        free(env);
        return NULL;
    }

    /* 5. Setup Magic Exit address to catch function return */
    env->magic_exit_addr = env->hook_trampoline_base + 0xf000ULL;
    /* Put an explicit ARM64 BRK #0 instruction at magic exit address */
    uint32_t brk_insn = 0xd4200000; /* BRK #0 */
    uc_mem_write(env->uc, env->magic_exit_addr, &brk_insn, sizeof(brk_insn));

    /* Initialize standard LibSystem hooks */
    darwin_hooks_init(env);

    env->is_initialized = true;
    return env;
}

void darwin_env_destroy(darwin_env_t *env) {
    if (!env) return;

    darwin_hooks_cleanup(env);

    if (env->uc) {
        uc_close(env->uc);
        env->uc = NULL;
    }

    free(env);
}

uint64_t darwin_env_malloc(darwin_env_t *env, size_t size) {
    if (!env || size == 0) return 0;

    /* 16-byte alignment as required by Darwin ARM64 ABI */
    size = (size + 15ULL) & ~15ULL;

    if (env->heap_cur + size > env->heap_base + env->heap_size) {
        fprintf(stderr, "[darwin_env] Out of memory in virtual heap (cur=0x%" PRIx64 ", req=%zu)\n",
                env->heap_cur, size);
        return 0;
    }

    uint64_t ptr = env->heap_cur;
    env->heap_cur += size;
    return ptr;
}

void darwin_env_free(darwin_env_t *env, uint64_t ptr) {
    (void)env;
    (void)ptr;
    /* Bump allocator does not free individual blocks */
}

int darwin_env_setup_thread(darwin_env_t *env, uint64_t entry_point) {
    if (!env || !env->uc) return -1;

    /* Set Stack Pointer (SP) */
    uc_reg_write(env->uc, UC_ARM64_REG_SP, &env->stack_top);

    /* Set Program Counter (PC) */
    uc_reg_write(env->uc, UC_ARM64_REG_PC, &entry_point);

    /* Set Link Register (LR / X30) to magic exit address */
    uc_reg_write(env->uc, UC_ARM64_REG_LR, &env->magic_exit_addr);

    /* Set TLS base register (TPIDR_EL0) */
    uc_reg_write(env->uc, UC_ARM64_REG_TPIDR_EL0, &env->tls_addr);

    return 0;
}

int darwin_env_read_string(darwin_env_t *env, uint64_t addr, char *buf, size_t max_len) {
    if (!env || !env->uc || !buf || max_len == 0 || addr == 0) {
        if (buf && max_len > 0) buf[0] = '\0';
        return -1;
    }

    size_t offset = 0;
    while (offset < max_len - 1) {
        char c = 0;
        uc_err err = uc_mem_read(env->uc, addr + offset, &c, 1);
        if (err != UC_ERR_OK) {
            buf[offset] = '\0';
            return -1;
        }
        buf[offset++] = c;
        if (c == '\0') break;
    }
    buf[offset] = '\0';
    return 0;
}

int darwin_env_write_string(darwin_env_t *env, uint64_t addr, const char *str) {
    if (!env || !env->uc || !str || addr == 0) return -1;
    size_t len = strlen(str) + 1;
    uc_err err = uc_mem_write(env->uc, addr, str, len);
    return (err == UC_ERR_OK) ? 0 : -1;
}

int darwin_env_read_mem(darwin_env_t *env, uint64_t addr, void *buf, size_t len) {
    if (!env || !env->uc || !buf || len == 0 || addr == 0) return -1;
    uc_err err = uc_mem_read(env->uc, addr, buf, len);
    return (err == UC_ERR_OK) ? 0 : -1;
}

int darwin_env_write_mem(darwin_env_t *env, uint64_t addr, const void *buf, size_t len) {
    if (!env || !env->uc || !buf || len == 0 || addr == 0) return -1;
    uc_err err = uc_mem_write(env->uc, addr, buf, len);
    return (err == UC_ERR_OK) ? 0 : -1;
}

uint64_t darwin_env_get_reg(darwin_env_t *env, int regid) {
    if (!env || !env->uc) return 0;
    uint64_t val = 0;
    uc_reg_read(env->uc, regid, &val);
    return val;
}

void darwin_env_set_reg(darwin_env_t *env, int regid, uint64_t val) {
    if (!env || !env->uc) return;
    uc_reg_write(env->uc, regid, &val);
}

void darwin_env_set_return(darwin_env_t *env, uint64_t ret_val) {
    darwin_env_set_reg(env, UC_ARM64_REG_X0, ret_val);
}

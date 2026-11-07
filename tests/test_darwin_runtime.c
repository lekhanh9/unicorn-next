#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

#include "../src/runtime/darwin_env.h"
#include "../src/runtime/hooks.h"
#include "../src/loader/macho.h"

int main(void) {
    printf("[TEST_RUNTIME] 1. Creating Darwin Emulation Environment...\n");
    darwin_env_t *env = darwin_env_create();
    assert(env != NULL && "darwin_env_create must succeed");
    assert(env->uc != NULL && "uc_engine must be initialized");

    /* Verify memory boundaries */
    printf("[TEST_RUNTIME] Stack: Base=0x%" PRIx64 ", Size=0x%" PRIx64 ", Top=0x%" PRIx64 "\n",
           env->stack_base, env->stack_size, env->stack_top);
    assert(env->stack_top % 16 == 0 && "SP must be 16-byte aligned");

    printf("[TEST_RUNTIME] Heap:  Base=0x%" PRIx64 ", Size=0x%" PRIx64 ", Cur=0x%" PRIx64 "\n",
           env->heap_base, env->heap_size, env->heap_cur);

    printf("[TEST_RUNTIME] TLS:   Addr=0x%" PRIx64 ", Size=0x%" PRIx64 "\n",
           env->tls_addr, env->tls_size);

    /* Verify TLS setup (TPIDR_EL0) */
    uint64_t tpidr = darwin_env_get_reg(env, UC_ARM64_REG_TPIDR_EL0);
    printf("[TEST_RUNTIME] TPIDR_EL0: 0x%" PRIx64 " (expected: 0x%" PRIx64 ")\n", tpidr, env->tls_addr);
    assert(tpidr == env->tls_addr && "TPIDR_EL0 must point to TLS block");

    /* 2. Test heap allocator */
    printf("[TEST_RUNTIME] 2. Testing virtual heap allocator...\n");
    uint64_t p1 = darwin_env_malloc(env, 64);
    uint64_t p2 = darwin_env_malloc(env, 128);
    printf("[TEST_RUNTIME] Allocated p1=0x%" PRIx64 ", p2=0x%" PRIx64 "\n", p1, p2);
    assert(p1 >= env->heap_base && p1 < env->heap_base + env->heap_size);
    assert(p2 >= env->heap_base && p2 < env->heap_base + env->heap_size);
    assert(p1 % 16 == 0 && p2 % 16 == 0 && "Heap allocations must be 16-byte aligned");
    assert(p2 >= p1 + 64 && "Heap allocations must not overlap");

    /* Test memory read/write helpers */
    const char *test_msg = "Hello macOS Emulation from Unicorn!";
    darwin_env_write_string(env, p1, test_msg);
    char read_msg[128] = {0};
    darwin_env_read_string(env, p1, read_msg, sizeof(read_msg));
    printf("[TEST_RUNTIME] Written & Read string: '%s'\n", read_msg);
    assert(strcmp(test_msg, read_msg) == 0 && "Memory read/write string must match");

    /* 3. Test Hook Lookup */
    printf("[TEST_RUNTIME] 3. Testing LibSystem hooks lookup...\n");
    uint64_t h_malloc = darwin_hooks_find(env, "malloc");
    uint64_t h_time = darwin_hooks_find(env, "mach_absolute_time");
    uint64_t h_sysctl = darwin_hooks_find(env, "sysctlbyname");
    printf("[TEST_RUNTIME] Trampolines: malloc=0x%" PRIx64 ", mach_absolute_time=0x%" PRIx64 ", sysctlbyname=0x%" PRIx64 "\n",
           h_malloc, h_time, h_sysctl);
    assert(h_malloc != 0 && "malloc hook must be registered");
    assert(h_time != 0 && "mach_absolute_time hook must be registered");
    assert(h_sysctl != 0 && "sysctlbyname hook must be registered");

    /* 4. Emulate ARM64 execution that calls malloc, saves to stack, calls mach_absolute_time, pops from stack */
    printf("[TEST_RUNTIME] 4. Setting up ARM64 guest code calling malloc & mach_absolute_time...\n");
    uint64_t code_addr = 0x10000000ULL;
    uc_err err = uc_mem_map(env->uc, code_addr, 0x10000, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC);
    assert(err == UC_ERR_OK && "Mapping code page must succeed");

    /*
     * Assembly Routine:
     *   0x00: stp x29, x30, [sp, #-16]!   (0xa9bf7bfd) -> push frame pointer & LR
     *   0x04: mov x0, #128                (0xd2801000)
     *   0x08: ldr x8, [pc, #48]           (0x58000188) -> loads malloc_trampoline at 0x38
     *   0x0c: blr x8                      (0xd63f0100) -> calls malloc(128)
     *   0x10: str x0, [sp, #-16]!         (0xf81f0fe0) -> push malloc_ptr to stack
     *   0x14: ldr x8, [pc, #44]           (0x58000168) -> loads time_trampoline at 0x40
     *   0x18: blr x8                      (0xd63f0100) -> calls mach_absolute_time()
     *   0x1c: ldr x1, [sp], #16           (0xf84107e1) -> pop malloc_ptr into x1
     *   0x20: ldp x29, x30, [sp], #16     (0xa8c17bfd) -> restore frame pointer & LR (magic_exit_addr)
     *   0x24: ret                         (0xd65f03c0) -> return to LR
     *   0x28..0x34: nops
     *   0x38: <64-bit malloc_trampoline>
     *   0x40: <64-bit time_trampoline>
     */
    uint32_t code_insns[] = {
        0xa9bf7bfd, /* stp x29, x30, [sp, #-16]! */
        0xd2801000, /* mov x0, #128 */
        0x58000188, /* ldr x8, [pc, #48] */
        0xd63f0100, /* blr x8 */
        0xf81f0fe0, /* str x0, [sp, #-16]! */
        0x58000168, /* ldr x8, [pc, #44] */
        0xd63f0100, /* blr x8 */
        0xf84107e1, /* ldr x1, [sp], #16 */
        0xa8c17bfd, /* ldp x29, x30, [sp], #16 */
        0xd65f03c0, /* ret */
        0xd503201f, /* nop */
        0xd503201f, /* nop */
        0xd503201f, /* nop */
        0xd503201f  /* nop */
    };
    darwin_env_write_mem(env, code_addr, code_insns, sizeof(code_insns));
    darwin_env_write_mem(env, code_addr + 0x38, &h_malloc, 8);
    darwin_env_write_mem(env, code_addr + 0x40, &h_time, 8);

    /* Setup CPU registers for execution */
    darwin_env_setup_thread(env, code_addr);

    printf("[TEST_RUNTIME] Starting CPU emulation...\n");
    err = uc_emu_start(env->uc, code_addr, env->magic_exit_addr, 0, 0);
    printf("[TEST_RUNTIME] Emulation stopped with: %d (%s)\n", err, uc_strerror(err));
    assert(err == UC_ERR_OK && "uc_emu_start must complete without error");

    /* Verify register results */
    uint64_t res_time = darwin_env_get_reg(env, UC_ARM64_REG_X0);
    uint64_t res_malloc_ptr = darwin_env_get_reg(env, UC_ARM64_REG_X1);
    uint64_t final_sp = darwin_env_get_reg(env, UC_ARM64_REG_SP);

    printf("[TEST_RUNTIME] Results:\n");
    printf("  X0 (mach_absolute_time): %" PRIu64 " ticks\n", res_time);
    printf("  X1 (malloc pointer):     0x%" PRIx64 "\n", res_malloc_ptr);
    printf("  SP (final):              0x%" PRIx64 " (initial: 0x%" PRIx64 ")\n", final_sp, env->stack_top);

    assert(res_time > 0 && "mach_absolute_time must return non-zero ticks");
    assert(res_malloc_ptr >= env->heap_base && res_malloc_ptr < env->heap_base + env->heap_size &&
           "malloc hook must return valid virtual heap pointer");
    assert(res_malloc_ptr % 16 == 0 && "Returned malloc pointer must be 16-byte aligned");
    assert(final_sp == env->stack_top && "Stack pointer must be properly balanced after push/pop");

    /* 5. Test sysctlbyname hook */
    printf("[TEST_RUNTIME] 5. Testing sysctlbyname('hw.model')...\n");
    uint64_t name_buf = darwin_env_malloc(env, 64);
    uint64_t out_buf = darwin_env_malloc(env, 64);
    uint64_t len_buf = darwin_env_malloc(env, 8);

    darwin_env_write_string(env, name_buf, "hw.model");
    size_t out_len = 64;
    darwin_env_write_mem(env, len_buf, &out_len, sizeof(out_len));

    darwin_env_set_reg(env, UC_ARM64_REG_X0, name_buf);
    darwin_env_set_reg(env, UC_ARM64_REG_X1, out_buf);
    darwin_env_set_reg(env, UC_ARM64_REG_X2, len_buf);

    darwin_env_setup_thread(env, h_sysctl);
    err = uc_emu_start(env->uc, h_sysctl, env->magic_exit_addr, 0, 0);
    assert(err == UC_ERR_OK && "sysctlbyname call must succeed");

    char model_str[64] = {0};
    darwin_env_read_string(env, out_buf, model_str, sizeof(model_str));
    printf("[TEST_RUNTIME] Emulated 'hw.model': '%s'\n", model_str);
    assert(strcmp(model_str, "MacBookPro18,1") == 0 && "hw.model must be MacBookPro18,1");

    /* Cleanup */
    darwin_env_destroy(env);
    printf("[TEST_RUNTIME] ALL CHECKS PASSED SUCCESSFULLY!\n");
    return 0;
}

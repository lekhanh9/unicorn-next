#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

#include "../src/runtime/darwin_env.h"
#include "../src/runtime/hooks.h"
#include "../src/mock/iokit.h"

int main(void) {
    printf("[TEST_IOKIT] 1. Initializing Darwin Environment...\n");
    darwin_env_t *env = darwin_env_create();
    assert(env != NULL && "darwin_env_create must succeed");

    printf("[TEST_IOKIT] 2. Initializing Mock IOKit with default MacBookPro profile...\n");
    int r = mock_iokit_init(env, NULL);
    assert(r == 0 && "mock_iokit_init must succeed");

    /* Verify trampolines registered */
    uint64_t h_prop = darwin_hooks_find(env, "IORegistryEntryCreateCFProperty");
    uint64_t h_match = darwin_hooks_find(env, "IOServiceGetMatchingService");
    printf("[TEST_IOKIT] IORegistryEntryCreateCFProperty = 0x%" PRIx64 "\n", h_prop);
    printf("[TEST_IOKIT] IOServiceGetMatchingService    = 0x%" PRIx64 "\n", h_match);
    assert(h_prop != 0 && "IORegistryEntryCreateCFProperty hook must exist");
    assert(h_match != 0 && "IOServiceGetMatchingService hook must exist");

    /* 3. Query 'model' property directly */
    printf("[TEST_IOKIT] 3. Testing 'model' property query...\n");
    uint64_t key_model = darwin_env_malloc(env, 32);
    darwin_env_write_string(env, key_model, "model");

    uint64_t prop_model = mock_IORegistryEntryCreateCFProperty(env, 1, key_model, 0, 0);
    assert(prop_model != 0 && "Property 'model' must be found");

    /* Check CFData: bytes at +16, length at +24 */
    uint64_t bytes_ptr = 0;
    uint64_t length = 0;
    darwin_env_read_mem(env, prop_model + 16, &bytes_ptr, 8);
    darwin_env_read_mem(env, prop_model + 24, &length, 8);

    char model_val[64] = {0};
    darwin_env_read_mem(env, bytes_ptr, model_val, length);
    printf("[TEST_IOKIT] 'model' value: '%s' (length: %" PRIu64 ")\n", model_val, length);
    assert(strcmp(model_val, "MacBookPro18,1") == 0 && "model must match MacBookPro18,1");

    /* 4. Query 'IOPlatformSerialNumber' */
    printf("[TEST_IOKIT] 4. Testing 'IOPlatformSerialNumber' property query...\n");
    uint64_t key_serial = darwin_env_malloc(env, 64);
    darwin_env_write_string(env, key_serial, "IOPlatformSerialNumber");

    uint64_t prop_serial = mock_IORegistryEntryCreateCFProperty(env, 1, key_serial, 0, 0);
    assert(prop_serial != 0 && "Property 'IOPlatformSerialNumber' must be found");

    darwin_env_read_mem(env, prop_serial + 16, &bytes_ptr, 8);
    darwin_env_read_mem(env, prop_serial + 24, &length, 8);

    char serial_val[64] = {0};
    darwin_env_read_mem(env, bytes_ptr, serial_val, length);
    printf("[TEST_IOKIT] 'IOPlatformSerialNumber': '%s' (length: %" PRIu64 ")\n", serial_val, length);
    assert(strcmp(serial_val, "C02G9012MD6R") == 0 && "serial must match profile");

    /* 5. Query 'board-id' */
    printf("[TEST_IOKIT] 5. Testing 'board-id' property query...\n");
    uint64_t key_board = darwin_env_malloc(env, 32);
    darwin_env_write_string(env, key_board, "board-id");

    uint64_t prop_board = mock_IORegistryEntryCreateCFProperty(env, 1, key_board, 0, 0);
    assert(prop_board != 0 && "Property 'board-id' must be found");

    darwin_env_read_mem(env, prop_board + 16, &bytes_ptr, 8);
    darwin_env_read_mem(env, prop_board + 24, &length, 8);

    char board_val[64] = {0};
    darwin_env_read_mem(env, bytes_ptr, board_val, length);
    printf("[TEST_IOKIT] 'board-id': '%s'\n", board_val);
    assert(strcmp(board_val, "Mac-E43C1C25D4880AD6") == 0 && "board-id must match profile");

    /* 6. Query 'chip-id' */
    printf("[TEST_IOKIT] 6. Testing 'chip-id' property query...\n");
    uint64_t key_chip = darwin_env_malloc(env, 32);
    darwin_env_write_string(env, key_chip, "chip-id");

    uint64_t prop_chip = mock_IORegistryEntryCreateCFProperty(env, 1, key_chip, 0, 0);
    assert(prop_chip != 0 && "Property 'chip-id' must be found");

    darwin_env_read_mem(env, prop_chip + 16, &bytes_ptr, 8);
    uint32_t chip_val = 0;
    darwin_env_read_mem(env, bytes_ptr, &chip_val, sizeof(chip_val));
    printf("[TEST_IOKIT] 'chip-id': 0x%04x (expected: 0x8103)\n", chip_val);
    assert(chip_val == 0x8103 && "chip-id must be 0x8103 (M1)");

    /* 7. Test CPU emulation calling IORegistryEntryCreateCFProperty via ARM64 BLR */
    printf("[TEST_IOKIT] 7. Emulating ARM64 call to IORegistryEntryCreateCFProperty...\n");
    uint64_t code_addr = 0x20000000ULL;
    uc_err err = uc_mem_map(env->uc, code_addr, 0x10000, UC_PROT_ALL);
    assert(err == UC_ERR_OK && "Mapping code page must succeed");

    /*
     * Assembly Routine:
     *   0x00: stp x29, x30, [sp, #-16]!
     *   0x04: mov x0, #1                  ; entry = 1
     *   0x08: ldr x1, [pc, #36]           ; load key_serial address from 0x30
     *   0x0c: mov x2, #0                  ; allocator = 0
     *   0x10: mov x3, #0                  ; options = 0
     *   0x14: ldr x8, [pc, #32]           ; load h_prop trampoline from 0x38
     *   0x18: blr x8                      ; call IORegistryEntryCreateCFProperty
     *   0x1c: ldp x29, x30, [sp], #16
     *   0x20: ret
     *   0x24..0x2c: nops
     *   0x30: <key_serial>
     *   0x38: <h_prop>
     */
    uint32_t asm_code[] = {
        0xa9bf7bfd, /* stp x29, x30, [sp, #-16]! */
        0xd2800020, /* mov x0, #1 */
        0x58000141, /* ldr x1, [pc, #40] -> 0x30 */
        0xd2800002, /* mov x2, #0 */
        0xd2800003, /* mov x3, #0 */
        0x58000128, /* ldr x8, [pc, #36] -> 0x38 */
        0xd63f0100, /* blr x8 */
        0xa8c17bfd, /* ldp x29, x30, [sp], #16 */
        0xd65f03c0, /* ret */
        0xd503201f, /* nop */
        0xd503201f, /* nop */
        0xd503201f  /* nop */
    };
    darwin_env_write_mem(env, code_addr, asm_code, sizeof(asm_code));
    darwin_env_write_mem(env, code_addr + 0x30, &key_serial, 8);
    darwin_env_write_mem(env, code_addr + 0x38, &h_prop, 8);

    darwin_env_setup_thread(env, code_addr);
    err = uc_emu_start(env->uc, code_addr, env->magic_exit_addr, 0, 0);
    assert(err == UC_ERR_OK && "uc_emu_start must succeed");

    uint64_t returned_cf = darwin_env_get_reg(env, UC_ARM64_REG_X0);
    printf("[TEST_IOKIT] Returned CFString from guest call: 0x%" PRIx64 "\n", returned_cf);
    assert(returned_cf != 0 && "Returned CFString must not be null");

    darwin_env_read_mem(env, returned_cf + 16, &bytes_ptr, 8);
    darwin_env_read_mem(env, returned_cf + 24, &length, 8);
    memset(serial_val, 0, sizeof(serial_val));
    darwin_env_read_mem(env, bytes_ptr, serial_val, length);
    printf("[TEST_IOKIT] Verified Serial from emulation: '%s'\n", serial_val);
    assert(strcmp(serial_val, "C02G9012MD6R") == 0 && "Emulation must return matching serial");

    darwin_env_destroy(env);
    printf("[TEST_IOKIT] ALL IOKIT TESTS PASSED SUCCESSFULLY!\n");
    return 0;
}

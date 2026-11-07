#include "iokit.h"
#include "../runtime/hooks.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#define GUEST_CFSTRING_FLAGS 0x07c8ULL
#define GUEST_CFDATA_FLAGS   0x07c8ULL

/* Global active hardware profile */
static mac_hardware_profile_t g_active_profile;
static bool g_profile_initialized = false;

/* Pre-defined default MacBookPro18,1 profile (M1 Pro) */
static const mac_hardware_profile_t s_default_macbook_profile = {
    .model         = "MacBookPro18,1",
    .serial_number = "C02G9012MD6R",
    .platform_uuid = "1E5B70A2-9E28-48F5-8D63-B8756314D8B2",
    .board_id      = "Mac-E43C1C25D4880AD6",
    .rom           = "\x00\x3e\xe1\xc4\x89\xa0", /* 6-byte raw MAC */
    .mlb           = "C021234567890123A",
    .chip_id       = 0x8103ULL
};

const mac_hardware_profile_t *mock_iokit_get_default_profile(void) {
    return &s_default_macbook_profile;
}

/*
 * Helper: Create a CFString-compatible object inside the emulator's virtual heap.
 * CFString struct layout (64-bit):
 *   [0x00] uint64_t isa;
 *   [0x08] uint64_t flags;
 *   [0x10] uint64_t str_ptr;
 *   [0x18] uint64_t length;
 */
static uint64_t iokit_create_guest_cfstring(darwin_env_t *env, const char *str) {
    if (!env || !str) return 0;
    size_t len = strlen(str);

    /* Allocate C-string in virtual heap */
    uint64_t str_addr = darwin_env_malloc(env, len + 1);
    darwin_env_write_string(env, str_addr, str);

    /* Allocate CFString struct (32 bytes) */
    uint64_t cf_addr = darwin_env_malloc(env, 32);

    uint64_t fields[4];
    fields[0] = 0;                     /* isa (0 or class reference) */
    fields[1] = GUEST_CFSTRING_FLAGS;  /* flags: ASCII, constant */
    fields[2] = str_addr;              /* buffer pointer */
    fields[3] = (uint64_t)len;         /* length */

    darwin_env_write_mem(env, cf_addr, fields, sizeof(fields));
    return cf_addr;
}

/*
 * Helper: Create a CFData-compatible object inside the emulator's virtual heap.
 * CFData struct layout (64-bit):
 *   [0x00] uint64_t isa;
 *   [0x08] uint64_t flags;
 *   [0x10] uint64_t bytes_ptr;
 *   [0x18] uint64_t length;
 */
static uint64_t iokit_create_guest_cfdata(darwin_env_t *env, const void *bytes, size_t len) {
    if (!env || !bytes || len == 0) return 0;

    /* Allocate buffer in virtual heap */
    uint64_t data_addr = darwin_env_malloc(env, len);
    darwin_env_write_mem(env, data_addr, bytes, len);

    /* Allocate CFData struct (32 bytes) */
    uint64_t cf_addr = darwin_env_malloc(env, 32);

    uint64_t fields[4];
    fields[0] = 0;                     /* isa */
    fields[1] = GUEST_CFDATA_FLAGS;    /* flags */
    fields[2] = data_addr;             /* bytes pointer */
    fields[3] = (uint64_t)len;         /* length */

    darwin_env_write_mem(env, cf_addr, fields, sizeof(fields));
    return cf_addr;
}

/*
 * Helper: Extract C string from guest CFString object or raw C-string pointer
 */
static bool iokit_extract_guest_string(darwin_env_t *env, uint64_t str_ptr, char *out_buf, size_t max_len) {
    if (!env || str_ptr == 0 || !out_buf || max_len == 0) return false;

    /*
     * Check if str_ptr is a valid CFString structure:
     *   [+0] isa
     *   [+8] flags (standard CFString flags typically have 0x07c0 or 0x07d0 in low 16 bits)
     *   [+16] cstr_ptr
     *   [+24] length
     */
    uint64_t flags = 0;
    uint64_t cstr_ptr = 0;
    uint64_t length = 0;
    if (darwin_env_read_mem(env, str_ptr + 8, &flags, 8) == 0 &&
        darwin_env_read_mem(env, str_ptr + 16, &cstr_ptr, 8) == 0 &&
        darwin_env_read_mem(env, str_ptr + 24, &length, 8) == 0) {
        uint16_t flag_lo = (uint16_t)(flags & 0xfff0);
        if ((flag_lo == 0x07c0 || flag_lo == 0x07d0 || flag_lo == 0x0780) &&
            cstr_ptr >= 0x10000ULL && length < max_len) {
            if (darwin_env_read_mem(env, cstr_ptr, out_buf, (size_t)length) == 0) {
                out_buf[length] = '\0';
                return true;
            }
        }
    }

    /* Fallback: treat str_ptr directly as a null-terminated C string */
    return (darwin_env_read_string(env, str_ptr, out_buf, max_len) == 0);
}

/* ========================================================================= */
/*                          Mock IOKit Functions                             */
/* ========================================================================= */

uint32_t mock_IOServiceGetMatchingService(darwin_env_t *env, uint32_t mainPort, uint64_t matchingDictPtr) {
    (void)env;
    (void)mainPort;
    (void)matchingDictPtr;
    /* Return dummy non-zero mach port handle for matching service (1 = IOPlatformExpertDevice) */
    return 1;
}

uint64_t mock_IORegistryEntryCreateCFProperty(darwin_env_t *env, uint32_t entry, uint64_t keyCFStringPtr,
                                              uint64_t allocator, uint32_t options) {
    (void)entry;
    (void)allocator;
    (void)options;

    char key[128] = {0};
    if (!iokit_extract_guest_string(env, keyCFStringPtr, key, sizeof(key))) {
        return 0;
    }

    const mac_hardware_profile_t *prof = g_profile_initialized ? &g_active_profile : &s_default_macbook_profile;

    /* 1. Model property */
    if (strcmp(key, "model") == 0) {
        /* Usually returned as CFData containing null-terminated string */
        return iokit_create_guest_cfdata(env, prof->model, strlen(prof->model) + 1);
    }

    /* 2. Serial number */
    if (strcmp(key, "IOPlatformSerialNumber") == 0 || strcmp(key, "serial-number") == 0) {
        return iokit_create_guest_cfstring(env, prof->serial_number);
    }

    /* 3. Platform UUID */
    if (strcmp(key, "IOPlatformUUID") == 0) {
        return iokit_create_guest_cfstring(env, prof->platform_uuid);
    }

    /* 4. Board ID */
    if (strcmp(key, "board-id") == 0) {
        return iokit_create_guest_cfdata(env, prof->board_id, strlen(prof->board_id) + 1);
    }

    /* 5. Main Logic Board (MLB) */
    if (strcmp(key, "MLB") == 0 || strcmp(key, "mlb") == 0) {
        return iokit_create_guest_cfstring(env, prof->mlb);
    }

    /* 6. ROM / MAC address */
    if (strcmp(key, "IOMACAddress") == 0 || strcmp(key, "mac-address") == 0 || strcmp(key, "ROM") == 0 || strcmp(key, "rom") == 0) {
        return iokit_create_guest_cfdata(env, prof->rom, 6);
    }

    /* 7. Chip ID (Apple Silicon) */
    if (strcmp(key, "chip-id") == 0) {
        uint32_t cid = (uint32_t)prof->chip_id;
        return iokit_create_guest_cfdata(env, &cid, sizeof(cid));
    }

    /* 8. Target Type */
    if (strcmp(key, "target-type") == 0) {
        const char *tt = "Mac";
        return iokit_create_guest_cfdata(env, tt, strlen(tt) + 1);
    }

    /* 9. Manufacturer */
    if (strcmp(key, "manufacturer") == 0) {
        const char *mfg = "Apple Inc.";
        return iokit_create_guest_cfstring(env, mfg);
    }

    return 0;
}

/* ========================================================================= */
/*                          IOKit Hook Handlers                              */
/* ========================================================================= */

static void hook_IOMasterPort(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    uint64_t master_port_ptr = darwin_env_get_reg(env, UC_ARM64_REG_X1);
    if (master_port_ptr) {
        uint32_t port = 1;
        darwin_env_write_mem(env, master_port_ptr, &port, sizeof(port));
    }
    darwin_env_set_return(env, 0); /* KERN_SUCCESS */
}

static void hook_IOMainPort(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    uint64_t main_port_ptr = darwin_env_get_reg(env, UC_ARM64_REG_X1);
    if (main_port_ptr) {
        uint32_t port = 1;
        darwin_env_write_mem(env, main_port_ptr, &port, sizeof(port));
    }
    darwin_env_set_return(env, 0); /* KERN_SUCCESS */
}

static void hook_IOServiceMatching(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    /* Returns a dummy matching dictionary handle (virtual pointer) */
    uint64_t dummy_dict = darwin_env_malloc(env, 16);
    darwin_env_set_return(env, dummy_dict);
}

static void hook_IOServiceNameMatching(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    uint64_t dummy_dict = darwin_env_malloc(env, 16);
    darwin_env_set_return(env, dummy_dict);
}

static void hook_IOServiceGetMatchingService(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    uint32_t main_port = (uint32_t)darwin_env_get_reg(env, UC_ARM64_REG_X0);
    uint64_t match_dict = darwin_env_get_reg(env, UC_ARM64_REG_X1);
    uint32_t service = mock_IOServiceGetMatchingService(env, main_port, match_dict);
    darwin_env_set_return(env, service);
}

static void hook_IOServiceGetMatchingServices(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    uint64_t iter_ptr = darwin_env_get_reg(env, UC_ARM64_REG_X2);
    if (iter_ptr) {
        uint32_t dummy_iter = 1;
        darwin_env_write_mem(env, iter_ptr, &dummy_iter, sizeof(dummy_iter));
    }
    darwin_env_set_return(env, 0); /* KERN_SUCCESS */
}

static void hook_IOIteratorNext(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    static int s_iter_count = 0;
    if (s_iter_count++ == 0) {
        darwin_env_set_return(env, 1); /* Return 1 service first time */
    } else {
        s_iter_count = 0;
        darwin_env_set_return(env, 0); /* End of iterator */
    }
}

static void hook_IORegistryEntryCreateCFProperty(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    uint32_t entry = (uint32_t)darwin_env_get_reg(env, UC_ARM64_REG_X0);
    uint64_t key_ptr = darwin_env_get_reg(env, UC_ARM64_REG_X1);
    uint64_t allocator = darwin_env_get_reg(env, UC_ARM64_REG_X2);
    uint32_t options = (uint32_t)darwin_env_get_reg(env, UC_ARM64_REG_X3);

    uint64_t prop = mock_IORegistryEntryCreateCFProperty(env, entry, key_ptr, allocator, options);
    darwin_env_set_return(env, prop);
}

static void hook_IOObjectRelease(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    darwin_env_set_return(env, 0); /* KERN_SUCCESS */
}

static void hook_IOObjectRetain(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    darwin_env_set_return(env, 0); /* KERN_SUCCESS */
}

static void hook_IOServiceOpen(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    uint64_t conn_ptr = darwin_env_get_reg(env, UC_ARM64_REG_X3);
    if (conn_ptr) {
        uint32_t conn = 1;
        darwin_env_write_mem(env, conn_ptr, &conn, sizeof(conn));
    }
    darwin_env_set_return(env, 0); /* KERN_SUCCESS */
}

static void hook_IOServiceClose(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    darwin_env_set_return(env, 0); /* KERN_SUCCESS */
}

static void hook_IOConnectCallMethod(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    darwin_env_set_return(env, 0); /* KERN_SUCCESS */
}

static void hook_IOConnectCallStructMethod(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    darwin_env_set_return(env, 0); /* KERN_SUCCESS */
}

int mock_iokit_init(darwin_env_t *env, const mac_hardware_profile_t *profile) {
    if (!env) return -1;

    if (profile) {
        g_active_profile = *profile;
        g_profile_initialized = true;
    } else {
        g_active_profile = s_default_macbook_profile;
        g_profile_initialized = true;
    }

    /* Register IOKit hook trampolines */
    darwin_hooks_register(env, "IOMasterPort", hook_IOMasterPort);
    darwin_hooks_register(env, "IOMainPort", hook_IOMainPort);
    darwin_hooks_register(env, "IOServiceMatching", hook_IOServiceMatching);
    darwin_hooks_register(env, "IOServiceNameMatching", hook_IOServiceNameMatching);
    darwin_hooks_register(env, "IOServiceGetMatchingService", hook_IOServiceGetMatchingService);
    darwin_hooks_register(env, "IOServiceGetMatchingServices", hook_IOServiceGetMatchingServices);
    darwin_hooks_register(env, "IOIteratorNext", hook_IOIteratorNext);
    darwin_hooks_register(env, "IORegistryEntryCreateCFProperty", hook_IORegistryEntryCreateCFProperty);
    darwin_hooks_register(env, "IOObjectRelease", hook_IOObjectRelease);
    darwin_hooks_register(env, "IOObjectRetain", hook_IOObjectRetain);
    darwin_hooks_register(env, "IOServiceOpen", hook_IOServiceOpen);
    darwin_hooks_register(env, "IOServiceClose", hook_IOServiceClose);
    darwin_hooks_register(env, "IOConnectCallMethod", hook_IOConnectCallMethod);
    darwin_hooks_register(env, "IOConnectCallStructMethod", hook_IOConnectCallStructMethod);

    return 0;
}

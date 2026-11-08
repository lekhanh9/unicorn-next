#include "iokit.h"
#if __has_include("../runtime/hooks.h")
#include "../runtime/hooks.h"
#else
#include "hooks.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>

#define GUEST_CFSTRING_FLAGS 0x07c8ULL
#define GUEST_CFDATA_FLAGS   0x07c8ULL

/* Global active hardware profile */
static mac_hardware_profile_t g_active_profile;
static bool g_profile_initialized = false;

/*
 * Table of genuine Apple Silicon Mac hardware models
 */
typedef struct mac_model_template {
    const char *model;
    const char *board_id;
    uint64_t chip_id;
    const char *serial_model_code;
    const char *os_version;
    const char *os_build;
    const char *darwin_version;
    const char *cfnetwork_version;
    const char *xcode_version;
} mac_model_template_t;

static const mac_model_template_t s_mac_templates[] = {
    {
        .model             = "MacBookPro18,1",
        .board_id          = "Mac-E43C1C25D4880AD6",
        .chip_id           = 0x8103ULL,
        .serial_model_code = "MD6R",
        .os_version        = "13.5",
        .os_build          = "22G90",
        .darwin_version    = "22.6.0",
        .cfnetwork_version = "1410.0.3",
        .xcode_version     = "14.3.1"
    },
    {
        .model             = "MacBookAir10,1",
        .board_id          = "Mac-B4831CEBD52A0C4C",
        .chip_id           = 0x8103ULL,
        .serial_model_code = "Q6LR",
        .os_version        = "13.5",
        .os_build          = "22G90",
        .darwin_version    = "22.6.0",
        .cfnetwork_version = "1410.0.3",
        .xcode_version     = "14.3.1"
    },
    {
        .model             = "Macmini9,1",
        .board_id          = "Mac-7BA5B2D9E42DDD94",
        .chip_id           = 0x8103ULL,
        .serial_model_code = "J5X6",
        .os_version        = "13.5",
        .os_build          = "22G90",
        .darwin_version    = "22.6.0",
        .cfnetwork_version = "1410.0.3",
        .xcode_version     = "14.3.1"
    },
    {
        .model             = "Mac14,2",
        .board_id          = "Mac-5F9802EFE386AA28",
        .chip_id           = 0x8112ULL,
        .serial_model_code = "LK12",
        .os_version        = "14.4.1",
        .os_build          = "23E224",
        .darwin_version    = "23.4.0",
        .cfnetwork_version = "1494.0.7",
        .xcode_version     = "15.3"
    },
    {
        .model             = "Mac15,3",
        .board_id          = "Mac-937CB26E2E02BB01",
        .chip_id           = 0x8122ULL,
        .serial_model_code = "N83K",
        .os_version        = "14.5",
        .os_build          = "23F79",
        .darwin_version    = "23.5.0",
        .cfnetwork_version = "1496.0.7",
        .xcode_version     = "15.4"
    }
};

#define NUM_TEMPLATES (sizeof(s_mac_templates) / sizeof(s_mac_templates[0]))

/* Simple PRNG state based on seed */
typedef struct {
    uint64_t state;
} prng_t;

static inline uint32_t prng_next(prng_t *p) {
    p->state = p->state * 6364136223846793005ULL + 1442695040888963407ULL;
    return (uint32_t)(p->state >> 32);
}

static inline char prng_alphanum(prng_t *p) {
    static const char charset[] = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZ"; // exclude I, O
    return charset[prng_next(p) % (sizeof(charset) - 1)];
}

int mock_iokit_create_profile(mac_hardware_profile_t *out_profile, const char *seed) {
    if (!out_profile) return -1;
    memset(out_profile, 0, sizeof(mac_hardware_profile_t));

    prng_t rng;
    if (seed && seed[0] != '\0') {
        /* FNV-1a 64-bit hash of seed */
        uint64_t h = 0xcbf29ce484222325ULL;
        for (const char *s = seed; *s; s++) {
            h ^= (uint64_t)(unsigned char)*s;
            h *= 0x100000001b3ULL;
        }
        rng.state = h;
    } else {
        rng.state = (uint64_t)time(NULL) ^ 0x9e3779b97f4a7c15ULL;
    }

    /* Pick a template */
    const mac_model_template_t *tmpl = &s_mac_templates[prng_next(&rng) % NUM_TEMPLATES];

    snprintf(out_profile->model, sizeof(out_profile->model), "%s", tmpl->model);
    snprintf(out_profile->board_id, sizeof(out_profile->board_id), "%s", tmpl->board_id);
    out_profile->chip_id = tmpl->chip_id;
    snprintf(out_profile->os_version, sizeof(out_profile->os_version), "%s", tmpl->os_version);
    snprintf(out_profile->os_build, sizeof(out_profile->os_build), "%s", tmpl->os_build);
    snprintf(out_profile->darwin_version, sizeof(out_profile->darwin_version), "%s", tmpl->darwin_version);

    /* Generate realistic Serial Number: C02 + 4 chars + model_code (11-12 chars) */
    out_profile->serial_number[0] = 'C';
    out_profile->serial_number[1] = '0';
    out_profile->serial_number[2] = '2';
    for (int i = 0; i < 4; i++) {
        out_profile->serial_number[3 + i] = prng_alphanum(&rng);
    }
    snprintf(out_profile->serial_number + 7, sizeof(out_profile->serial_number) - 7, "%s", tmpl->serial_model_code);

    /* Generate Main Logic Board (MLB) Serial Number: C02 + 14 chars */
    out_profile->mlb[0] = 'C';
    out_profile->mlb[1] = '0';
    out_profile->mlb[2] = '2';
    for (int i = 0; i < 14; i++) {
        out_profile->mlb[3 + i] = prng_alphanum(&rng);
    }
    out_profile->mlb[17] = '\0';

    /* Generate Hardware Platform UUID: 8-4-4-4-12 */
    static const char hexchars[] = "0123456789ABCDEF";
    char uuid_buf[64];
    int idx = 0;
    for (int i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            uuid_buf[idx++] = '-';
        } else if (i == 14) {
            uuid_buf[idx++] = '4'; // UUID v4
        } else if (i == 19) {
            uuid_buf[idx++] = hexchars[(prng_next(&rng) & 0x3) | 0x8]; // variant
        } else {
            uuid_buf[idx++] = hexchars[prng_next(&rng) & 0xf];
        }
    }
    uuid_buf[idx] = '\0';
    snprintf(out_profile->platform_uuid, sizeof(out_profile->platform_uuid), "%s", uuid_buf);

    /* Generate ROM / MAC address with Apple OUI (00:3E:E1) */
    out_profile->rom[0] = 0x00;
    out_profile->rom[1] = 0x3e;
    out_profile->rom[2] = 0xe1;
    out_profile->rom[3] = (unsigned char)(prng_next(&rng) & 0xff);
    out_profile->rom[4] = (unsigned char)(prng_next(&rng) & 0xff);
    out_profile->rom[5] = (unsigned char)(prng_next(&rng) & 0xff);

    /* Build matching X-MMe-Client-Info: <Model> <Mac OS X;VERSION;BUILD> <com.apple.AuthKit/1 (com.apple.dt.Xcode/XCODE)> */
    snprintf(out_profile->client_info, sizeof(out_profile->client_info),
             "<%s> <Mac OS X;%s;%s> <com.apple.AuthKit/1 (com.apple.dt.Xcode/%s)>",
             tmpl->model, tmpl->os_version, tmpl->os_build, tmpl->xcode_version);

    /* Build matching User-Agent: akd/1.0 CFNetwork/VERSION Darwin/VERSION */
    snprintf(out_profile->user_agent, sizeof(out_profile->user_agent),
             "akd/1.0 CFNetwork/%s Darwin/%s",
             tmpl->cfnetwork_version, tmpl->darwin_version);

    return 0;
}

const mac_hardware_profile_t *mock_iokit_get_current_profile(void) {
    if (!g_profile_initialized) {
        mock_iokit_create_profile(&g_active_profile, "default_seed");
        g_profile_initialized = true;
    }
    return &g_active_profile;
}

/*
 * Helper: Create a CFString-compatible object inside the emulator's virtual heap.
 */
static uint64_t iokit_create_guest_cfstring(darwin_env_t *env, const char *str) {
    if (!env || !str) return 0;
    size_t len = strlen(str);

    uint64_t str_addr = darwin_env_malloc(env, len + 1);
    darwin_env_write_string(env, str_addr, str);

    uint64_t cf_addr = darwin_env_malloc(env, 32);

    uint64_t fields[4];
    fields[0] = 0;                     /* isa */
    fields[1] = GUEST_CFSTRING_FLAGS;  /* flags: ASCII, constant */
    fields[2] = str_addr;              /* buffer pointer */
    fields[3] = (uint64_t)len;         /* length */

    darwin_env_write_mem(env, cf_addr, fields, sizeof(fields));
    return cf_addr;
}

/*
 * Helper: Create a CFData-compatible object inside the emulator's virtual heap.
 */
static uint64_t iokit_create_guest_cfdata(darwin_env_t *env, const void *bytes, size_t len) {
    if (!env || !bytes || len == 0) return 0;

    uint64_t data_addr = darwin_env_malloc(env, len);
    darwin_env_write_mem(env, data_addr, bytes, len);

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

    const mac_hardware_profile_t *prof = mock_iokit_get_current_profile();

    /* 1. Model property */
    if (strcmp(key, "model") == 0) {
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
    darwin_env_set_return(env, 0);
}

static void hook_IOMainPort(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    uint64_t main_port_ptr = darwin_env_get_reg(env, UC_ARM64_REG_X1);
    if (main_port_ptr) {
        uint32_t port = 1;
        darwin_env_write_mem(env, main_port_ptr, &port, sizeof(port));
    }
    darwin_env_set_return(env, 0);
}

static void hook_IOServiceMatching(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
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
    darwin_env_set_return(env, 0);
}

static void hook_IOIteratorNext(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    static int s_iter_count = 0;
    if (s_iter_count++ == 0) {
        darwin_env_set_return(env, 1);
    } else {
        s_iter_count = 0;
        darwin_env_set_return(env, 0);
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
    darwin_env_set_return(env, 0);
}

static void hook_IOObjectRetain(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    darwin_env_set_return(env, 0);
}

static void hook_IOServiceOpen(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    uint64_t conn_ptr = darwin_env_get_reg(env, UC_ARM64_REG_X3);
    if (conn_ptr) {
        uint32_t conn = 1;
        darwin_env_write_mem(env, conn_ptr, &conn, sizeof(conn));
    }
    darwin_env_set_return(env, 0);
}

static void hook_IOServiceClose(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    darwin_env_set_return(env, 0);
}

static void hook_IOConnectCallMethod(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    darwin_env_set_return(env, 0);
}

static void hook_IOConnectCallStructMethod(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    darwin_env_set_return(env, 0);
}

int mock_iokit_init(darwin_env_t *env, const mac_hardware_profile_t *profile) {
    if (!env) return -1;

    if (profile) {
        g_active_profile = *profile;
        g_profile_initialized = true;
    } else if (!g_profile_initialized) {
        mock_iokit_create_profile(&g_active_profile, NULL);
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

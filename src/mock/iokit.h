#ifndef MOCK_IOKIT_H
#define MOCK_IOKIT_H

#include <stdint.h>
#include <stdbool.h>
#include "../runtime/darwin_env.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Virtual Hardware Device Identity Profile
 */
typedef struct mac_hardware_profile {
    char model[32];             /* e.g. "MacBookPro18,1" */
    char serial_number[32];     /* e.g. "C02G1234MD6R" */
    char platform_uuid[64];     /* Hardware UUID */
    char board_id[32];          /* Mac board ID, e.g. "Mac-E43C1C25D4880AD6" */
    unsigned char rom[6];       /* Primary MAC address / ROM bytes (6 bytes) */
    char mlb[32];               /* Main Logic Board serial number */
    uint64_t chip_id;           /* Apple Silicon Chip ID (0x8103, 0x8112, etc.) */
    char os_version[16];        /* e.g. "13.5" or "14.4.1" */
    char os_build[16];          /* e.g. "22G90" or "23E224" */
    char darwin_version[16];    /* e.g. "22.6.0" or "23.4.0" */
    char client_info[256];      /* Matching X-MMe-Client-Info */
    char user_agent[256];       /* Matching User-Agent */
} mac_hardware_profile_t;

/**
 * Generate a randomized but realistic Mac hardware profile.
 * If seed is non-null, the profile is deterministically derived from the seed,
 * ensuring consistent identity across app launches on the same device.
 */
int mock_iokit_create_profile(mac_hardware_profile_t *out_profile, const char *seed);

/**
 * Initialize IOKit mock registry with given hardware identity.
 * If profile is NULL, automatically derives/creates a profile.
 */
int mock_iokit_init(darwin_env_t *env, const mac_hardware_profile_t *profile);

/**
 * Get the currently active profile in the mock registry.
 */
const mac_hardware_profile_t *mock_iokit_get_current_profile(void);

/**
 * Mock implementation of IOServiceGetMatchingService
 */
uint32_t mock_IOServiceGetMatchingService(darwin_env_t *env, uint32_t mainPort, uint64_t matchingDictPtr);

/**
 * Mock implementation of IORegistryEntryCreateCFProperty
 */
uint64_t mock_IORegistryEntryCreateCFProperty(darwin_env_t *env, uint32_t entry, uint64_t keyCFStringPtr, uint64_t allocator, uint32_t options);

#ifdef __cplusplus
}
#endif

#endif /* MOCK_IOKIT_H */

#ifndef MOCK_IOKIT_H
#define MOCK_IOKIT_H

#include <stdint.h>
#include <stdbool.h>
#include "../runtime/darwin_env.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Virtual Hardware Device Identity (MacBookPro18,1 by default)
 */
typedef struct mac_hardware_profile {
    const char *model;          /* e.g. "MacBookPro18,1" */
    const char *serial_number;  /* e.g. "C02XYZ123456" */
    const char *platform_uuid;  /* Hardware UUID */
    const char *board_id;       /* Mac board ID, e.g. "Mac-E43C1C25D4880AD6" */
    const char *rom;            /* Primary MAC address / ROM bytes */
    const char *mlb;            /* Main Logic Board serial number */
    uint64_t chip_id;           /* Apple Silicon Chip ID (T8103 / M1) */
} mac_hardware_profile_t;

/**
 * Initialize IOKit mock registry with given hardware identity.
 */
int mock_iokit_init(darwin_env_t *env, const mac_hardware_profile_t *profile);

/**
 * Get default MacBookPro profile for emulation.
 */
const mac_hardware_profile_t *mock_iokit_get_default_profile(void);

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

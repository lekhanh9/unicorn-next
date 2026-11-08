#ifndef API_ANISETTE_H
#define API_ANISETTE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Anisette Headers output structure for Apple ID authentication
 */
typedef struct anisette_headers {
    char *x_apple_i_md;         /* Base64 OTP machine data */
    char *x_apple_i_md_m;       /* Base64 machine identifier */
    char *x_apple_i_md_rinfo;   /* Routing info */
    char *x_apple_i_md_lu;      /* Local user ID */
    char *x_apple_i_timezone;   /* Timezone string */
    char *x_apple_i_locale;     /* Locale string */
    char *x_apple_i_client_time;/* ISO8601 formatted client timestamp */
    char *x_mme_client_info;    /* Matching X-MMe-Client-Info */
    char *user_agent;           /* Matching User-Agent */
} anisette_headers_t;

/**
 * Initialize the MacAuth emulation engine, load AuthKit / AppleIDAuthSupport.
 *
 * @param authkit_path Path to AuthKit binary.
 * @param aidauth_path Path to AppleIDAuthSupport binary.
 * @return 0 on success, negative error code on failure.
 */
int macauth_init(const char *authkit_path, const char *aidauth_path);

/**
 * Clean up emulator engine and resources.
 */
void macauth_cleanup(void);

/**
 * Generate fresh Anisette headers for Apple ID requests.
 *
 * @param out_headers Output structure populated with newly generated header strings.
 * @return 0 on success, negative error code on failure.
 */
int macauth_fetch_anisette_headers(anisette_headers_t *out_headers);

/**
 * Free resources allocated inside an anisette_headers_t struct.
 */
void macauth_free_anisette_headers(anisette_headers_t *headers);

/**
 * Run ADIProvisioningStart in the emulated akd engine.
 *
 * @param spim Server Provisioning Information Message (can be NULL if none).
 * @param spim_len Length of spim buffer.
 * @param out_cpim Allocated client data output buffer (caller frees).
 * @param out_cpim_len Length of out_cpim.
 * @param out_session Returned session identifier.
 * @return 0 on success, or negative error code.
 */
int macauth_start_provision(const uint8_t *spim, uint32_t spim_len, uint8_t **out_cpim, uint32_t *out_cpim_len, uint32_t *out_session);

/**
 * Run ADIProvisioningEnd in the emulated akd engine.
 *
 * @param session Session identifier from start_provision.
 * @param ptm Server response PTM buffer.
 * @param ptm_len Length of ptm buffer.
 * @param out_routing Allocated routing info buffer (caller frees).
 * @param out_routing_len Length of routing info.
 * @return 0 on success, or negative error code.
 */
int macauth_end_provision(uint32_t session, const uint8_t *ptm, uint32_t ptm_len, uint8_t **out_routing, uint32_t *out_routing_len);

/**
 * Encode raw bytes to Base64 string. Caller frees result with free().
 */
char *macauth_base64_encode(const unsigned char *src, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* API_ANISETTE_H */

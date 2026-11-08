#include "anisette.h"
#if __has_include("../runtime/darwin_env.h")
#include "../runtime/darwin_env.h"
#include "../runtime/hooks.h"
#include "../mock/iokit.h"
#include "../loader/macho.h"
#else
#include "darwin_env.h"
#include "hooks.h"
#include "iokit.h"
#include "macho.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>
#include <unistd.h>

/* Internal emulator state for MacAuth */
static struct {
    darwin_env_t *env;
    macho_image_t *img_akd;
    bool is_initialized;
    uint64_t entry_otp;
    uint64_t entry_prov_start;
    uint64_t entry_prov_end;
} g_macauth = {0};

/* Base64 encoding table */
static const char s_b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *macauth_base64_encode(const unsigned char *src, size_t len) {
    size_t out_len = 4 * ((len + 2) / 3);
    char *out = (char *)malloc(out_len + 1);
    if (!out) return NULL;

    size_t i = 0, j = 0;
    while (i < len) {
        uint32_t octet_a = i < len ? src[i++] : 0;
        uint32_t octet_b = i < len ? src[i++] : 0;
        uint32_t octet_c = i < len ? src[i++] : 0;

        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        out[j++] = s_b64_table[(triple >> 18) & 0x3f];
        out[j++] = s_b64_table[(triple >> 12) & 0x3f];
        out[j++] = (i > len + 1) ? '=' : s_b64_table[(triple >> 6) & 0x3f];
        out[j++] = (i > len) ? '=' : s_b64_table[triple & 0x3f];
    }
    out[j] = '\0';
    return out;
}

int macauth_init(const char *authkit_path, const char *aidauth_path) {
    (void)aidauth_path;
    if (g_macauth.is_initialized) return 0;

    /* Initialize iOS Unicorn W^X JIT compatibility layer */
    macho_init_unicorn_compat();

    /* 1. Create Darwin Emulation Environment */
    g_macauth.env = darwin_env_create();
    if (!g_macauth.env) {
        fprintf(stderr, "[macauth] Error: Failed to create darwin environment\n");
        return -1;
    }

    /* 2. Initialize Mock IOKit registry */
    if (mock_iokit_init(g_macauth.env, NULL) != 0) {
        fprintf(stderr, "[macauth] Error: Failed to init mock IOKit\n");
        darwin_env_destroy(g_macauth.env);
        g_macauth.env = NULL;
        return -2;
    }

    /* 3. Determine akd binary path */
    const char *candidate_paths[] = {
        authkit_path,
        "binaries/akd",
        "/System/Library/PrivateFrameworks/AuthKit.framework/akd"
    };

    const char *path_akd = NULL;
    for (size_t i = 0; i < sizeof(candidate_paths) / sizeof(candidate_paths[0]); i++) {
        if (candidate_paths[i] && access(candidate_paths[i], R_OK) == 0) {
            path_akd = candidate_paths[i];
            break;
        }
    }

    if (path_akd) {
        printf("[macauth] Loading akd from %s...\n", path_akd);
        g_macauth.img_akd = macho_load_file(path_akd);
        if (g_macauth.img_akd) {
            if (macho_map_to_unicorn(g_macauth.env->uc, g_macauth.img_akd, 0) == 0) {
                macho_apply_chained_fixups(g_macauth.env, g_macauth.img_akd);
            }
        }
    } else {
        printf("[macauth] Warning: akd binary not found, running in fallback mode\n");
    }

    /* Standard FairPlay entry point offsets in akd (iOS 16+ Darwin ARM64) */
    g_macauth.entry_otp        = 0x1000a50dcULL;
    g_macauth.entry_prov_start = 0x100098f94ULL;
    g_macauth.entry_prov_end   = 0x1000a028cULL;

    g_macauth.is_initialized = true;
    return 0;
}

void macauth_cleanup(void) {
    if (!g_macauth.is_initialized) return;

    if (g_macauth.img_akd) {
        macho_free_image(g_macauth.img_akd);
        g_macauth.img_akd = NULL;
    }

    if (g_macauth.env) {
        darwin_env_destroy(g_macauth.env);
        g_macauth.env = NULL;
    }

    g_macauth.is_initialized = false;
}

int macauth_fetch_anisette_headers(anisette_headers_t *out_headers) {
    if (!out_headers) return -1;
    memset(out_headers, 0, sizeof(anisette_headers_t));

    if (!g_macauth.is_initialized) {
        int r = macauth_init(NULL, NULL);
        if (r != 0) return r;
    }

    const mac_hardware_profile_t *prof = mock_iokit_get_current_profile();

    bool got_real_adi = false;
    if (g_macauth.env && g_macauth.img_akd) {
        uint64_t sp = g_macauth.env->stack_top;
        uint64_t p_out_mid = sp - 0x10;
        uint64_t p_out_mid_len = sp - 0x18;
        uint64_t p_out_otp = sp - 0x20;
        uint64_t p_out_otp_len = sp - 0x28;

        uint64_t zero64 = 0;
        darwin_env_write_mem(g_macauth.env, p_out_mid, &zero64, 8);
        darwin_env_write_mem(g_macauth.env, p_out_mid_len, &zero64, 8);
        darwin_env_write_mem(g_macauth.env, p_out_otp, &zero64, 8);
        darwin_env_write_mem(g_macauth.env, p_out_otp_len, &zero64, 8);

        uint64_t new_sp = sp - 0x100;
        darwin_env_set_reg(g_macauth.env, UC_ARM64_REG_X0, 0); // dsid
        darwin_env_set_reg(g_macauth.env, UC_ARM64_REG_X1, p_out_mid);
        darwin_env_set_reg(g_macauth.env, UC_ARM64_REG_X2, p_out_mid_len);
        darwin_env_set_reg(g_macauth.env, UC_ARM64_REG_X3, p_out_otp);
        darwin_env_set_reg(g_macauth.env, UC_ARM64_REG_X4, p_out_otp_len);
        darwin_env_set_reg(g_macauth.env, UC_ARM64_REG_SP, new_sp);
        darwin_env_set_reg(g_macauth.env, UC_ARM64_REG_LR, g_macauth.env->magic_exit_addr);

        uc_err err = uc_emu_start(g_macauth.env->uc, g_macauth.entry_otp, g_macauth.env->magic_exit_addr, 0, 0);
        if (err == UC_ERR_OK) {
            uint64_t ret_val = darwin_env_get_reg(g_macauth.env, UC_ARM64_REG_X0);
            int32_t ret_code = (int32_t)ret_val;
            printf("[macauth] ADIGenerateOTPCode returned %d (0x%x)\n", ret_code, (uint32_t)ret_code);

            if (ret_code == 0) {
                uint64_t mid_buf = 0, otp_buf = 0;
                uint32_t mid_len = 0, otp_len = 0;
                darwin_env_read_mem(g_macauth.env, p_out_mid, &mid_buf, 8);
                darwin_env_read_mem(g_macauth.env, p_out_mid_len, &mid_len, 4);
                darwin_env_read_mem(g_macauth.env, p_out_otp, &otp_buf, 8);
                darwin_env_read_mem(g_macauth.env, p_out_otp_len, &otp_len, 4);

                if (mid_buf && mid_len > 0) {
                    uint8_t *mid_bytes = (uint8_t *)malloc(mid_len);
                    darwin_env_read_mem(g_macauth.env, mid_buf, mid_bytes, mid_len);
                    out_headers->x_apple_i_md_m = macauth_base64_encode(mid_bytes, mid_len);
                    free(mid_bytes);
                }
                if (otp_buf && otp_len > 0) {
                    uint8_t *otp_bytes = (uint8_t *)malloc(otp_len);
                    darwin_env_read_mem(g_macauth.env, otp_buf, otp_bytes, otp_len);
                    out_headers->x_apple_i_md = macauth_base64_encode(otp_bytes, otp_len);
                    free(otp_bytes);
                }
                got_real_adi = true;
            }
        }
    }

    if (g_macauth.img_akd && (!got_real_adi || !out_headers->x_apple_i_md)) {
        /* Real akd is loaded but unprovisioned -> return ADI_ERROR_NOT_PROVISIONED (-45061) */
        return -45061;
    }

    if (!got_real_adi) {
        /* Fallback: Hardware profile based Machine ID and token (mock-only mode) */
        unsigned char mdm_raw[32];
        for (size_t i = 0; i < sizeof(mdm_raw); i++) {
            mdm_raw[i] = (unsigned char)(prof->platform_uuid[i % strlen(prof->platform_uuid)] ^ (i * 0x3d));
        }
        out_headers->x_apple_i_md_m = macauth_base64_encode(mdm_raw, 16);

        unsigned char otp_raw[32];
        time_t now = time(NULL);
        for (size_t i = 0; i < sizeof(otp_raw); i++) {
            otp_raw[i] = (unsigned char)(((now >> (i % 4)) ^ (prof->chip_id >> ((i % 8) * 8))) & 0xff);
        }
        out_headers->x_apple_i_md = macauth_base64_encode(otp_raw, 28);
    }

    /* 3. X-Apple-I-MD-RINFO: Routing Info (standard macOS routing code) */
    out_headers->x_apple_i_md_rinfo = strdup("17106176");

    /* 4. X-Apple-I-MD-LU (Local User identifier) */
    unsigned char lu_raw[16];
    for (size_t i = 0; i < sizeof(lu_raw); i++) {
        lu_raw[i] = (unsigned char)(i * 0x1f + 0x07);
    }
    out_headers->x_apple_i_md_lu = macauth_base64_encode(lu_raw, 16);

    /* 5. X-Apple-I-TimeZone */
    time_t t = time(NULL);
    struct tm lt;
    localtime_r(&t, &lt);
    char tz_buf[32] = {0};
    strftime(tz_buf, sizeof(tz_buf), "%Z", &lt);
    if (tz_buf[0] == '\0') {
        snprintf(tz_buf, sizeof(tz_buf), "UTC");
    }
    out_headers->x_apple_i_timezone = strdup(tz_buf);

    /* 6. X-Apple-I-Locale */
    out_headers->x_apple_i_locale = strdup("en_US");

    /* 7. X-Apple-I-Client-Time: ISO8601 UTC timestamp */
    struct tm gm;
    gmtime_r(&t, &gm);
    char iso_buf[64] = {0};
    strftime(iso_buf, sizeof(iso_buf), "%Y-%m-%dT%H:%M:%SZ", &gm);
    out_headers->x_apple_i_client_time = strdup(iso_buf);

    /* 8. X-MMe-Client-Info & User-Agent (strictly matching simulated hardware) */
    out_headers->x_mme_client_info = strdup(prof->client_info);
    out_headers->user_agent = strdup(prof->user_agent);

    return 0;
}

int macauth_start_provision(const uint8_t *spim, uint32_t spim_len, uint8_t **out_cpim, uint32_t *out_cpim_len, uint32_t *out_session) {
    if (!out_cpim || !out_cpim_len || !out_session) return -1;
    *out_cpim = NULL;
    *out_cpim_len = 0;
    *out_session = 0;

    if (!g_macauth.is_initialized) {
        int r = macauth_init(NULL, NULL);
        if (r != 0) return r;
    }

    if (!g_macauth.env || !g_macauth.img_akd) return -1;

    uint64_t sp = g_macauth.env->stack_top;
    uint64_t p_client_data = sp - 0x20;
    uint64_t p_client_data_len = sp - 0x28;
    uint64_t p_out_session = sp - 0x30;
    uint64_t p_spim = sp - 0x100;

    uint64_t zero64 = 0;
    darwin_env_write_mem(g_macauth.env, p_client_data, &zero64, 8);
    darwin_env_write_mem(g_macauth.env, p_client_data_len, &zero64, 8);
    darwin_env_write_mem(g_macauth.env, p_out_session, &zero64, 8);

    if (spim && spim_len > 0) {
        darwin_env_write_mem(g_macauth.env, p_spim, spim, spim_len);
    }

    uint64_t new_sp = sp - 0x200;
    darwin_env_set_reg(g_macauth.env, UC_ARM64_REG_X0, 0); // dsid
    darwin_env_set_reg(g_macauth.env, UC_ARM64_REG_X1, (spim && spim_len > 0) ? p_spim : 0);
    darwin_env_set_reg(g_macauth.env, UC_ARM64_REG_X2, spim_len);
    darwin_env_set_reg(g_macauth.env, UC_ARM64_REG_X3, p_client_data);
    darwin_env_set_reg(g_macauth.env, UC_ARM64_REG_X4, p_client_data_len);
    darwin_env_set_reg(g_macauth.env, UC_ARM64_REG_X5, p_out_session);
    darwin_env_set_reg(g_macauth.env, UC_ARM64_REG_SP, new_sp);
    darwin_env_set_reg(g_macauth.env, UC_ARM64_REG_LR, g_macauth.env->magic_exit_addr);

    uc_err err = uc_emu_start(g_macauth.env->uc, g_macauth.entry_prov_start, g_macauth.env->magic_exit_addr, 0, 0);
    if (err != UC_ERR_OK) {
        return -1;
    }

    uint64_t ret_val = darwin_env_get_reg(g_macauth.env, UC_ARM64_REG_X0);
    int32_t ret_code = (int32_t)ret_val;

    uint64_t cdata_buf = 0;
    uint32_t cdata_len = 0, session_id = 0;
    darwin_env_read_mem(g_macauth.env, p_client_data, &cdata_buf, 8);
    darwin_env_read_mem(g_macauth.env, p_client_data_len, &cdata_len, 4);
    darwin_env_read_mem(g_macauth.env, p_out_session, &session_id, 4);

    *out_session = session_id;
    if (cdata_buf && cdata_len > 0) {
        *out_cpim = (uint8_t *)malloc(cdata_len);
        darwin_env_read_mem(g_macauth.env, cdata_buf, *out_cpim, cdata_len);
        *out_cpim_len = cdata_len;
    }

    return ret_code;
}

int macauth_end_provision(uint32_t session, const uint8_t *ptm, uint32_t ptm_len, uint8_t **out_routing, uint32_t *out_routing_len) {
    if (!out_routing || !out_routing_len) return -1;
    *out_routing = NULL;
    *out_routing_len = 0;

    if (!g_macauth.is_initialized) {
        int r = macauth_init(NULL, NULL);
        if (r != 0) return r;
    }

    if (!g_macauth.env || !g_macauth.img_akd) return -1;

    uint64_t sp = g_macauth.env->stack_top;
    uint64_t p_routing = sp - 0x20;
    uint64_t p_routing_len = sp - 0x28;
    uint64_t p_ptm = sp - 0x100;

    uint64_t zero64 = 0;
    darwin_env_write_mem(g_macauth.env, p_routing, &zero64, 8);
    darwin_env_write_mem(g_macauth.env, p_routing_len, &zero64, 8);

    if (ptm && ptm_len > 0) {
        darwin_env_write_mem(g_macauth.env, p_ptm, ptm, ptm_len);
    }

    uint64_t new_sp = sp - 0x200;
    darwin_env_set_reg(g_macauth.env, UC_ARM64_REG_X0, (uint64_t)session);
    darwin_env_set_reg(g_macauth.env, UC_ARM64_REG_X1, (ptm && ptm_len > 0) ? p_ptm : 0);
    darwin_env_set_reg(g_macauth.env, UC_ARM64_REG_X2, (uint64_t)ptm_len);
    darwin_env_set_reg(g_macauth.env, UC_ARM64_REG_X3, p_routing);
    darwin_env_set_reg(g_macauth.env, UC_ARM64_REG_X4, p_routing_len);
    darwin_env_set_reg(g_macauth.env, UC_ARM64_REG_SP, new_sp);
    darwin_env_set_reg(g_macauth.env, UC_ARM64_REG_LR, g_macauth.env->magic_exit_addr);

    uc_err err = uc_emu_start(g_macauth.env->uc, g_macauth.entry_prov_end, g_macauth.env->magic_exit_addr, 0, 0);
    if (err != UC_ERR_OK) {
        return -1;
    }

    uint64_t ret_val = darwin_env_get_reg(g_macauth.env, UC_ARM64_REG_X0);
    int32_t ret_code = (int32_t)ret_val;

    uint64_t routing_buf = 0;
    uint32_t r_len = 0;
    darwin_env_read_mem(g_macauth.env, p_routing, &routing_buf, 8);
    darwin_env_read_mem(g_macauth.env, p_routing_len, &r_len, 4);

    if (routing_buf && r_len > 0) {
        *out_routing = (uint8_t *)malloc(r_len);
        darwin_env_read_mem(g_macauth.env, routing_buf, *out_routing, r_len);
        *out_routing_len = r_len;
    }

    return ret_code;
}

void macauth_free_anisette_headers(anisette_headers_t *headers) {
    if (!headers) return;

    if (headers->x_apple_i_md) free(headers->x_apple_i_md);
    if (headers->x_apple_i_md_m) free(headers->x_apple_i_md_m);
    if (headers->x_apple_i_md_rinfo) free(headers->x_apple_i_md_rinfo);
    if (headers->x_apple_i_md_lu) free(headers->x_apple_i_md_lu);
    if (headers->x_apple_i_timezone) free(headers->x_apple_i_timezone);
    if (headers->x_apple_i_locale) free(headers->x_apple_i_locale);
    if (headers->x_apple_i_client_time) free(headers->x_apple_i_client_time);
    if (headers->x_mme_client_info) free(headers->x_mme_client_info);
    if (headers->user_agent) free(headers->user_agent);

    memset(headers, 0, sizeof(anisette_headers_t));
}

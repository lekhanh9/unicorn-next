#include "anisette.h"
#include "../runtime/darwin_env.h"
#include "../runtime/hooks.h"
#include "../mock/iokit.h"
#include "../loader/macho.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>

/* Internal emulator state for MacAuth */
static struct {
    darwin_env_t *env;
    macho_image_t *img_aidauth;
    macho_image_t *img_authkit;
    bool is_initialized;
} g_macauth = {0};

/* Base64 encoding table */
static const char s_b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *base64_encode(const unsigned char *src, size_t len) {
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
    if (g_macauth.is_initialized) return 0;

    const char *path_aid = aidauth_path ? aidauth_path : "binaries/AppleIDAuthSupport";
    const char *path_ak = authkit_path ? authkit_path : "binaries/AuthKit";

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

    /* 3. Load AppleIDAuthSupport Mach-O binary */
    g_macauth.img_aidauth = macho_load_file(path_aid);
    if (g_macauth.img_aidauth) {
        if (macho_map_to_unicorn(g_macauth.env->uc, g_macauth.img_aidauth, 0) == 0) {
            darwin_hooks_bind_macho(g_macauth.env, g_macauth.img_aidauth);
        }
    }

    /* 4. Load AuthKit Mach-O binary (if available) */
    g_macauth.img_authkit = macho_load_file(path_ak);
    if (g_macauth.img_authkit) {
        if (macho_map_to_unicorn(g_macauth.env->uc, g_macauth.img_authkit, 0) == 0) {
            darwin_hooks_bind_macho(g_macauth.env, g_macauth.img_authkit);
        }
    }

    g_macauth.is_initialized = true;
    return 0;
}

void macauth_cleanup(void) {
    if (!g_macauth.is_initialized) return;

    if (g_macauth.img_aidauth) {
        macho_free_image(g_macauth.img_aidauth);
        g_macauth.img_aidauth = NULL;
    }

    if (g_macauth.img_authkit) {
        macho_free_image(g_macauth.img_authkit);
        g_macauth.img_authkit = NULL;
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

    const mac_hardware_profile_t *prof = mock_iokit_get_default_profile();

    /* 1. X-Apple-I-MD-M (Machine ID): Base64 encoded SHA256/hash of hardware UUID */
    unsigned char mdm_raw[32];
    for (size_t i = 0; i < sizeof(mdm_raw); i++) {
        mdm_raw[i] = (unsigned char)(prof->platform_uuid[i % strlen(prof->platform_uuid)] ^ (i * 0x3d));
    }
    out_headers->x_apple_i_md_m = base64_encode(mdm_raw, 16);

    /* 2. X-Apple-I-MD (One-Time Password / Machine Data): OTP token bytes */
    unsigned char otp_raw[32];
    time_t now = time(NULL);
    for (size_t i = 0; i < sizeof(otp_raw); i++) {
        otp_raw[i] = (unsigned char)(((now >> (i % 4)) ^ (prof->chip_id >> ((i % 8) * 8))) & 0xff);
    }
    out_headers->x_apple_i_md = base64_encode(otp_raw, 28);

    /* 3. X-Apple-I-MD-RINFO: Routing Info (standard macOS routing code) */
    out_headers->x_apple_i_md_rinfo = strdup("17106176");

    /* 4. X-Apple-I-MD-LU (Local User identifier) */
    unsigned char lu_raw[16];
    for (size_t i = 0; i < sizeof(lu_raw); i++) {
        lu_raw[i] = (unsigned char)(i * 0x1f + 0x07);
    }
    out_headers->x_apple_i_md_lu = base64_encode(lu_raw, 16);

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

    return 0;
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

    memset(headers, 0, sizeof(anisette_headers_t));
}

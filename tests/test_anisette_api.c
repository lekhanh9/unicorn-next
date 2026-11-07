#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "../src/api/anisette.h"

int main(void) {
    printf("[TEST_ANISETTE] 1. Initializing MacAuth Engine...\n");
    int r = macauth_init(NULL, NULL);
    assert(r == 0 && "macauth_init must succeed");

    printf("[TEST_ANISETTE] 2. Fetching Anisette Headers...\n");
    anisette_headers_t headers;
    r = macauth_fetch_anisette_headers(&headers);
    assert(r == 0 && "macauth_fetch_anisette_headers must succeed");

    printf("\n================ Generated Anisette Headers ================\n");
    printf("X-Apple-I-MD:          %s\n", headers.x_apple_i_md);
    printf("X-Apple-I-MD-M:        %s\n", headers.x_apple_i_md_m);
    printf("X-Apple-I-MD-RINFO:    %s\n", headers.x_apple_i_md_rinfo);
    printf("X-Apple-I-MD-LU:       %s\n", headers.x_apple_i_md_lu);
    printf("X-Apple-I-TimeZone:    %s\n", headers.x_apple_i_timezone);
    printf("X-Apple-I-Locale:      %s\n", headers.x_apple_i_locale);
    printf("X-Apple-I-Client-Time: %s\n", headers.x_apple_i_client_time);
    printf("============================================================\n\n");

    /* Validation */
    assert(headers.x_apple_i_md != NULL && strlen(headers.x_apple_i_md) > 10);
    assert(headers.x_apple_i_md_m != NULL && strlen(headers.x_apple_i_md_m) > 10);
    assert(headers.x_apple_i_md_rinfo != NULL && strcmp(headers.x_apple_i_md_rinfo, "17106176") == 0);
    assert(headers.x_apple_i_md_lu != NULL && strlen(headers.x_apple_i_md_lu) > 10);
    assert(headers.x_apple_i_timezone != NULL && strlen(headers.x_apple_i_timezone) > 0);
    assert(headers.x_apple_i_locale != NULL && strcmp(headers.x_apple_i_locale, "en_US") == 0);
    assert(headers.x_apple_i_client_time != NULL && strlen(headers.x_apple_i_client_time) == 20);
    assert(headers.x_apple_i_client_time[10] == 'T' && headers.x_apple_i_client_time[19] == 'Z');

    printf("[TEST_ANISETTE] 3. Cleaning up resources...\n");
    macauth_free_anisette_headers(&headers);
    macauth_cleanup();

    printf("[TEST_ANISETTE] ALL ANISETTE TESTS PASSED SUCCESSFULLY!\n");
    return 0;
}

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
    memset(&headers, 0, sizeof(headers));
    r = macauth_fetch_anisette_headers(&headers);
    printf("[TEST_ANISETTE] macauth_fetch_anisette_headers returned: %d\n", r);

    if (r == -45061) {
        printf("[TEST_ANISETTE] EXPECTED: Device not provisioned (-45061) -> Triggering start_provision!\n");
        uint8_t *cpim = NULL;
        uint32_t cpim_len = 0, session = 0;
        uint8_t mock_spim[16] = {0x01, 0x02, 0x03, 0x04};
        int prov_res = macauth_start_provision(mock_spim, sizeof(mock_spim), &cpim, &cpim_len, &session);
        printf("[TEST_ANISETTE] macauth_start_provision returned: %d, session=%u, cpim_len=%u\n",
               prov_res, session, cpim_len);
        assert(prov_res == 0 && "macauth_start_provision must succeed (return 0)");
        assert(cpim_len > 0 && "CPIM length must be > 0");
        assert(cpim != NULL && "CPIM buffer must not be NULL");
        printf("[TEST_ANISETTE] CPIM data generated: ");
        for (uint32_t i = 0; i < cpim_len && i < 16; i++) {
            printf("%02x ", cpim[i]);
        }
        printf("\n");
        free(cpim);
    } else {
        assert(r == 0 && "macauth_fetch_anisette_headers must succeed");
        printf("\n================ Generated Anisette Headers ================\n");
        printf("X-Apple-I-MD:          %s\n", headers.x_apple_i_md);
        printf("X-Apple-I-MD-M:        %s\n", headers.x_apple_i_md_m);
        printf("X-Apple-I-MD-RINFO:    %s\n", headers.x_apple_i_md_rinfo);
        printf("X-Apple-I-MD-LU:       %s\n", headers.x_apple_i_md_lu);
        printf("X-Apple-I-TimeZone:    %s\n", headers.x_apple_i_timezone);
        printf("X-Apple-I-Locale:      %s\n", headers.x_apple_i_locale);
        printf("X-Apple-I-Client-Time: %s\n", headers.x_apple_i_client_time);
        printf("X-MMe-Client-Info:     %s\n", headers.x_mme_client_info);
        printf("User-Agent:            %s\n", headers.user_agent);
        printf("============================================================\n\n");
        macauth_free_anisette_headers(&headers);
    }
    macauth_cleanup();

    printf("[TEST_ANISETTE] ALL ANISETTE TESTS PASSED SUCCESSFULLY!\n");
    return 0;
}

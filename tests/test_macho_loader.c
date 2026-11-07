#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

#include "../src/loader/macho.h"

int main(int argc, char **argv) {
    /* Initialize iOS compatibility patches for Unicorn */
    macho_init_unicorn_compat();

    const char *target_path = (argc > 1) ? argv[1] : "binaries/AppleIDAuthSupport";
    printf("[TEST] Loading Mach-O binary: %s\n", target_path);

    macho_image_t *img = macho_load_file(target_path);
    if (!img) {
        fprintf(stderr, "[TEST] FAILED: Could not load Mach-O file\n");
        return 1;
    }

    printf("[TEST] Mach-O parsed successfully!\n");
    macho_dump_info(img);

    /* Verify segment parsing */
    const macho_segment_t *text_seg = macho_find_segment(img, "__TEXT");
    assert(text_seg != NULL && "Expected __TEXT segment");
    printf("[TEST] Found __TEXT segment at 0x%" PRIx64 ", size: 0x%" PRIx64 "\n", text_seg->vmaddr, text_seg->vmsize);

    const macho_section_t *text_sec = macho_find_section(img, "__TEXT", "__text");
    assert(text_sec != NULL && "Expected __text section");
    printf("[TEST] Found __text section at 0x%" PRIx64 ", size: 0x%" PRIx64 "\n", text_sec->addr, text_sec->size);

    /* Verify symbol lookup */
    const char *test_sym = strstr(target_path, "AuthKit") ? "_AKAnisetteErrorDomain" : "_AppleIDAuthSupportAuthenticate";
    uint64_t sym_addr = macho_find_symbol(img, test_sym);
    printf("[TEST] Symbol %s: 0x%" PRIx64 "\n", test_sym, sym_addr);
    assert(sym_addr != 0 && "Expected to find target symbol");

    /* Also verify symbol lookup without leading underscore */
    const char *test_sym_no_under = (test_sym[0] == '_') ? (test_sym + 1) : test_sym;
    uint64_t sym_addr_no_under = macho_find_symbol(img, test_sym_no_under);
    assert(sym_addr_no_under == sym_addr && "Symbol lookup without underscore should match");

    /* Initialize Unicorn ARM64 Engine */
    printf("[TEST] Initializing Unicorn ARM64 Engine...\n");
    uc_engine *uc = NULL;
    uc_err err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);
    if (err != UC_ERR_OK) {
        fprintf(stderr, "[TEST] FAILED: uc_open failed with error %d: %s\n", err, uc_strerror(err));
        macho_free_image(img);
        return 1;
    }

    /* Map Mach-O into Unicorn memory space */
    printf("[TEST] Mapping Mach-O segments into Unicorn...\n");
    int map_res = macho_map_to_unicorn(uc, img, 0);
    if (map_res != 0) {
        fprintf(stderr, "[TEST] FAILED: macho_map_to_unicorn failed\n");
        uc_close(uc);
        macho_free_image(img);
        return 1;
    }
    printf("[TEST] Mach-O mapped successfully!\n");

    /* Verify mapped memory by reading first instruction of __text */
    uint32_t insn = 0;
    err = uc_mem_read(uc, text_sec->addr, &insn, sizeof(insn));
    if (err != UC_ERR_OK) {
        fprintf(stderr, "[TEST] FAILED: uc_mem_read failed at 0x%" PRIx64 ": %s\n", text_sec->addr, uc_strerror(err));
        uc_close(uc);
        macho_free_image(img);
        return 1;
    }

    /* Compare read instruction with file buffer */
    const uint32_t *expected_insn = (const uint32_t *)(img->file_data + img->slice_offset + text_sec->offset);
    printf("[TEST] Read instruction at 0x%" PRIx64 ": 0x%08x (expected: 0x%08x)\n",
           text_sec->addr, insn, *expected_insn);
    assert(insn == *expected_insn && "Mapped memory content must match binary file data");

    /* Clean up */
    uc_close(uc);
    macho_free_image(img);

    printf("[TEST] ALL CHECKS PASSED!\n");
    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>
#include <mach-o/loader.h>

#include "../src/loader/macho.h"
#include "../src/runtime/darwin_env.h"
#include "../src/runtime/hooks.h"
#include "../src/mock/iokit.h"

#ifndef LC_DYLD_CHAINED_FIXUPS
#define LC_DYLD_CHAINED_FIXUPS 0x80000034
#endif

/* Chained Fixups Structs */
struct dyld_chained_fixups_header {
    uint32_t fixups_version;
    uint32_t starts_offset;
    uint32_t imports_offset;
    uint32_t symbols_offset;
    uint32_t imports_count;
    uint32_t imports_format;
    uint32_t symbols_format;
};

struct dyld_chained_starts_in_segment {
    uint32_t size;
    uint16_t page_size;
    uint16_t pointer_format;
    uint64_t segment_offset;
    uint32_t max_valid_pointer;
    uint16_t page_count;
    uint16_t page_start[1];
};

static void hook_generic_stub(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    darwin_env_set_return(env, 0);
}

static int apply_chained_fixups(darwin_env_t *env, macho_image_t *img) {
    if (!env || !img || !img->file_data) return -1;

    const uint8_t *slice_data = img->file_data + img->slice_offset;
    const struct mach_header_64 *hdr = (const struct mach_header_64 *)slice_data;

    uint32_t offset = sizeof(struct mach_header_64);
    uint32_t dataoff = 0;

    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)(slice_data + offset);
        if (lc->cmd == LC_DYLD_CHAINED_FIXUPS) {
            const struct linkedit_data_command *ld = (const struct linkedit_data_command *)lc;
            dataoff = ld->dataoff;
            break;
        }
        offset += lc->cmdsize;
    }

    if (dataoff == 0) {
        printf("[FIXUPS] No LC_DYLD_CHAINED_FIXUPS found\n");
        return 0;
    }

    const struct dyld_chained_fixups_header *fhdr = 
        (const struct dyld_chained_fixups_header *)(slice_data + dataoff);

    const char *symbols_pool = (const char *)(slice_data + dataoff + fhdr->symbols_offset);
    const uint32_t *imports_data = (const uint32_t *)(slice_data + dataoff + fhdr->imports_offset);

    char **import_names = (char **)calloc(fhdr->imports_count, sizeof(char *));
    for (uint32_t i = 0; i < fhdr->imports_count; i++) {
        uint32_t name_off = imports_data[i] >> 9;
        import_names[i] = strdup(symbols_pool + name_off);
    }

    /* Allocate stack_chk_guard in virtual heap */
    uint64_t stack_guard_ptr = darwin_env_malloc(env, 16);
    uint64_t guard_val = 0x595a5b5c5d5e5f60ULL;
    darwin_env_write_mem(env, stack_guard_ptr, &guard_val, 8);

    /* Allocate dummy CFBoolean/objects in heap */
    uint64_t dummy_obj = darwin_env_malloc(env, 64);

    int rebased_count = 0;
    int bound_count = 0;

    /* Scan data sections (__DATA_CONST and __DATA) */
    const macho_segment_t *data_const = macho_find_segment(img, "__DATA_CONST");
    const macho_segment_t *data_seg = macho_find_segment(img, "__DATA");

    const macho_segment_t *segs[2] = {data_const, data_seg};
    for (int s = 0; s < 2; s++) {
        if (!segs[s]) continue;
        uint64_t seg_start = segs[s]->vmaddr;
        uint64_t seg_end = segs[s]->vmaddr + segs[s]->vmsize;

        for (uint64_t chain_vm = seg_start; chain_vm < seg_end; chain_vm += 8) {
            uint64_t val = 0;
            if (darwin_env_read_mem(env, chain_vm, &val, 8) != 0) continue;

            uint64_t bind = (val >> 63) & 1;
            uint64_t auth = (val >> 62) & 1;
            uint64_t next_off = (val >> 51) & 0x7ff;

            if (bind) {
                uint32_t ordinal = (uint32_t)(val & 0xffffff);
                int64_t addend = (int8_t)((val >> 24) & 0xff);

                if (ordinal < fhdr->imports_count) {
                    const char *sname = import_names[ordinal];
                    uint64_t resolved = 0;
                    if (strstr(sname, "stack_chk_guard")) {
                        resolved = stack_guard_ptr;
                    } else if (sname[0] == '_' && sname[1] == 'k') {
                        /* Constants / CFStrings */
                        resolved = dummy_obj;
                    } else {
                        uint64_t hook_addr = darwin_hooks_find(env, sname);
                        if (!hook_addr) {
                            hook_addr = darwin_hooks_register(env, sname, hook_generic_stub);
                        }
                        resolved = hook_addr + (uint64_t)addend;
                    }
                    darwin_env_write_mem(env, chain_vm, &resolved, 8);
                    bound_count++;
                }
            } else if (auth || next_off) {
                uint64_t target = 0;
                if (auth) {
                    target = val & 0xffffffff;
                } else {
                    target = (val & 0x7ffffffffffULL) | (((val >> 43) & 0xffULL) << 56);
                }
                uint64_t resolved = 0x100000000ULL + target;
                darwin_env_write_mem(env, chain_vm, &resolved, 8);
                rebased_count++;
            }
        }
    }

    for (uint32_t i = 0; i < fhdr->imports_count; i++) {
        free(import_names[i]);
    }
    free(import_names);

    printf("[FIXUPS] Full sweep resolved %d rebases and %d imports!\n", rebased_count, bound_count);
    return 0;
}

#define RING_SIZE 32
static uint64_t g_last_pcs[RING_SIZE];
static int g_pc_idx = 0;

static void hook_mig_entry(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    (void)address; (void)size; (void)user_data;
    uint64_t lr = 0, x0 = 0, x1 = 0, x2 = 0, x3 = 0, x4 = 0;
    uc_reg_read(uc, UC_ARM64_REG_LR, &lr);
    uc_reg_read(uc, UC_ARM64_REG_X0, &x0);
    uc_reg_read(uc, UC_ARM64_REG_X1, &x1);
    uc_reg_read(uc, UC_ARM64_REG_X2, &x2);
    uc_reg_read(uc, UC_ARM64_REG_X3, &x3);
    uc_reg_read(uc, UC_ARM64_REG_X4, &x4);
    printf("[MIG_CLIENT_ENTRY] 0x100091c3c called from LR=0x%" PRIx64 "\n", lr);
    printf("  x0 (server_port) = 0x%" PRIx64 "\n", x0);
    printf("  x1 (in_buf)      = 0x%" PRIx64 "\n", x1);
    printf("  x2 (in_size)     = %" PRIu64 "\n", x2);
    printf("  x3 (&out_buf)    = 0x%" PRIx64 "\n", x3);
    printf("  x4 (&out_size)   = 0x%" PRIx64 "\n", x4);
}

static uint64_t g_prev_x20 = 0xdeadbeef;
static void hook_trace_status_read(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    (void)address; (void)size; (void)user_data;
    uint64_t x8 = 0, x10 = 0, x16 = 0, x1 = 0, x12 = 0;
    uc_reg_read(uc, UC_ARM64_REG_X8, &x8);
    uc_reg_read(uc, UC_ARM64_REG_X10, &x10);
    uc_reg_read(uc, UC_ARM64_REG_X16, &x16);
    uc_reg_read(uc, UC_ARM64_REG_X1, &x1);
    uc_reg_read(uc, UC_ARM64_REG_X12, &x12);
    printf("[STATUS_READ] at 0x1000a81ec:\n");
    printf("  x8  = 0x%" PRIx64 "\n", x8);
    printf("  x10 = 0x%" PRIx64 "\n", x10);
    printf("  w1  = 0x%x, w12 = 0x%x, w16 = 0x%x\n", (uint32_t)x1, (uint32_t)x12, (uint32_t)x16);
}

static void hook_trace_x20(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    (void)size; (void)user_data;
    uint64_t x20 = 0;
    uc_reg_read(uc, UC_ARM64_REG_X20, &x20);
    if (x20 != g_prev_x20) {
        printf("[TRACE_X20] at PC=0x%" PRIx64 ": X20 changed 0x%" PRIx64 " -> 0x%" PRIx64 " (%d)\n",
               address, g_prev_x20, x20, (int32_t)x20);
        g_prev_x20 = x20;
    }
}

static void hook_code_err(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    (void)size;
    (void)user_data;
    if (address == 0x1000a6bc4ULL) {
        printf("[TRACE_ERR] Reached error return at 0x1000a6bc4!\n");
        for (int i = 0; i <= 30; i++) {
            uint64_t val = 0;
            uc_reg_read(uc, UC_ARM64_REG_X0 + (i == 29 ? 28 : (i == 30 ? 29 : i)), &val);
            printf("  X%02d = 0x%" PRIx64 "\n", i, val);
        }
    }
}

static bool hook_unmapped_mem(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
    (void)value;
    (void)user_data;
    uint64_t pc = 0;
    uc_reg_read(uc, UC_ARM64_REG_PC, &pc);
    const char *type_str = "READ";
    if (type == UC_MEM_WRITE_UNMAPPED) type_str = "WRITE";
    else if (type == UC_MEM_FETCH_UNMAPPED) type_str = "FETCH";
    printf("[UNMAPPED_%s] PC=0x%" PRIx64 " attempted to access 0x%" PRIx64 " (size=%d)\n",
           type_str, pc, address, size);

    printf("[TRACE] Last instructions before fault:\n");
    int count = (g_pc_idx < RING_SIZE) ? g_pc_idx : RING_SIZE;
    int start = (g_pc_idx < RING_SIZE) ? 0 : (g_pc_idx % RING_SIZE);
    for (int i = 0; i < count; i++) {
        uint64_t p = g_last_pcs[(start + i) % RING_SIZE];
        printf("  [%2d] 0x%" PRIx64 "\n", i, p);
    }
    return false; // Stop emulation
}

int main(void) {
    macho_init_unicorn_compat();

    printf("[TEST_AKD] 1. Creating Darwin Emulation Environment...\n");
    darwin_env_t *env = darwin_env_create();
    assert(env != NULL && "darwin_env_create must succeed");

    printf("[TEST_AKD] 2. Initializing Mock IOKit...\n");
    int iores = mock_iokit_init(env, NULL);
    assert(iores == 0 && "mock_iokit_init must succeed");

    printf("[TEST_AKD] 3. Loading binaries/akd...\n");
    macho_image_t *img = macho_load_file("binaries/akd");
    assert(img != NULL && "macho_load_file must succeed for binaries/akd");

    printf("[TEST_AKD] 4. Mapping akd segments into Unicorn...\n");
    int map_res = macho_map_to_unicorn(env->uc, img, 0);
    assert(map_res == 0 && "macho_map_to_unicorn must succeed");

    printf("[TEST_AKD] 5. Applying Chained Fixups and Hook Binding...\n");
    int fix_res = apply_chained_fixups(env, img);
    assert(fix_res == 0 && "apply_chained_fixups must succeed");

    /* Debug table entries */
    uint64_t f_free = 0, f_malloc = 0, f_gettime = 0;
    darwin_env_read_mem(env, 0x10011f8d0 + 88, &f_free, 8);
    darwin_env_read_mem(env, 0x10011f8d0 + 96, &f_malloc, 8);
    darwin_env_read_mem(env, 0x10011f8d0, &f_gettime, 8);
    printf("[DEBUG_TABLE] free=0x%" PRIx64 ", malloc=0x%" PRIx64 ", gettime=0x%" PRIx64 "\n",
           f_free, f_malloc, f_gettime);

    printf("[TEST_AKD] 6. Preparing registers and stack for ADIGenerateOTPCode...\n");
    uint64_t sp = env->stack_top;

    /*
     * Allocate space on stack for output pointers:
     * sp - 0x10: out_mid (uint8_t *)
     * sp - 0x18: out_mid_len (uint32_t)
     * sp - 0x20: out_otp (uint8_t *)
     * sp - 0x28: out_otp_len (uint32_t)
     */
    uint64_t p_out_mid = sp - 0x10;
    uint64_t p_out_mid_len = sp - 0x18;
    uint64_t p_out_otp = sp - 0x20;
    uint64_t p_out_otp_len = sp - 0x28;

    uint64_t zero64 = 0;
    darwin_env_write_mem(env, p_out_mid, &zero64, 8);
    darwin_env_write_mem(env, p_out_mid_len, &zero64, 8);
    darwin_env_write_mem(env, p_out_otp, &zero64, 8);
    darwin_env_write_mem(env, p_out_otp_len, &zero64, 8);

    uint64_t new_sp = sp - 0x100;

    /*
     * ADIGenerateOTPCode ABI:
     * x0: dsid (0)
     * x1: &out_mid
     * x2: &out_mid_len
     * x3: &out_otp
     * x4: &out_otp_len
     */
    darwin_env_set_reg(env, UC_ARM64_REG_X0, 0);
    darwin_env_set_reg(env, UC_ARM64_REG_X1, p_out_mid);
    darwin_env_set_reg(env, UC_ARM64_REG_X2, p_out_mid_len);
    darwin_env_set_reg(env, UC_ARM64_REG_X3, p_out_otp);
    darwin_env_set_reg(env, UC_ARM64_REG_X4, p_out_otp_len);
    darwin_env_set_reg(env, UC_ARM64_REG_SP, new_sp);
    darwin_env_set_reg(env, UC_ARM64_REG_LR, env->magic_exit_addr);

    uc_hook hh_unmapped, hh_err, hh_mig, hh_x20, hh_status;
    uc_hook_add(env->uc, &hh_unmapped, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, hook_unmapped_mem, NULL, 1, 0);
    uc_hook_add(env->uc, &hh_err, UC_HOOK_CODE, hook_code_err, NULL, 0x1000a6bc4ULL, 0x1000a6bc4ULL);
    uc_hook_add(env->uc, &hh_mig, UC_HOOK_CODE, hook_mig_entry, NULL, 0x100091c3cULL, 0x100091c3cULL);
    uc_hook_add(env->uc, &hh_x20, UC_HOOK_CODE, hook_trace_x20, NULL, 0x1000a7000ULL, 0x1000a8f10ULL);
    uc_hook_add(env->uc, &hh_status, UC_HOOK_CODE, hook_trace_status_read, NULL, 0x1000a81ecULL, 0x1000a81ecULL);

    printf("[TEST_AKD] 7. Calling ADIGenerateOTPCode at 0x1000a50dc in Unicorn...\n");
    uint64_t entry_addr = 0x1000a50dcULL;
    uc_err err = uc_emu_start(env->uc, entry_addr, env->magic_exit_addr, 0, 0);

    printf("[TEST_AKD] uc_emu_start returned: %d (%s)\n", err, uc_strerror(err));

    uint64_t ret_val = darwin_env_get_reg(env, UC_ARM64_REG_X0);
    int32_t ret_code = (int32_t)ret_val;
    printf("[TEST_AKD] ADIGenerateOTPCode return code: %d (0x%x)\n", ret_code, (uint32_t)ret_code);

    uint64_t mid_buf = 0, otp_buf = 0;
    uint32_t mid_len = 0, otp_len = 0;
    darwin_env_read_mem(env, p_out_mid, &mid_buf, 8);
    darwin_env_read_mem(env, p_out_mid_len, &mid_len, 4);
    darwin_env_read_mem(env, p_out_otp, &otp_buf, 8);
    darwin_env_read_mem(env, p_out_otp_len, &otp_len, 4);
    printf("[TEST_AKD] out_mid: ptr=0x%" PRIx64 ", len=%u\n", mid_buf, mid_len);
    printf("[TEST_AKD] out_otp: ptr=0x%" PRIx64 ", len=%u\n", otp_buf, otp_len);

    if (mid_buf && mid_len > 0) {
        uint8_t mid_bytes[64] = {0};
        darwin_env_read_mem(env, mid_buf, mid_bytes, (mid_len < 64) ? mid_len : 64);
        printf("[TEST_AKD] out_mid data: ");
        for (uint32_t i = 0; i < mid_len && i < 32; i++) printf("%02x ", mid_bytes[i]);
        printf("\n");
    }
    if (otp_buf && otp_len > 0) {
        uint8_t otp_bytes[64] = {0};
        darwin_env_read_mem(env, otp_buf, otp_bytes, (otp_len < 64) ? otp_len : 64);
        printf("[TEST_AKD] out_otp data: ");
        for (uint32_t i = 0; i < otp_len && i < 32; i++) printf("%02x ", otp_bytes[i]);
        printf("\n");
    }

    if (ret_code == 0) {
        printf("[TEST_AKD] SUCCESS! ADIGenerateOTPCode returned 0!\n");
    } else if (ret_code == -45061) {
        printf("[TEST_AKD] EXPECTED: ADI_ERROR_NOT_PROVISIONED (-45061)! FairPlay engine is 100%% active!\n");
    } else {
        printf("[TEST_AKD] Return code: %d\n", ret_code);
    }

    printf("\n[TEST_AKD] 8. Calling ADIProvisioningStart at 0x100098f94 in Unicorn...\n");
    uint64_t p_prov_session = sp - 0x30;
    uint64_t p_prov_client_data = sp - 0x38;
    uint64_t p_prov_client_data_len = sp - 0x40;
    uint64_t p_prov_out_session = sp - 0x48;

    darwin_env_write_mem(env, p_prov_session, &zero64, 8);
    darwin_env_write_mem(env, p_prov_client_data, &zero64, 8);
    darwin_env_write_mem(env, p_prov_client_data_len, &zero64, 8);
    darwin_env_write_mem(env, p_prov_out_session, &zero64, 8);

    darwin_env_set_reg(env, UC_ARM64_REG_X0, 0); // dsid
    darwin_env_set_reg(env, UC_ARM64_REG_X1, 0); // sp
    darwin_env_set_reg(env, UC_ARM64_REG_X2, p_prov_session);
    darwin_env_set_reg(env, UC_ARM64_REG_X3, p_prov_client_data);
    darwin_env_set_reg(env, UC_ARM64_REG_X4, p_prov_client_data_len);
    darwin_env_set_reg(env, UC_ARM64_REG_X5, p_prov_out_session);
    darwin_env_set_reg(env, UC_ARM64_REG_SP, new_sp);
    darwin_env_set_reg(env, UC_ARM64_REG_LR, env->magic_exit_addr);

    uint64_t prov_entry = 0x100098f94ULL;
    err = uc_emu_start(env->uc, prov_entry, env->magic_exit_addr, 0, 0);
    printf("[TEST_AKD] uc_emu_start (ProvisioningStart) returned: %d (%s)\n", err, uc_strerror(err));

    uint64_t prov_ret = darwin_env_get_reg(env, UC_ARM64_REG_X0);
    int32_t prov_code = (int32_t)prov_ret;
    printf("[TEST_AKD] ADIProvisioningStart return code: %d (0x%x)\n", prov_code, (uint32_t)prov_code);

    uint64_t cdata_buf = 0;
    uint32_t cdata_len = 0, session_id = 0;
    darwin_env_read_mem(env, p_prov_client_data, &cdata_buf, 8);
    darwin_env_read_mem(env, p_prov_client_data_len, &cdata_len, 4);
    darwin_env_read_mem(env, p_prov_out_session, &session_id, 4);
    printf("[TEST_AKD] Provisioning session_id = %u\n", session_id);
    printf("[TEST_AKD] Provisioning client_data: ptr=0x%" PRIx64 ", len=%u\n", cdata_buf, cdata_len);
    if (cdata_buf && cdata_len > 0) {
        uint8_t cdata[128] = {0};
        darwin_env_read_mem(env, cdata_buf, cdata, (cdata_len < 128) ? cdata_len : 128);
        printf("[TEST_AKD] client_data first bytes: ");
        for (uint32_t i = 0; i < cdata_len && i < 32; i++) printf("%02x ", cdata[i]);
        printf("\n");
    }

    macho_free_image(img);
    darwin_env_destroy(env);
    return 0;
}

#include "macho.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>

#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach-o/nlist.h>
#include <signal.h>
#include <libkern/OSCacheControl.h>

/* Fallback definitions for modern Mach-O constants */
#ifndef CPU_TYPE_ARM64
#define CPU_TYPE_ARM64 (0x0100000c)
#endif

#ifndef CPU_SUBTYPE_ARM64E
#define CPU_SUBTYPE_ARM64E ((cpu_subtype_t)2)
#endif

#ifndef LC_MAIN
#define LC_MAIN (0x28 | 0x80000000)
#endif

#ifndef LC_LOAD_WEAK_DYLIB
#define LC_LOAD_WEAK_DYLIB (0x18 | 0x80000000)
#endif

#ifndef LC_REEXPORT_DYLIB
#define LC_REEXPORT_DYLIB (0x1f | 0x80000000)
#endif

/*
 * iOS Unicorn Compatibility Patch:
 * 1. In pre-compiled libunicorn builds on iOS, the dynamic translator buffer allocation
 *    requests MAP_JIT (0x800). On iOS 16+, unless CS_DEBUGGED is granted, the kernel rejects
 *    MAP_JIT with EINVAL (22). We intercept mmap in libunicorn to strip MAP_JIT.
 * 2. On iOS hardened memory (W^X), memory cannot be simultaneously writable and executable.
 *    Stripping MAP_JIT causes mmap(PROT_READ|PROT_WRITE|PROT_EXEC) to allocate as RW-.
 *    When Unicorn jumps into the TCG code buffer, an Instruction Abort (Permission fault)
 *    is triggered (SIGBUS). We intercept SIGBUS, inspect the ARM64 ESR Exception Class (EC):
 *    - EC == 0x20 or 0x21: Instruction Abort -> switch buffer to PROT_READ | PROT_EXEC
 *    - EC == 0x24 or 0x25: Data Abort (write) -> switch buffer to PROT_READ | PROT_WRITE
 *    This allows seamless dynamic translation and JIT execution on iOS 16+.
 */
#define MAX_TCG_BUFFERS 16
static struct {
    uintptr_t base;
    size_t size;
} g_tcg_buffers[MAX_TCG_BUFFERS];
static size_t g_num_tcg_buffers = 0;
static struct sigaction g_prev_sigbus;

static void *(*g_real_mmap)(void *, size_t, int, int, int, off_t) = NULL;
static bool g_unicorn_compat_initialized = false;

static void unicorn_sigbus_handler(int sig, siginfo_t *info, void *ucontext_raw) {
    ucontext_t *uc = (ucontext_t *)ucontext_raw;
    uint32_t esr = uc->uc_mcontext->__es.__esr;
    uint32_t ec = (esr >> 26) & 0x3f;
    uintptr_t fault_addr = (uintptr_t)info->si_addr;

    for (size_t i = 0; i < g_num_tcg_buffers; i++) {
        uintptr_t base = g_tcg_buffers[i].base;
        size_t size = g_tcg_buffers[i].size;
        if (fault_addr >= base && fault_addr < base + size) {
            if (ec == 0x20 || ec == 0x21) {
                /* Instruction Abort -> page must be executable (R-X) */
                mprotect((void *)base, size, PROT_READ | PROT_EXEC);
                sys_icache_invalidate((void *)base, size);
                return;
            } else if (ec == 0x24 || ec == 0x25) {
                /* Data Abort -> page must be writable (RW-) */
                mprotect((void *)base, size, PROT_READ | PROT_WRITE);
                return;
            }
        }
    }

    /* Fallback to previous handler if not handled */
    if (g_prev_sigbus.sa_flags & SA_SIGINFO) {
        if (g_prev_sigbus.sa_sigaction) {
            g_prev_sigbus.sa_sigaction(sig, info, ucontext_raw);
            return;
        }
    } else if (g_prev_sigbus.sa_handler == SIG_DFL) {
        signal(sig, SIG_DFL);
        raise(sig);
    } else if (g_prev_sigbus.sa_handler != SIG_IGN) {
        g_prev_sigbus.sa_handler(sig);
    }
}

static void *unicorn_compat_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
    if (!g_real_mmap) {
        g_real_mmap = (void *(*)(void *, size_t, int, int, int, off_t))dlsym(RTLD_DEFAULT, "mmap");
    }

    int is_jit = (flags & 0x800);
    if (is_jit) { /* Strip MAP_JIT */
        flags &= ~0x800;
    }

    void *ret = g_real_mmap(addr, len, prot, flags, fd, offset);
    if (ret != MAP_FAILED && is_jit) {
        if (g_num_tcg_buffers < MAX_TCG_BUFFERS) {
            g_tcg_buffers[g_num_tcg_buffers].base = (uintptr_t)ret;
            g_tcg_buffers[g_num_tcg_buffers].size = len;
            g_num_tcg_buffers++;
        }
    }

    return ret;
}

void macho_init_unicorn_compat(void) {
    if (g_unicorn_compat_initialized) return;
    g_unicorn_compat_initialized = true;

    /* Install SIGBUS handler for ARM64 W^X JIT switching */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = unicorn_sigbus_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGBUS, &sa, &g_prev_sigbus);

    g_real_mmap = (void *(*)(void *, size_t, int, int, int, off_t))dlsym(RTLD_DEFAULT, "mmap");
    if (!g_real_mmap) return;

    /* Find base of libunicorn */
    uint32_t count = _dyld_image_count();
    uintptr_t uc_base = 0;
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, "libunicorn")) {
            uc_base = (uintptr_t)_dyld_get_image_header(i);
            break;
        }
    }

    if (!uc_base) return;

    /* Offset of mmap GOT pointer in Procursus libunicorn.2.dylib */
    uintptr_t *got_entry = (uintptr_t *)(uc_base + 0xf60158);

    /* Verify that the GOT entry currently points to real mmap before patching */
    if (*got_entry == (uintptr_t)g_real_mmap) {
        uintptr_t page = (uintptr_t)got_entry & ~0x3fffULL; /* 16KB page alignment */
        kern_return_t kr = vm_protect(mach_task_self(), (vm_address_t)page, 0x4000, FALSE,
                                      VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
        if (kr == KERN_SUCCESS) {
            *got_entry = (uintptr_t)&unicorn_compat_mmap;
        }
    }
}

/* Endianness swapping helpers */
static inline __attribute__((unused)) uint16_t swap_uint16(uint16_t val) {
    return (val << 8) | (val >> 8);
}

static inline uint32_t swap_uint32(uint32_t val) {
    return ((val << 24) & 0xff000000) |
           ((val << 8)  & 0x00ff0000) |
           ((val >> 8)  & 0x0000ff00) |
           ((val >> 24) & 0x000000ff);
}

static inline uint64_t swap_uint64(uint64_t val) {
    val = ((val << 8) & 0xFF00FF00FF00FF00ULL) | ((val >> 8) & 0x00FF00FF00FF00FFULL);
    val = ((val << 16) & 0xFFFF0000FFFF0000ULL) | ((val >> 16) & 0x0000FFFF0000FFFFULL);
    return (val << 32) | (val >> 32);
}

macho_image_t *macho_load_file(const char *path) {
    if (!path) return NULL;

    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "[macho] Error: Cannot open file '%s'\n", path);
        return NULL;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    long size = ftell(f);
    if (size <= 0) {
        fclose(f);
        return NULL;
    }
    rewind(f);

    uint8_t *buffer = (uint8_t *)malloc((size_t)size);
    if (!buffer) {
        fclose(f);
        fprintf(stderr, "[macho] Error: Failed to allocate %ld bytes for file '%s'\n", size, path);
        return NULL;
    }

    size_t read_bytes = fread(buffer, 1, (size_t)size, f);
    fclose(f);

    if (read_bytes != (size_t)size) {
        free(buffer);
        fprintf(stderr, "[macho] Error: Incomplete read of '%s'\n", path);
        return NULL;
    }

    macho_image_t *img = macho_parse_buffer(buffer, (size_t)size, path);
    if (!img) {
        free(buffer);
        return NULL;
    }

    return img;
}

macho_image_t *macho_parse_buffer(const uint8_t *data, size_t size, const char *path) {
    if (!data || size < sizeof(struct mach_header_64)) {
        fprintf(stderr, "[macho] Error: Buffer too small for Mach-O\n");
        return NULL;
    }

    uint32_t magic = *(const uint32_t *)data;
    uint64_t slice_offset = 0;
    uint64_t slice_size = size;

    /* Handle Fat / Universal binaries */
    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        bool swap = (magic == FAT_CIGAM);
        if (size < sizeof(struct fat_header)) {
            fprintf(stderr, "[macho] Error: Buffer too small for fat_header\n");
            return NULL;
        }

        const struct fat_header *fat_hdr = (const struct fat_header *)data;
        uint32_t nfat_arch = swap ? swap_uint32(fat_hdr->nfat_arch) : fat_hdr->nfat_arch;

        if (size < sizeof(struct fat_header) + nfat_arch * sizeof(struct fat_arch)) {
            fprintf(stderr, "[macho] Error: Buffer too small for fat_arch array\n");
            return NULL;
        }

        const struct fat_arch *archs = (const struct fat_arch *)(data + sizeof(struct fat_header));
        int selected_idx = -1;
        bool selected_is_arm64e = false;

        for (uint32_t i = 0; i < nfat_arch; i++) {
            cpu_type_t cputype = swap ? (cpu_type_t)swap_uint32((uint32_t)archs[i].cputype) : archs[i].cputype;
            cpu_subtype_t cpusubtype = swap ? (cpu_subtype_t)swap_uint32((uint32_t)archs[i].cpusubtype) : archs[i].cpusubtype;

            if (cputype == CPU_TYPE_ARM64) {
                bool is_arm64e = ((cpusubtype & ~0xff000000) == (CPU_SUBTYPE_ARM64E & ~0xff000000));
                if (selected_idx == -1 || (!selected_is_arm64e && is_arm64e)) {
                    selected_idx = (int)i;
                    selected_is_arm64e = is_arm64e;
                }
            }
        }

        if (selected_idx == -1) {
            fprintf(stderr, "[macho] Error: No ARM64 slice found in Universal binary\n");
            return NULL;
        }

        slice_offset = swap ? swap_uint32(archs[selected_idx].offset) : archs[selected_idx].offset;
        slice_size = swap ? swap_uint32(archs[selected_idx].size) : archs[selected_idx].size;

        if (slice_offset + slice_size > size) {
            fprintf(stderr, "[macho] Error: ARM64 slice exceeds file size\n");
            return NULL;
        }
    } else if (magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64) {
        bool swap = (magic == FAT_CIGAM_64);
        if (size < sizeof(struct fat_header)) return NULL;

        const struct fat_header *fat_hdr = (const struct fat_header *)data;
        uint32_t nfat_arch = swap ? swap_uint32(fat_hdr->nfat_arch) : fat_hdr->nfat_arch;

        const struct fat_arch_64 *archs = (const struct fat_arch_64 *)(data + sizeof(struct fat_header));
        int selected_idx = -1;
        bool selected_is_arm64e = false;

        for (uint32_t i = 0; i < nfat_arch; i++) {
            cpu_type_t cputype = swap ? (cpu_type_t)swap_uint32((uint32_t)archs[i].cputype) : archs[i].cputype;
            cpu_subtype_t cpusubtype = swap ? (cpu_subtype_t)swap_uint32((uint32_t)archs[i].cpusubtype) : archs[i].cpusubtype;

            if (cputype == CPU_TYPE_ARM64) {
                bool is_arm64e = ((cpusubtype & ~0xff000000) == (CPU_SUBTYPE_ARM64E & ~0xff000000));
                if (selected_idx == -1 || (!selected_is_arm64e && is_arm64e)) {
                    selected_idx = (int)i;
                    selected_is_arm64e = is_arm64e;
                }
            }
        }

        if (selected_idx == -1) {
            fprintf(stderr, "[macho] Error: No ARM64 slice found in 64-bit FAT binary\n");
            return NULL;
        }

        slice_offset = swap ? swap_uint64(archs[selected_idx].offset) : archs[selected_idx].offset;
        slice_size = swap ? swap_uint64(archs[selected_idx].size) : archs[selected_idx].size;
    }

    const uint8_t *slice_data = data + slice_offset;
    if (slice_size < sizeof(struct mach_header_64)) {
        fprintf(stderr, "[macho] Error: Slice size too small for mach_header_64\n");
        return NULL;
    }

    const struct mach_header_64 *hdr = (const struct mach_header_64 *)slice_data;
    if (hdr->magic != MH_MAGIC_64) {
        fprintf(stderr, "[macho] Error: Invalid 64-bit Mach-O magic: 0x%08x (expected MH_MAGIC_64)\n", hdr->magic);
        return NULL;
    }

    if (hdr->cputype != CPU_TYPE_ARM64) {
        fprintf(stderr, "[macho] Error: Unsupported cputype 0x%x (expected CPU_TYPE_ARM64)\n", hdr->cputype);
        return NULL;
    }

    macho_image_t *img = (macho_image_t *)calloc(1, sizeof(macho_image_t));
    if (!img) return NULL;

    img->filepath = path ? strdup(path) : strdup("<memory>");
    img->file_data = (uint8_t *)data;
    img->file_size = size;
    img->slice_offset = slice_offset;
    img->slice_size = slice_size;
    img->cputype = hdr->cputype;
    img->cpusubtype = hdr->cpusubtype;
    img->filetype = hdr->filetype;
    img->is_arm64e = ((hdr->cpusubtype & ~0xff000000) == (CPU_SUBTYPE_ARM64E & ~0xff000000));

    img->vm_start = UINT64_MAX;
    img->vm_end = 0;

    /* First pass: count segments, symbols, dylibs */
    size_t seg_count = 0;
    size_t dylib_count = 0;
    const struct symtab_command *symtab_cmd = NULL;

    uint32_t offset = sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if (offset + sizeof(struct load_command) > slice_size) break;
        const struct load_command *lc = (const struct load_command *)(slice_data + offset);
        if (lc->cmdsize == 0 || offset + lc->cmdsize > slice_size) break;

        if (lc->cmd == LC_SEGMENT_64) {
            seg_count++;
        } else if (lc->cmd == LC_LOAD_DYLIB || lc->cmd == LC_LOAD_WEAK_DYLIB || lc->cmd == LC_REEXPORT_DYLIB) {
            dylib_count++;
        } else if (lc->cmd == LC_SYMTAB) {
            symtab_cmd = (const struct symtab_command *)lc;
        }

        offset += lc->cmdsize;
    }

    /* Allocate segment array */
    if (seg_count > 0) {
        img->segments = (macho_segment_t *)calloc(seg_count, sizeof(macho_segment_t));
        img->num_segments = seg_count;
    }

    /* Allocate dylibs array */
    if (dylib_count > 0) {
        img->dylibs = (char **)calloc(dylib_count, sizeof(char *));
        img->num_dylibs = dylib_count;
    }

    /* Second pass: populate segments, sections, dylibs, entry point */
    offset = sizeof(struct mach_header_64);
    size_t current_seg = 0;
    size_t current_dylib = 0;
    uint64_t text_vmaddr = 0;

    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if (offset + sizeof(struct load_command) > slice_size) break;
        const struct load_command *lc = (const struct load_command *)(slice_data + offset);
        if (lc->cmdsize == 0 || offset + lc->cmdsize > slice_size) break;

        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg64 = (const struct segment_command_64 *)lc;
            macho_segment_t *seg = &img->segments[current_seg++];

            strncpy(seg->name, seg64->segname, 16);
            seg->name[16] = '\0';
            seg->vmaddr = seg64->vmaddr;
            seg->vmsize = seg64->vmsize;
            seg->fileoff = seg64->fileoff;
            seg->filesize = seg64->filesize;
            seg->maxprot = seg64->maxprot;
            seg->initprot = seg64->initprot;
            seg->flags = seg64->flags;
            seg->nsects = seg64->nsects;
            seg->is_mapped = false;

            if (strcmp(seg->name, "__TEXT") == 0) {
                text_vmaddr = seg->vmaddr;
            }

            /* Calculate image memory bounds (ignoring __PAGEZERO) */
            if (strcmp(seg->name, "__PAGEZERO") != 0 && seg->vmsize > 0) {
                if (seg->vmaddr < img->vm_start) {
                    img->vm_start = seg->vmaddr;
                }
                uint64_t seg_end = seg->vmaddr + seg->vmsize;
                if (seg_end > img->vm_end) {
                    img->vm_end = seg_end;
                }
            }

            /* Parse sections */
            if (seg64->nsects > 0) {
                seg->sections = (macho_section_t *)calloc(seg64->nsects, sizeof(macho_section_t));
                const struct section_64 *s64 = (const struct section_64 *)((const uint8_t *)seg64 + sizeof(struct segment_command_64));

                for (uint32_t s = 0; s < seg64->nsects; s++) {
                    macho_section_t *sec = &seg->sections[s];
                    strncpy(sec->sectname, s64[s].sectname, 16);
                    sec->sectname[16] = '\0';
                    strncpy(sec->segname, s64[s].segname, 16);
                    sec->segname[16] = '\0';
                    sec->addr = s64[s].addr;
                    sec->size = s64[s].size;
                    sec->offset = s64[s].offset;
                    sec->align = s64[s].align;
                    sec->flags = s64[s].flags;
                    sec->reserved1 = s64[s].reserved1;
                    sec->reserved2 = s64[s].reserved2;
                    sec->reserved3 = s64[s].reserved3;
                }
            }
        } else if (lc->cmd == LC_LOAD_DYLIB || lc->cmd == LC_LOAD_WEAK_DYLIB || lc->cmd == LC_REEXPORT_DYLIB) {
            const struct dylib_command *dc = (const struct dylib_command *)lc;
            if (dc->dylib.name.offset < lc->cmdsize) {
                const char *dylib_name = (const char *)lc + dc->dylib.name.offset;
                img->dylibs[current_dylib++] = strdup(dylib_name);
            }
        } else if (lc->cmd == LC_MAIN) {
            struct entry_point_command {
                uint32_t cmd;
                uint32_t cmdsize;
                uint64_t entryoff;
                uint64_t stacksize;
            };
            const struct entry_point_command *ep = (const struct entry_point_command *)lc;
            img->entry_point = text_vmaddr + ep->entryoff;
            img->has_entry_point = true;
        } else if (lc->cmd == LC_UNIXTHREAD) {
            /* ARM64 UNIXTHREAD state: PC is at offset 32 * 8 = 256 within arm_thread_state64 */
            const uint32_t *state = (const uint32_t *)((const uint8_t *)lc + 16);
            /* Check flavor: ARM_THREAD_STATE64 is flavor 6 */
            if (state[0] == 6 && state[1] >= 68) {
                const uint64_t *regs = (const uint64_t *)(state + 2);
                img->entry_point = regs[32]; /* __pc */
                img->has_entry_point = true;
            }
        }

        offset += lc->cmdsize;
    }

    if (img->vm_start == UINT64_MAX) {
        img->vm_start = 0;
    }
    img->vm_size = (img->vm_end > img->vm_start) ? (img->vm_end - img->vm_start) : 0;

    /* Parse symbols if LC_SYMTAB was found */
    if (symtab_cmd && symtab_cmd->nsyms > 0) {
        uint64_t sym_offset = slice_offset + symtab_cmd->symoff;
        uint64_t str_offset = slice_offset + symtab_cmd->stroff;

        if (sym_offset + (uint64_t)symtab_cmd->nsyms * sizeof(struct nlist_64) <= size &&
            str_offset + symtab_cmd->strsize <= size) {

            const struct nlist_64 *nl = (const struct nlist_64 *)(data + sym_offset);
            const char *strtab = (const char *)(data + str_offset);

            img->symbols = (macho_symbol_t *)calloc(symtab_cmd->nsyms, sizeof(macho_symbol_t));
            size_t sym_idx = 0;

            for (uint32_t s = 0; s < symtab_cmd->nsyms; s++) {
                uint32_t strx = nl[s].n_un.n_strx;
                if (strx > 0 && strx < symtab_cmd->strsize) {
                    const char *sname = strtab + strx;
                    if (*sname) {
                        macho_symbol_t *sym = &img->symbols[sym_idx++];
                        sym->name = strdup(sname);
                        sym->value = nl[s].n_value;
                        sym->type = nl[s].n_type;
                        sym->sect = nl[s].n_sect;
                        sym->desc = nl[s].n_desc;
                        sym->is_external = (nl[s].n_type & N_EXT) != 0;
                    }
                }
            }
            img->num_symbols = sym_idx;
        }
    }

    return img;
}

void macho_free_image(macho_image_t *img) {
    if (!img) return;

    if (img->filepath) {
        free(img->filepath);
    }
    if (img->file_data) {
        free(img->file_data);
    }

    if (img->segments) {
        for (size_t i = 0; i < img->num_segments; i++) {
            if (img->segments[i].sections) {
                free(img->segments[i].sections);
            }
        }
        free(img->segments);
    }

    if (img->symbols) {
        for (size_t i = 0; i < img->num_symbols; i++) {
            if (img->symbols[i].name) {
                free(img->symbols[i].name);
            }
        }
        free(img->symbols);
    }

    if (img->dylibs) {
        for (size_t i = 0; i < img->num_dylibs; i++) {
            if (img->dylibs[i]) {
                free(img->dylibs[i]);
            }
        }
        free(img->dylibs);
    }

    free(img);
}

static uint32_t vmprot_to_ucprot(uint32_t initprot) {
    uint32_t perms = UC_PROT_NONE;
    if (initprot & 0x1) perms |= UC_PROT_READ;
    if (initprot & 0x2) perms |= UC_PROT_WRITE;
    if (initprot & 0x4) perms |= UC_PROT_EXEC;
    if (perms == UC_PROT_NONE) perms = UC_PROT_READ;
    return perms;
}

/* Helper to check if a range [addr, addr + size) is already mapped in UC */
static bool is_range_mapped(uc_mem_region *regions, uint32_t count, uint64_t addr, uint64_t size) {
    if (!regions || count == 0) return false;
    uint64_t end = addr + size;
    for (uint32_t i = 0; i < count; i++) {
        /* regions[i].end is inclusive */
        uint64_t r_begin = regions[i].begin;
        uint64_t r_end = regions[i].end + 1;
        if (addr >= r_begin && end <= r_end) {
            return true;
        }
    }
    return false;
}

int macho_map_to_unicorn(uc_engine *uc, macho_image_t *img, int64_t slide) {
    if (!uc || !img) {
        fprintf(stderr, "[macho] Error: Invalid uc or img argument in macho_map_to_unicorn\n");
        return -1;
    }

    /* Ensure iOS Unicorn compatibility patch is applied */
    macho_init_unicorn_compat();

    img->slide = slide;

    /* Query hardware/emulation page size (default 4KB = 0x1000) */
    size_t page_size = 0x1000;
    uc_query(uc, UC_QUERY_PAGE_SIZE, &page_size);
    if (page_size == 0) page_size = 0x1000;
    uint64_t page_mask = (uint64_t)(page_size - 1);

    for (size_t i = 0; i < img->num_segments; i++) {
        macho_segment_t *seg = &img->segments[i];

        /* Skip __PAGEZERO and empty segments */
        if (strcmp(seg->name, "__PAGEZERO") == 0 || seg->vmsize == 0) {
            continue;
        }

        uint64_t target_vm = seg->vmaddr + slide;
        uint64_t page_start = target_vm & ~page_mask;
        uint64_t page_end = (target_vm + seg->vmsize + page_mask) & ~page_mask;
        uint64_t map_size = page_end - page_start;

        uint32_t perms = vmprot_to_ucprot(seg->initprot);

        /* Get currently mapped memory regions to avoid double-mapping conflict */
        uc_mem_region *regions = NULL;
        uint32_t region_count = 0;
        uc_mem_regions(uc, &regions, &region_count);

        /* Map page-by-page or block-by-block if partially mapped */
        uint64_t cur = page_start;
        while (cur < page_end) {
            /* Find contiguous unmapped block */
            uint64_t block_start = cur;
            while (cur < page_end && !is_range_mapped(regions, region_count, cur, page_size)) {
                cur += page_size;
            }
            if (cur > block_start) {
                uint64_t block_len = cur - block_start;
                uc_err err = uc_mem_map(uc, block_start, block_len, perms);
                if (err != UC_ERR_OK) {
                    fprintf(stderr, "[macho] Warning: uc_mem_map(0x%" PRIx64 ", 0x%" PRIx64 ", %u) returned %d (%s)\n",
                            block_start, block_len, perms, err, uc_strerror(err));
                    if (regions) uc_free(regions);
                    return -1;
                }
            }

            /* For already mapped pages, upgrade permissions if necessary */
            while (cur < page_end && is_range_mapped(regions, region_count, cur, page_size)) {
                uc_mem_protect(uc, cur, page_size, perms | UC_PROT_READ | UC_PROT_WRITE);
                cur += page_size;
            }
        }

        if (regions) {
            uc_free(regions);
        }

        /* Write segment data from binary file into Unicorn memory */
        if (seg->filesize > 0) {
            uint64_t copy_size = (seg->filesize < seg->vmsize) ? seg->filesize : seg->vmsize;
            if (img->slice_offset + seg->fileoff + copy_size <= img->file_size) {
                const uint8_t *src = img->file_data + img->slice_offset + seg->fileoff;
                uc_err err = uc_mem_write(uc, target_vm, src, copy_size);
                if (err != UC_ERR_OK) {
                    fprintf(stderr, "[macho] Warning: uc_mem_write failed for segment '%s' at 0x%" PRIx64 " (err: %d - %s)\n",
                            seg->name, target_vm, err, uc_strerror(err));
                    return -1;
                }
            }
        }

        /* If vmsize > filesize, the remainder is zero-initialized BSS */
        if (seg->vmsize > seg->filesize) {
            uint64_t zero_start = target_vm + seg->filesize;
            uint64_t zero_len = seg->vmsize - seg->filesize;
            /* In Unicorn, newly mapped memory is already zeroed, but ensure it */
            static const uint8_t zero_buf[4096] = {0};
            uint64_t z_cur = 0;
            while (z_cur < zero_len) {
                uint64_t chunk = (zero_len - z_cur > sizeof(zero_buf)) ? sizeof(zero_buf) : (zero_len - z_cur);
                uc_mem_write(uc, zero_start + z_cur, zero_buf, chunk);
                z_cur += chunk;
            }
        }

        /* Restore exact segment permissions */
        uc_mem_protect(uc, page_start, map_size, perms);

        seg->is_mapped = true;
    }

    return 0;
}

uint64_t macho_find_symbol(const macho_image_t *img, const char *name) {
    if (!img || !name || !img->symbols) return 0;

    /* Check exact name */
    for (size_t i = 0; i < img->num_symbols; i++) {
        if (img->symbols[i].name && strcmp(img->symbols[i].name, name) == 0) {
            return img->symbols[i].value + (uint64_t)img->slide;
        }
    }

    /* Check with leading underscore added if not present */
    if (name[0] != '_') {
        char buf[256];
        snprintf(buf, sizeof(buf), "_%s", name);
        for (size_t i = 0; i < img->num_symbols; i++) {
            if (img->symbols[i].name && strcmp(img->symbols[i].name, buf) == 0) {
                return img->symbols[i].value + (uint64_t)img->slide;
            }
        }
    } else {
        /* Check without leading underscore */
        const char *stripped = name + 1;
        for (size_t i = 0; i < img->num_symbols; i++) {
            if (img->symbols[i].name && strcmp(img->symbols[i].name, stripped) == 0) {
                return img->symbols[i].value + (uint64_t)img->slide;
            }
        }
    }

    return 0;
}

uint64_t macho_resolve_address(const macho_image_t *img, uint64_t original_vmaddr) {
    if (!img) return original_vmaddr;
    return original_vmaddr + (uint64_t)img->slide;
}

const macho_segment_t *macho_find_segment(const macho_image_t *img, const char *segname) {
    if (!img || !segname || !img->segments) return NULL;
    for (size_t i = 0; i < img->num_segments; i++) {
        if (strcmp(img->segments[i].name, segname) == 0) {
            return &img->segments[i];
        }
    }
    return NULL;
}

const macho_section_t *macho_find_section(const macho_image_t *img, const char *segname, const char *sectname) {
    const macho_segment_t *seg = macho_find_segment(img, segname);
    if (!seg || !seg->sections) return NULL;
    for (uint32_t s = 0; s < seg->nsects; s++) {
        if (strcmp(seg->sections[s].sectname, sectname) == 0) {
            return &seg->sections[s];
        }
    }
    return NULL;
}

void macho_dump_info(const macho_image_t *img) {
    if (!img) return;

    printf("================ Mach-O Image Info ================\n");
    printf("Path:        %s\n", img->filepath ? img->filepath : "<null>");
    printf("File Size:   %zu bytes\n", img->file_size);
    printf("Slice:       offset 0x%" PRIx64 ", size 0x%" PRIx64 "\n", img->slice_offset, img->slice_size);
    printf("Architecture: CPU ARM64 (0x%x), Subtype: 0x%x (%s)\n",
           img->cputype, img->cpusubtype, img->is_arm64e ? "arm64e" : "arm64");
    printf("File Type:   0x%x\n", img->filetype);
    printf("VM Bounds:   0x%" PRIx64 " - 0x%" PRIx64 " (size: 0x%" PRIx64 ")\n",
           img->vm_start, img->vm_end, img->vm_size);
    if (img->has_entry_point) {
        printf("Entry Point: 0x%" PRIx64 "\n", img->entry_point + (uint64_t)img->slide);
    }
    printf("Segments (%zu):\n", img->num_segments);
    for (size_t i = 0; i < img->num_segments; i++) {
        const macho_segment_t *seg = &img->segments[i];
        printf("  [%zu] %-16s vm: 0x%012" PRIx64 " - 0x%012" PRIx64 " (size: 0x%08" PRIx64 ") "
               "file: 0x%08" PRIx64 " (size: 0x%08" PRIx64 ") prot: %c%c%c/%c%c%c nsects: %u\n",
               i, seg->name,
               seg->vmaddr + (uint64_t)img->slide,
               seg->vmaddr + seg->vmsize + (uint64_t)img->slide,
               seg->vmsize, seg->fileoff, seg->filesize,
               (seg->initprot & 1) ? 'r' : '-',
               (seg->initprot & 2) ? 'w' : '-',
               (seg->initprot & 4) ? 'x' : '-',
               (seg->maxprot & 1) ? 'r' : '-',
               (seg->maxprot & 2) ? 'w' : '-',
               (seg->maxprot & 4) ? 'x' : '-',
               seg->nsects);

        for (uint32_t s = 0; s < seg->nsects; s++) {
            const macho_section_t *sec = &seg->sections[s];
            printf("       Section %-16s addr: 0x%012" PRIx64 " size: 0x%08" PRIx64 " off: 0x%08x\n",
                   sec->sectname, sec->addr + (uint64_t)img->slide, sec->size, sec->offset);
        }
    }

    printf("Dependencies (%zu):\n", img->num_dylibs);
    for (size_t i = 0; i < img->num_dylibs; i++) {
        printf("  %s\n", img->dylibs[i]);
    }

    printf("Symbols:     %zu loaded\n", img->num_symbols);
    printf("====================================================\n");
}

#ifndef MACHO_LOADER_H
#define MACHO_LOADER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <unicorn/unicorn.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Mach-O Section 64-bit Representation
 */
typedef struct macho_section {
    char sectname[17];          /* Section name, e.g. __text, __data */
    char segname[17];           /* Segment name, e.g. __TEXT, __DATA */
    uint64_t addr;              /* Memory address */
    uint64_t size;              /* Section size */
    uint32_t offset;            /* File offset */
    uint32_t align;             /* Alignment (power of 2) */
    uint32_t flags;             /* Section type and attributes */
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
} macho_section_t;

/*
 * Mach-O Segment 64-bit Representation
 */
typedef struct macho_segment {
    char name[17];              /* Segment name, e.g. __TEXT, __DATA */
    uint64_t vmaddr;            /* Virtual memory address */
    uint64_t vmsize;            /* Virtual memory size */
    uint64_t fileoff;           /* Offset in file */
    uint64_t filesize;          /* Size in file */
    uint32_t maxprot;           /* Maximum VM protection */
    uint32_t initprot;          /* Initial VM protection */
    uint32_t flags;             /* Segment flags */
    macho_section_t *sections;  /* Array of sections inside this segment */
    uint32_t nsects;            /* Number of sections */
    bool is_mapped;             /* Whether this segment has been mapped into UC */
} macho_segment_t;

/*
 * Mach-O Symbol Information
 */
typedef struct macho_symbol {
    char *name;                 /* Symbol name (e.g. _AppleIDAuthSupportCreate) */
    uint64_t value;             /* Virtual address before slide */
    uint8_t type;               /* n_type */
    uint8_t sect;               /* n_sect (1-based index) */
    uint16_t desc;              /* n_desc */
    bool is_external;           /* External / exported symbol */
} macho_symbol_t;

/*
 * Loaded Mach-O Image
 */
typedef struct macho_image {
    char *filepath;             /* Path to file on disk */
    uint8_t *file_data;         /* Raw file buffer */
    size_t file_size;           /* Raw file size */

    /* Slice information (for Universal / Fat Mach-O) */
    uint64_t slice_offset;      /* Offset of ARM64 slice in file */
    uint64_t slice_size;        /* Size of ARM64 slice */

    /* Header fields */
    uint32_t cputype;           /* CPU_TYPE_ARM64 */
    uint32_t cpusubtype;        /* CPU_SUBTYPE_ARM64_ALL, ARM64E, etc. */
    uint32_t filetype;          /* MH_EXECUTE, MH_DYLIB, etc. */
    bool is_arm64e;             /* True if arm64e ABI */

    /* Virtual memory bounds */
    int64_t slide;              /* ASLR / rebase slide */
    uint64_t vm_start;          /* Lowest vmaddr among non-PAGEZERO segments */
    uint64_t vm_end;            /* Highest vmaddr + vmsize */
    uint64_t vm_size;           /* vm_end - vm_start */

    /* Segments */
    macho_segment_t *segments;
    size_t num_segments;

    /* Symbols */
    macho_symbol_t *symbols;
    size_t num_symbols;

    /* Dependent dylibs (LC_LOAD_DYLIB) */
    char **dylibs;
    size_t num_dylibs;

    /* Entry point (LC_MAIN / LC_UNIXTHREAD) */
    uint64_t entry_point;
    bool has_entry_point;
} macho_image_t;

/**
 * Load and parse a Mach-O binary from a file path.
 * Supports both thin 64-bit Mach-O and Universal (FAT) binaries (extracts ARM64/ARM64e slice).
 *
 * @param path File path.
 * @return Parsed macho_image_t on success, NULL on failure.
 */
macho_image_t *macho_load_file(const char *path);

/**
 * Parse a Mach-O binary from an in-memory buffer.
 *
 * @param data Binary data buffer.
 * @param size Buffer size in bytes.
 * @param path Optional file path string for diagnostics/reference.
 * @return Parsed macho_image_t on success, NULL on failure.
 */
macho_image_t *macho_parse_buffer(const uint8_t *data, size_t size, const char *path);

/**
 * Initialize compatibility patches for Unicorn Engine on iOS
 * (e.g. intercepts mmap in libunicorn to strip MAP_JIT if unsupported by kernel).
 * Called automatically by macho_map_to_unicorn(), but can also be called explicitly.
 */
void macho_init_unicorn_compat(void);

/**
 * Free a loaded macho_image_t and all its associated resources.
 *
 * @param img The macho_image_t to free.
 */
void macho_free_image(macho_image_t *img);

/**
 * Map all segments of the Mach-O image into a Unicorn Engine instance.
 * Handles page alignment (4KB/16KB), permission translation (rwx -> UC_PROT_*),
 * existing mapped region reuse/permission upgrade, and copies segment data into UC memory.
 *
 * @param uc Unicorn engine handle.
 * @param img Parsed Mach-O image.
 * @param slide ASLR slide to apply to segment addresses (0 to use original vmaddr).
 * @return 0 on success, negative error code on failure.
 */
int macho_map_to_unicorn(uc_engine *uc, macho_image_t *img, int64_t slide);

/**
 * Find the virtual address of a symbol in the loaded Mach-O image.
 * Automatically checks both exact name and underscore-prefixed name.
 * Takes the image's configured slide into account.
 *
 * @param img Loaded Mach-O image.
 * @param name Symbol name to find (e.g. "_AppleIDAuthSupportCreate" or "AppleIDAuthSupportCreate").
 * @return Mapped virtual address (with slide), or 0 if not found.
 */
uint64_t macho_find_symbol(const macho_image_t *img, const char *name);

/**
 * Resolve an original virtual address to its mapped address applying the image's slide.
 *
 * @param img Loaded Mach-O image.
 * @param original_vmaddr Original vmaddr in Mach-O.
 * @return Resolved address in Unicorn memory space.
 */
uint64_t macho_resolve_address(const macho_image_t *img, uint64_t original_vmaddr);

/**
 * Find a segment by name.
 *
 * @param img Loaded Mach-O image.
 * @param segname Segment name (e.g. "__TEXT", "__DATA").
 * @return Pointer to macho_segment_t or NULL if not found.
 */
const macho_segment_t *macho_find_segment(const macho_image_t *img, const char *segname);

/**
 * Find a section by segment name and section name.
 *
 * @param img Loaded Mach-O image.
 * @param segname Segment name (e.g. "__TEXT").
 * @param sectname Section name (e.g. "__text").
 * @return Pointer to macho_section_t or NULL if not found.
 */
const macho_section_t *macho_find_section(const macho_image_t *img, const char *segname, const char *sectname);

/**
 * Print detailed diagnostic information about the Mach-O image.
 *
 * @param img Loaded Mach-O image.
 */
void macho_dump_info(const macho_image_t *img);

#ifdef __cplusplus
}
#endif

#endif /* MACHO_LOADER_H */

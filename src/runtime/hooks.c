#include "hooks.h"
#include "darwin_env.h"
#include "../loader/macho.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sys/time.h>
#include <mach/mach_time.h>
#include "../mock/iokit.h"

#define TRAMPOLINE_SLOT_SIZE 8 /* 2 instructions: NOP; RET */

/*
 * Dispatcher called by Unicorn whenever CPU executes within hook trampoline page
 */
static void hook_code_dispatch(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    (void)size;
    darwin_env_t *env = (darwin_env_t *)user_data;
    if (!env || !env->hooks) return;

    /* Check magic exit trampoline */
    if (address == env->magic_exit_addr) {
        uc_emu_stop(uc);
        return;
    }

    darwin_hook_manager_t *mgr = env->hooks;
    for (size_t i = 0; i < mgr->count; i++) {
        if (mgr->entries[i].addr == address) {
            if (mgr->entries[i].handler) {
                mgr->entries[i].handler(env, uc);
            }
            return;
        }
    }
}

/* ========================================================================= */
/*                              LibSystem Hooks                              */
/* ========================================================================= */

static void hook_malloc(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    uint64_t size = darwin_env_get_reg(env, UC_ARM64_REG_X0);
    uint64_t ptr = darwin_env_malloc(env, (size_t)size);
    darwin_env_set_return(env, ptr);
}

static void hook_calloc(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    uint64_t count = darwin_env_get_reg(env, UC_ARM64_REG_X0);
    uint64_t size = darwin_env_get_reg(env, UC_ARM64_REG_X1);
    uint64_t total = count * size;

    uint64_t ptr = darwin_env_malloc(env, (size_t)total);
    if (ptr && total > 0) {
        static const uint8_t zeros[4096] = {0};
        uint64_t cur = 0;
        while (cur < total) {
            uint64_t chunk = (total - cur > sizeof(zeros)) ? sizeof(zeros) : (total - cur);
            darwin_env_write_mem(env, ptr + cur, zeros, (size_t)chunk);
            cur += chunk;
        }
    }
    darwin_env_set_return(env, ptr);
}

static void hook_realloc(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    uint64_t old_ptr = darwin_env_get_reg(env, UC_ARM64_REG_X0);
    uint64_t new_size = darwin_env_get_reg(env, UC_ARM64_REG_X1);

    if (old_ptr == 0) {
        darwin_env_set_return(env, darwin_env_malloc(env, (size_t)new_size));
        return;
    }
    if (new_size == 0) {
        darwin_env_free(env, old_ptr);
        darwin_env_set_return(env, 0);
        return;
    }

    uint64_t new_ptr = darwin_env_malloc(env, (size_t)new_size);
    if (new_ptr && old_ptr) {
        uint8_t temp[4096];
        uint64_t copied = 0;
        while (copied < new_size) {
            uint64_t chunk = (new_size - copied > sizeof(temp)) ? sizeof(temp) : (new_size - copied);
            if (darwin_env_read_mem(env, old_ptr + copied, temp, (size_t)chunk) != 0) break;
            darwin_env_write_mem(env, new_ptr + copied, temp, (size_t)chunk);
            copied += chunk;
        }
    }
    darwin_env_set_return(env, new_ptr);
}

static void hook_free(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    uint64_t ptr = darwin_env_get_reg(env, UC_ARM64_REG_X0);
    darwin_env_free(env, ptr);
}

static void hook_posix_memalign(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    uint64_t memptr = darwin_env_get_reg(env, UC_ARM64_REG_X0);
    uint64_t size = darwin_env_get_reg(env, UC_ARM64_REG_X2);

    uint64_t ptr = darwin_env_malloc(env, (size_t)size);
    if (memptr) {
        darwin_env_write_mem(env, memptr, &ptr, sizeof(ptr));
    }
    darwin_env_set_return(env, 0);
}

static void hook_memcpy(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    uint64_t dst = darwin_env_get_reg(env, UC_ARM64_REG_X0);
    uint64_t src = darwin_env_get_reg(env, UC_ARM64_REG_X1);
    uint64_t n = darwin_env_get_reg(env, UC_ARM64_REG_X2);

    if (n > 0 && dst != src) {
        uint8_t buf[4096];
        uint64_t cur = 0;
        while (cur < n) {
            uint64_t chunk = (n - cur > sizeof(buf)) ? sizeof(buf) : (n - cur);
            darwin_env_read_mem(env, src + cur, buf, (size_t)chunk);
            darwin_env_write_mem(env, dst + cur, buf, (size_t)chunk);
            cur += chunk;
        }
    }
    darwin_env_set_return(env, dst);
}

static void hook_memset(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    uint64_t dst = darwin_env_get_reg(env, UC_ARM64_REG_X0);
    uint64_t c = darwin_env_get_reg(env, UC_ARM64_REG_X1) & 0xff;
    uint64_t n = darwin_env_get_reg(env, UC_ARM64_REG_X2);

    if (n > 0) {
        uint8_t buf[4096];
        memset(buf, (int)c, sizeof(buf));
        uint64_t cur = 0;
        while (cur < n) {
            uint64_t chunk = (n - cur > sizeof(buf)) ? sizeof(buf) : (n - cur);
            darwin_env_write_mem(env, dst + cur, buf, (size_t)chunk);
            cur += chunk;
        }
    }
    darwin_env_set_return(env, dst);
}

static void hook_bzero(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    uint64_t dst = darwin_env_get_reg(env, UC_ARM64_REG_X0);
    uint64_t n = darwin_env_get_reg(env, UC_ARM64_REG_X1);

    if (n > 0) {
        static const uint8_t zeros[4096] = {0};
        uint64_t cur = 0;
        while (cur < n) {
            uint64_t chunk = (n - cur > sizeof(zeros)) ? sizeof(zeros) : (n - cur);
            darwin_env_write_mem(env, dst + cur, zeros, (size_t)chunk);
            cur += chunk;
        }
    }
}

static void hook_strlen(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    uint64_t s = darwin_env_get_reg(env, UC_ARM64_REG_X0);
    uint64_t len = 0;
    char ch = 0;
    while (darwin_env_read_mem(env, s + len, &ch, 1) == 0 && ch != '\0') {
        len++;
    }
    darwin_env_set_return(env, len);
}

static void hook_strcmp(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    uint64_t s1 = darwin_env_get_reg(env, UC_ARM64_REG_X0);
    uint64_t s2 = darwin_env_get_reg(env, UC_ARM64_REG_X1);

    char str1[1024] = {0};
    char str2[1024] = {0};
    darwin_env_read_string(env, s1, str1, sizeof(str1));
    darwin_env_read_string(env, s2, str2, sizeof(str2));

    darwin_env_set_return(env, (uint64_t)(int64_t)strcmp(str1, str2));
}

static void hook_mach_timebase_info(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    uint64_t info_ptr = darwin_env_get_reg(env, UC_ARM64_REG_X0);
    struct mach_timebase_info info = {1, 1};
    mach_timebase_info(&info);
    if (info_ptr) {
        darwin_env_write_mem(env, info_ptr, &info, sizeof(info));
    }
    darwin_env_set_return(env, 0);
}

static void hook_mach_absolute_time(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    uint64_t now = mach_absolute_time();
    darwin_env_set_return(env, now);
}

static void hook_gettimeofday(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    uint64_t tv_ptr = darwin_env_get_reg(env, UC_ARM64_REG_X0);
    uint64_t tz_ptr = darwin_env_get_reg(env, UC_ARM64_REG_X1);

    struct timeval tv;
    struct timezone tz;
    int ret = gettimeofday(&tv, tz_ptr ? &tz : NULL);

    if (tv_ptr) {
        darwin_env_write_mem(env, tv_ptr, &tv, sizeof(tv));
    }
    if (tz_ptr) {
        darwin_env_write_mem(env, tz_ptr, &tz, sizeof(tz));
    }
    darwin_env_set_return(env, (uint64_t)ret);
}

static void hook_pthread_self(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    darwin_env_set_return(env, env->tls_addr);
}

static void hook_pthread_mutex_noop(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    darwin_env_set_return(env, 0);
}

static void hook_pthread_once(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    uint64_t once_control = darwin_env_get_reg(env, UC_ARM64_REG_X0);
    long val = 0;
    if (once_control) {
        darwin_env_read_mem(env, once_control, &val, sizeof(val));
        if (val == 0) {
            val = 1;
            darwin_env_write_mem(env, once_control, &val, sizeof(val));
        }
    }
    darwin_env_set_return(env, 0);
}

static void hook_dispatch_once(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    uint64_t predicate = darwin_env_get_reg(env, UC_ARM64_REG_X0);
    long val = 0;
    if (predicate) {
        darwin_env_read_mem(env, predicate, &val, sizeof(val));
        if (val != ~0L) {
            val = ~0L;
            darwin_env_write_mem(env, predicate, &val, sizeof(val));
        }
    }
}

static void hook_pthread_key_create(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    uint64_t key_ptr = darwin_env_get_reg(env, UC_ARM64_REG_X0);
    static uint32_t s_key_counter = 1;
    uint32_t key = s_key_counter++;
    if (key_ptr) {
        darwin_env_write_mem(env, key_ptr, &key, sizeof(key));
    }
    darwin_env_set_return(env, 0);
}

static void hook_pthread_getspecific(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    uint64_t key = darwin_env_get_reg(env, UC_ARM64_REG_X0);
    uint64_t val = 0;
    if (key < 256) {
        darwin_env_read_mem(env, env->tls_addr + 0x100 + key * 8, &val, 8);
    }
    darwin_env_set_return(env, val);
}

static void hook_pthread_setspecific(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    uint64_t key = darwin_env_get_reg(env, UC_ARM64_REG_X0);
    uint64_t val = darwin_env_get_reg(env, UC_ARM64_REG_X1);
    if (key < 256) {
        darwin_env_write_mem(env, env->tls_addr + 0x100 + key * 8, &val, 8);
    }
    darwin_env_set_return(env, 0);
}

static void hook_sysctlbyname(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    uint64_t name_ptr = darwin_env_get_reg(env, UC_ARM64_REG_X0);
    uint64_t oldp = darwin_env_get_reg(env, UC_ARM64_REG_X1);
    uint64_t oldlenp = darwin_env_get_reg(env, UC_ARM64_REG_X2);

    char name[128] = {0};
    darwin_env_read_string(env, name_ptr, name, sizeof(name));

    size_t oldlen = 0;
    if (oldlenp) {
        darwin_env_read_mem(env, oldlenp, &oldlen, sizeof(oldlen));
    }

    const char *str_val = NULL;
    uint64_t int_val = 0;
    bool is_int = false;

    const mac_hardware_profile_t *prof = mock_iokit_get_current_profile();

    if (strcmp(name, "hw.model") == 0) {
        str_val = prof ? prof->model : "MacBookPro18,1";
    } else if (strcmp(name, "hw.machine") == 0) {
        str_val = "arm64";
    } else if (strcmp(name, "kern.osrelease") == 0) {
        str_val = prof ? prof->darwin_version : "22.6.0";
    } else if (strcmp(name, "kern.osversion") == 0) {
        str_val = prof ? prof->os_build : "22G90";
    } else if (strcmp(name, "kern.osproductversion") == 0) {
        str_val = prof ? prof->os_version : "13.5";
    } else if (strcmp(name, "hw.ncpu") == 0 || strcmp(name, "hw.physicalcpu") == 0 || strcmp(name, "hw.logicalcpu") == 0) {
        int_val = 10;
        is_int = true;
    } else if (strcmp(name, "hw.memsize") == 0) {
        int_val = 16ULL * 1024 * 1024 * 1024;
        is_int = true;
    } else if (strcmp(name, "hw.pagesize") == 0) {
        int_val = 16384;
        is_int = true;
    }

    if (str_val) {
        size_t needed = strlen(str_val) + 1;
        if (oldp && oldlen > 0) {
            size_t copy_len = (needed < oldlen) ? needed : oldlen;
            darwin_env_write_mem(env, oldp, str_val, copy_len);
        }
        if (oldlenp) {
            darwin_env_write_mem(env, oldlenp, &needed, sizeof(needed));
        }
        darwin_env_set_return(env, 0);
    } else if (is_int) {
        size_t needed = sizeof(int_val);
        if (oldp && oldlen >= 4) {
            if (oldlen == 4) {
                uint32_t val32 = (uint32_t)int_val;
                darwin_env_write_mem(env, oldp, &val32, 4);
            } else {
                darwin_env_write_mem(env, oldp, &int_val, sizeof(int_val));
            }
        }
        if (oldlenp) {
            darwin_env_write_mem(env, oldlenp, &needed, sizeof(needed));
        }
        darwin_env_set_return(env, 0);
    } else {
        darwin_env_set_return(env, (uint64_t)(int64_t)-1);
    }
}

static void hook_getenv(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    darwin_env_set_return(env, 0);
}

static void hook_abort(darwin_env_t *env, uc_engine *uc) {
    fprintf(stderr, "[darwin_hooks] abort() called by guest emulator\n");
    uc_emu_stop(uc);
    darwin_env_set_return(env, 0);
}

static void hook_os_log_create(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    uint64_t dummy = darwin_env_malloc(env, 16);
    darwin_env_set_return(env, dummy);
}

static void hook_os_log_noop(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    darwin_env_set_return(env, 0);
}

/* ========================================================================= */
/*                           Hook Manager Core                               */
/* ========================================================================= */

int darwin_hooks_init(darwin_env_t *env) {
    if (!env || !env->uc) return -1;

    darwin_hook_manager_t *mgr = (darwin_hook_manager_t *)calloc(1, sizeof(darwin_hook_manager_t));
    if (!mgr) return -1;

    mgr->capacity = 128;
    mgr->entries = (darwin_hook_entry_t *)calloc(mgr->capacity, sizeof(darwin_hook_entry_t));
    mgr->next_trampoline = env->hook_trampoline_base;

    /* Register Unicorn code hook on the whole trampoline region */
    uc_err err = uc_hook_add(env->uc, &mgr->uc_code_hook, UC_HOOK_CODE,
                             (void *)hook_code_dispatch, env,
                             env->hook_trampoline_base,
                             env->hook_trampoline_base + env->hook_trampoline_size);
    if (err != UC_ERR_OK) {
        fprintf(stderr, "[darwin_hooks] Error: uc_hook_add failed: %d (%s)\n", err, uc_strerror(err));
        free(mgr->entries);
        free(mgr);
        return -1;
    }

    env->hooks = mgr;

    /* Register Memory & String Hooks */
    darwin_hooks_register(env, "malloc", hook_malloc);
    darwin_hooks_register(env, "calloc", hook_calloc);
    darwin_hooks_register(env, "realloc", hook_realloc);
    darwin_hooks_register(env, "free", hook_free);
    darwin_hooks_register(env, "posix_memalign", hook_posix_memalign);
    darwin_hooks_register(env, "memcpy", hook_memcpy);
    darwin_hooks_register(env, "memmove", hook_memcpy);
    darwin_hooks_register(env, "memset", hook_memset);
    darwin_hooks_register(env, "bzero", hook_bzero);
    darwin_hooks_register(env, "strlen", hook_strlen);
    darwin_hooks_register(env, "strcmp", hook_strcmp);

    /* Register Time Hooks */
    darwin_hooks_register(env, "mach_timebase_info", hook_mach_timebase_info);
    darwin_hooks_register(env, "mach_absolute_time", hook_mach_absolute_time);
    darwin_hooks_register(env, "gettimeofday", hook_gettimeofday);

    /* Register Threading & Sync Hooks */
    darwin_hooks_register(env, "pthread_self", hook_pthread_self);
    darwin_hooks_register(env, "pthread_mutex_init", hook_pthread_mutex_noop);
    darwin_hooks_register(env, "pthread_mutex_lock", hook_pthread_mutex_noop);
    darwin_hooks_register(env, "pthread_mutex_unlock", hook_pthread_mutex_noop);
    darwin_hooks_register(env, "pthread_mutex_destroy", hook_pthread_mutex_noop);
    darwin_hooks_register(env, "pthread_once", hook_pthread_once);
    darwin_hooks_register(env, "dispatch_once", hook_dispatch_once);
    darwin_hooks_register(env, "dispatch_once_f", hook_dispatch_once);
    darwin_hooks_register(env, "pthread_key_create", hook_pthread_key_create);
    darwin_hooks_register(env, "pthread_getspecific", hook_pthread_getspecific);
    darwin_hooks_register(env, "pthread_setspecific", hook_pthread_setspecific);

    /* Register System Hooks */
    darwin_hooks_register(env, "sysctlbyname", hook_sysctlbyname);
    darwin_hooks_register(env, "getenv", hook_getenv);
    darwin_hooks_register(env, "abort", hook_abort);
    darwin_hooks_register(env, "os_log_create", hook_os_log_create);
    darwin_hooks_register(env, "_os_log_impl", hook_os_log_noop);
    darwin_hooks_register(env, "os_log_type_enabled", hook_os_log_noop);

    return 0;
}

void darwin_hooks_cleanup(darwin_env_t *env) {
    if (!env || !env->hooks) return;
    darwin_hook_manager_t *mgr = env->hooks;

    if (mgr->entries) {
        for (size_t i = 0; i < mgr->count; i++) {
            if (mgr->entries[i].name) {
                free(mgr->entries[i].name);
            }
        }
        free(mgr->entries);
    }

    free(mgr);
    env->hooks = NULL;
}

uint64_t darwin_hooks_register(darwin_env_t *env, const char *symbol_name, darwin_hook_fn handler) {
    if (!env || !env->hooks || !symbol_name || !handler) return 0;
    darwin_hook_manager_t *mgr = env->hooks;

    /* Check if already registered */
    uint64_t existing = darwin_hooks_find(env, symbol_name);
    if (existing != 0) return existing;

    /* Resize if full */
    if (mgr->count >= mgr->capacity) {
        mgr->capacity *= 2;
        mgr->entries = (darwin_hook_entry_t *)realloc(mgr->entries, mgr->capacity * sizeof(darwin_hook_entry_t));
    }

    uint64_t trampoline_addr = mgr->next_trampoline;
    mgr->next_trampoline += TRAMPOLINE_SLOT_SIZE;

    /* Write ARM64 trampoline instructions: NOP; RET */
    static const uint32_t insns[2] = {
        0xd503201f, /* NOP */
        0xd65f03c0  /* RET (LR) */
    };
    uc_mem_write(env->uc, trampoline_addr, insns, sizeof(insns));

    darwin_hook_entry_t *entry = &mgr->entries[mgr->count++];
    entry->name = strdup(symbol_name);
    entry->addr = trampoline_addr;
    entry->handler = handler;

    return trampoline_addr;
}

uint64_t darwin_hooks_find(darwin_env_t *env, const char *symbol_name) {
    if (!env || !env->hooks || !symbol_name) return 0;
    darwin_hook_manager_t *mgr = env->hooks;

    /* Check exact name */
    for (size_t i = 0; i < mgr->count; i++) {
        if (strcmp(mgr->entries[i].name, symbol_name) == 0) {
            return mgr->entries[i].addr;
        }
    }

    /* Check with/without underscore */
    if (symbol_name[0] == '_') {
        const char *stripped = symbol_name + 1;
        for (size_t i = 0; i < mgr->count; i++) {
            if (strcmp(mgr->entries[i].name, stripped) == 0) {
                return mgr->entries[i].addr;
            }
        }
    } else {
        char buf[256];
        snprintf(buf, sizeof(buf), "_%s", symbol_name);
        for (size_t i = 0; i < mgr->count; i++) {
            if (strcmp(mgr->entries[i].name, buf) == 0) {
                return mgr->entries[i].addr;
            }
        }
    }

    return 0;
}

int darwin_hooks_bind_macho(darwin_env_t *env, macho_image_t *img) {
    if (!env || !img) return 0;
    int bound_count = 0;

    /* 1. Bind GOT sections (__got, __auth_got) */
    const char *got_sections[] = {"__got", "__auth_got"};
    for (size_t g = 0; g < 2; g++) {
        for (size_t i = 0; i < img->num_segments; i++) {
            const macho_segment_t *seg = &img->segments[i];
            for (uint32_t s = 0; s < seg->nsects; s++) {
                const macho_section_t *sec = &seg->sections[s];
                if (strcmp(sec->sectname, got_sections[g]) == 0 && sec->size >= 8) {
                    /* Scan pointers in GOT */
                    size_t num_ptrs = (size_t)(sec->size / 8);
                    for (size_t p = 0; p < num_ptrs; p++) {
                        uint64_t got_slot_addr = sec->addr + (uint64_t)img->slide + p * 8;
                        /* Check symbols to see which symbol corresponds to this got entry */
                        for (size_t sym_i = 0; sym_i < img->num_symbols; sym_i++) {
                            const macho_symbol_t *sym = &img->symbols[sym_i];
                            if (sym->value == got_slot_addr - (uint64_t)img->slide) {
                                uint64_t hook_addr = darwin_hooks_find(env, sym->name);
                                if (hook_addr) {
                                    darwin_env_write_mem(env, got_slot_addr, &hook_addr, 8);
                                    bound_count++;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return bound_count;
}

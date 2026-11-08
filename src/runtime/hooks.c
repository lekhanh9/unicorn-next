#include "hooks.h"
#include "darwin_env.h"
#if __has_include("../loader/macho.h")
#include "../loader/macho.h"
#include "../mock/iokit.h"
#else
#include "macho.h"
#include "iokit.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sys/time.h>
#include <mach/mach_time.h>

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
            uint64_t lr = darwin_env_get_reg(env, UC_ARM64_REG_LR);
            printf("[HOOK_CALL] -> %s (LR=0x%llx)\n", mgr->entries[i].name, (unsigned long long)lr);
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
    printf("[HOOK_MALLOC] size=%llu -> ptr=0x%llx\n", (unsigned long long)size, (unsigned long long)ptr);
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

#include <mach/mach.h>
extern mach_port_t bootstrap_port;
extern kern_return_t bootstrap_look_up(mach_port_t, const char *, mach_port_t *);
extern mach_port_t mig_get_reply_port(void);

static mach_port_t g_host_adid_port = MACH_PORT_NULL;
static bool g_host_adid_tried = false;

static mach_port_t get_host_adid_port(void) {
    if (!g_host_adid_tried) {
        g_host_adid_tried = true;
        kern_return_t kr = bootstrap_look_up(bootstrap_port, "com.apple.adid", &g_host_adid_port);
        if (kr == KERN_SUCCESS) {
            printf("[MACH_MSG] Successfully connected to host com.apple.adid (port=0x%x)!\n", g_host_adid_port);
        } else {
            printf("[MACH_MSG] Host com.apple.adid not available (kr=%d), using local synthesis.\n", kr);
        }
    }
    return g_host_adid_port;
}

static void hook_mach_msg(darwin_env_t *env, uc_engine *uc) {
    (void)uc;
    uint64_t msg_ptr = darwin_env_get_reg(env, UC_ARM64_REG_X0);
    uint32_t option = (uint32_t)darwin_env_get_reg(env, UC_ARM64_REG_X1);
    uint32_t send_size = (uint32_t)darwin_env_get_reg(env, UC_ARM64_REG_X2);
    uint32_t rcv_size = (uint32_t)darwin_env_get_reg(env, UC_ARM64_REG_X3);

    mach_msg_header_t hdr;
    darwin_env_read_mem(env, msg_ptr, &hdr, sizeof(hdr));
    printf("[MACH_MSG] option=0x%x, send_size=%u, rcv_size=%u, remote_port=0x%x, msgh_id=%d (0x%x)\n",
           option, send_size, rcv_size, hdr.msgh_remote_port, hdr.msgh_id, hdr.msgh_id);

    uint8_t payload[64] = {0};
    size_t payload_len = (send_size > sizeof(hdr)) ? (send_size - sizeof(hdr)) : 0;
    if (payload_len > sizeof(payload)) payload_len = sizeof(payload);
    darwin_env_read_mem(env, msg_ptr + sizeof(hdr), payload, payload_len);
    printf("[MACH_MSG] Payload: ");
    for (size_t i = 0; i < payload_len && i < 24; i++) {
        printf("%02x ", payload[i]);
    }
    printf("\n");

    /* If it was a send+receive request, synthesize standard MIG reply */
    if (option & 2) { /* MACH_RCV_MSG */
        if (hdr.msgh_id == 1200) {
            /* Complex MIG reply for com.apple.adid.midchanged */
            typedef struct {
                mach_msg_header_t Head;
                mach_msg_body_t Body;
                struct {
                    uint64_t address;
                    uint8_t deallocate;
                    uint8_t copy;
                    uint8_t pad1;
                    uint8_t type;
                    uint32_t size;
                } __attribute__((packed)) ool;
                uint32_t NDR[2];
                uint32_t count;
            } __attribute__((packed)) mig_reply_1200_t;

            mig_reply_1200_t reply;
            memset(&reply, 0, sizeof(reply));
            reply.Head.msgh_bits = 0x80000012; /* MACH_MSGH_BITS_COMPLEX */
            reply.Head.msgh_size = sizeof(reply); /* 56 */
            reply.Head.msgh_remote_port = 0;
            reply.Head.msgh_local_port = 0;
            reply.Head.msgh_id = 1300;
            reply.Body.msgh_descriptor_count = 1;

            struct {
                mach_msg_body_t Body;
                struct {
                    uint64_t address;
                    uint8_t deallocate;
                    uint8_t copy;
                    uint8_t pad1;
                    uint8_t type;
                    uint32_t size;
                } __attribute__((packed)) ool;
                uint32_t NDR[2];
                uint32_t count;
            } __attribute__((packed)) req_body;
            darwin_env_read_mem(env, msg_ptr + sizeof(mach_msg_header_t), &req_body, sizeof(req_body));

            printf("[MACH_MSG 1200] req: in_addr=0x%llx, in_size=%u, count=%u\n",
                   (unsigned long long)req_body.ool.address, req_body.ool.size, req_body.count);

            uint8_t host_req_buf[64] = {0};
            uint32_t req_sz = req_body.ool.size ? req_body.ool.size : 20;
            if (req_sz > sizeof(host_req_buf)) req_sz = sizeof(host_req_buf);
            if (req_body.ool.address && req_sz > 0) {
                darwin_env_read_mem(env, req_body.ool.address, host_req_buf, req_sz);
                printf("[MACH_MSG 1200] in_buf (len=%u): ", req_sz);
                for (uint32_t i = 0; i < req_sz && i < 48; i++) {
                    printf("%02x ", host_req_buf[i]);
                }
                printf("\n");
            }

            mach_port_t real_port = get_host_adid_port();
            bool forwarded = false;
            if (real_port != MACH_PORT_NULL) {
                mach_port_t real_reply_port = mig_get_reply_port();

                struct {
                    mach_msg_header_t Head;
                    mach_msg_body_t Body;
                    struct {
                        void *address;
                        uint8_t deallocate;
                        uint8_t copy;
                        uint8_t pad1;
                        uint8_t type;
                        uint32_t size;
                    } __attribute__((packed)) ool;
                    uint32_t NDR[2];
                    uint32_t count;
                } __attribute__((packed)) real_req;

                memset(&real_req, 0, sizeof(real_req));
                real_req.Head.msgh_bits = 0x80001513;
                real_req.Head.msgh_size = sizeof(real_req);
                real_req.Head.msgh_remote_port = real_port;
                real_req.Head.msgh_local_port = real_reply_port;
                real_req.Head.msgh_id = 1200;
                real_req.Body.msgh_descriptor_count = 1;
                real_req.ool.address = host_req_buf;
                real_req.ool.type = 1;
                real_req.ool.copy = 1;
                real_req.ool.size = req_sz;
                real_req.count = req_sz;

                uint8_t real_reply_bytes[128] = {0};
                mach_msg_return_t mr = mach_msg(
                    (mach_msg_header_t *)&real_req,
                    MACH_SEND_MSG | MACH_RCV_MSG,
                    sizeof(real_req),
                    sizeof(real_reply_bytes),
                    real_reply_port,
                    1000,
                    MACH_PORT_NULL
                );

                if (mr == MACH_MSG_SUCCESS) {
                    mach_msg_header_t *rh = (mach_msg_header_t *)real_reply_bytes;
                    printf("[MACH_MSG 1200] Host adid replied: bits=0x%x, size=%u, id=%d\n",
                           rh->msgh_bits, rh->msgh_size, rh->msgh_id);
                    if (rh->msgh_bits & 0x80000000) {
                        mig_reply_1200_t *r_rep = (void *)real_reply_bytes;
                        uint32_t out_len = r_rep->count;
                        uint64_t reply_buf = darwin_env_malloc(env, out_len);
                        if (r_rep->ool.address && out_len > 0) {
                            darwin_env_write_mem(env, reply_buf, (const void *)r_rep->ool.address, out_len);
                        }

                        reply.ool.address = reply_buf;
                        reply.ool.deallocate = 0;
                        reply.ool.copy = 0;
                        reply.ool.pad1 = 0;
                        reply.ool.type = 1;
                        reply.ool.size = out_len;
                        reply.NDR[0] = 0;
                        reply.NDR[1] = 0;
                        reply.count = out_len;

                        darwin_env_write_mem(env, msg_ptr, &reply, sizeof(reply));
                        forwarded = true;
                        printf("[MACH_MSG 1200] Successfully forwarded host reply (len=%u) to Unicorn!\n", out_len);
                    }
                } else {
                    printf("[MACH_MSG 1200] Host adid mach_msg returned 0x%x, using fallback.\n", mr);
                }
            }

            if (!forwarded) {
                /* Synthesize exact adid daemon reply (echo in_buf with status 0) */
                uint32_t out_len = (req_sz >= 20) ? req_sz : 20;
                uint64_t reply_buf = darwin_env_malloc(env, out_len);
                uint8_t temp[64] = {0};
                if (req_sz > 0) {
                    memcpy(temp, host_req_buf, (req_sz < sizeof(temp)) ? req_sz : sizeof(temp));
                }
                /* Byte 0..3: status = 0 (SUCCESS) */
                temp[0] = 0; temp[1] = 0; temp[2] = 0; temp[3] = 0;
                /* Byte 4..7: count/length = 8 */
                temp[4] = 0; temp[5] = 0; temp[6] = 0; temp[7] = 0x08;
                darwin_env_write_mem(env, reply_buf, temp, out_len);

                reply.ool.address = reply_buf;
                reply.ool.deallocate = 0;
                reply.ool.copy = 0;
                reply.ool.pad1 = 0;
                reply.ool.type = 1; /* MACH_MSG_OOL_DESCRIPTOR */
                reply.ool.size = out_len;
                reply.NDR[0] = 0;
                reply.NDR[1] = 0;
                reply.count = out_len;

                darwin_env_write_mem(env, msg_ptr, &reply, sizeof(reply));
                printf("[MACH_MSG 1200] Synthesized adid daemon fallback reply (size=%zu): msgh_id=1300, code=-45061\n",
                       sizeof(reply));
            }
        } else {
            struct {
                mach_msg_header_t Head;
                uint32_t NDR[2];
                int32_t RetCode;
                uint8_t dummy[64];
            } reply;
            memset(&reply, 0, sizeof(reply));
            reply.Head.msgh_bits = 0x12;
            reply.Head.msgh_size = (rcv_size < sizeof(reply)) ? rcv_size : sizeof(reply);
            reply.Head.msgh_remote_port = 0;
            reply.Head.msgh_local_port = 0;
            reply.Head.msgh_id = hdr.msgh_id + 100; /* MIG reply convention */
            reply.RetCode = 0; /* KERN_SUCCESS */

            darwin_env_write_mem(env, msg_ptr, &reply, (rcv_size < sizeof(reply)) ? rcv_size : sizeof(reply));
            printf("[MACH_MSG] Synthesized MIG reply for msgh_id=%d, RetCode=0!\n", reply.Head.msgh_id);
        }
    }

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
    darwin_hooks_register(env, "mach_msg", hook_mach_msg);
    darwin_hooks_register(env, "_mach_msg", hook_mach_msg);

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

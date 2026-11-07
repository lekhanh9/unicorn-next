#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mach/mach.h>
#include <mach/message.h>

extern kern_return_t bootstrap_look_up(mach_port_t, const char *, mach_port_t *);
extern mach_port_t mig_get_reply_port(void);

int main(void) {
    mach_port_t bp = bootstrap_port;
    mach_port_t sp = MACH_PORT_NULL;

    kern_return_t kr = bootstrap_look_up(bp, "com.apple.adid", &sp);
    printf("[REAL_ADID] bootstrap_look_up com.apple.adid -> kr=%d, port=0x%x\n", kr, sp);
    if (kr != KERN_SUCCESS) return 1;

    mach_port_t reply_port = mig_get_reply_port();

    /* Prepare request buffer (20 bytes) */
    uint8_t req_data[20] = {
        0x00, 0x00, 0x00, 0x01,
        0xcf, 0xe0, 0xb4, 0x6a,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };

    typedef struct {
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
    } __attribute__((packed)) Request;

    typedef struct {
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
        uint8_t trailer[64];
    } __attribute__((packed)) Reply;

    union {
        Request req;
        Reply reply;
    } msg;

    memset(&msg, 0, sizeof(msg));
    msg.req.Head.msgh_bits = 0x80001513; // MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE)
    msg.req.Head.msgh_size = sizeof(Request);
    msg.req.Head.msgh_remote_port = sp;
    msg.req.Head.msgh_local_port = reply_port;
    msg.req.Head.msgh_voucher_port = MACH_PORT_NULL;
    msg.req.Head.msgh_id = 1200;

    msg.req.Body.msgh_descriptor_count = 1;
    msg.req.ool.address = req_data;
    msg.req.ool.deallocate = 0;
    msg.req.ool.copy = 1; // MACH_MSG_PHYSICAL_COPY
    msg.req.ool.pad1 = 0;
    msg.req.ool.type = 1; // MACH_MSG_OOL_DESCRIPTOR
    msg.req.ool.size = sizeof(req_data);

    msg.req.NDR[0] = 0;
    msg.req.NDR[1] = 0;
    msg.req.count = sizeof(req_data);

    printf("[REAL_ADID] Sending mach_msg 1200 to com.apple.adid...\n");
    mach_msg_return_t mr = mach_msg(
        &msg.req.Head,
        MACH_SEND_MSG | MACH_RCV_MSG,
        sizeof(Request),
        sizeof(Reply),
        reply_port,
        MACH_MSG_TIMEOUT_NONE,
        MACH_PORT_NULL
    );

    printf("[REAL_ADID] mach_msg returned: 0x%x (%d)\n", mr, mr);
    if (mr == MACH_MSG_SUCCESS) {
        printf("[REAL_ADID] Reply Head: msgh_bits=0x%x, msgh_size=%u, msgh_id=%d\n",
               msg.reply.Head.msgh_bits, msg.reply.Head.msgh_size, msg.reply.Head.msgh_id);
        if (msg.reply.Head.msgh_bits & MACH_MSGH_BITS_COMPLEX) {
            printf("[REAL_ADID] COMPLEX REPLY! Reply Body: desc_count=%u\n", msg.reply.Body.msgh_descriptor_count);
            printf("[REAL_ADID] Reply OOL: addr=%p, size=%u, type=%u\n",
                   msg.reply.ool.address, msg.reply.ool.size, msg.reply.ool.type);
            printf("[REAL_ADID] Reply count=%u\n", msg.reply.count);

            if (msg.reply.ool.address && msg.reply.ool.size > 0) {
                uint8_t *data = (uint8_t *)msg.reply.ool.address;
                printf("[REAL_ADID] Reply Data (%u bytes): ", msg.reply.ool.size);
                for (uint32_t i = 0; i < msg.reply.ool.size; i++) {
                    printf("%02x ", data[i]);
                }
                printf("\n");
            }
        } else {
            /* Simple reply / error */
            struct {
                mach_msg_header_t Head;
                uint32_t NDR[2];
                int32_t RetCode;
            } *err_reply = (void *)&msg;
            printf("[REAL_ADID] SIMPLE REPLY / RetCode = %d (0x%x)\n",
                   err_reply->RetCode, err_reply->RetCode);
        }
    }

    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mach/mach.h>

extern kern_return_t bootstrap_look_up(mach_port_t, const char *, mach_port_t *);

int main(void) {
    mach_port_t bp = bootstrap_port;
    mach_port_t sp = MACH_PORT_NULL;

    const char *services[] = {
        "com.apple.adid",
        "com.apple.adid.xpc",
        "com.apple.adid.midchangedV1.5",
        "com.apple.adid.midchangedV3",
        "com.apple.adid.midchangedV1",
        NULL
    };

    for (int i = 0; services[i]; i++) {
        kern_return_t kr = bootstrap_look_up(bp, services[i], &sp);
        printf("[LOOKUP] %-30s -> kr=%d (port=0x%x)\n", services[i], kr, sp);
        if (kr == KERN_SUCCESS && sp != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), sp);
        }
    }
    return 0;
}

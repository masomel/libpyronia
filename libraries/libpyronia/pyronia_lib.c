#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <kernel_comm.h>
#include <linux/pyronia_netlink.h>

#define FAMILY_STR "SI_COMM"

static int nl_sock;
static int nl_fam;
static uint32_t nl_port;

/* libpyronia-specific wrapper around send_message in kernel_comm.h */
int pyr_to_kernel(int nl_cmd, int nl_attr, char *msg) {
    return send_message(nl_sock, nl_fam, nl_cmd, nl_attr, nl_port, msg);
}

/* Do all the necessary setup for a language runtime to use
 * the Pyronia extensions: open the stack inspection communication
 * channel and initialize the SMV backend.
 */
int pyr_init() {
    int err = 0;

    /* Open the netlink socket */
    nl_sock = create_netlink_socket(0);
    if(nl_sock < 0){
        printf("create netlink socket failure\n");
        return 0;
    }

    nl_port = getpid();

    nl_fam = get_family_id(nl_sock, nl_port, FAMILY_STR);

    // We don't want the main thread's memdom to be
    // globally accessible, so init with 0.
    // err = smv_main_init(0);

    return err;
}

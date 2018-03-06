#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <signal.h>
#include <linux/sched.h>
#include <linux/genetlink.h>
#include "kernel_comm.h"
#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <netlink/socket.h>
#include <netlink/genl/genl.h>

#include "kernel_comm.h"
#include "callstack.h"

struct nl_sock *sock;
uint32_t port_num;
int family_id;

#define GENLMSG_DATA(glh) ((void *)(NLMSG_DATA(glh) + GENL_HDRLEN))
#define GENLMSG_PAYLOAD(glh) (NLMSG_PAYLOAD(glh, 0) - GENL_HDRLEN)
#define NLA_DATA(na) ((void *)((char*)(na) + NLA_HDRLEN))

static int message_to_kernel(char* message) {
    int err = 0;

    // TODO: we probably want to use genlmsg_put and such here
    err = nl_send_simple(sock, family_id, NLMSG_DONE, message,
                         strlen(message)+1);
    if (err < 0) {
        rlog("Error sending message to kernel: %d\n", err);
    }
    else {
        rlog("Sent %d bytes to kernel\n", err);
        err = 0;
    }

    return err;
}

/* Handle a callstack request from the kernel by calling
 * the callstack generator in the callstack library.
 * Once the callstack is generated, serialize and send the
 * callstack back to the kernel.
 */
static int handle_callstack_request(struct nl_msg *msg, void *arg) {
    // FIXME: Don't just echo back the kernel's message

    int *reqp;

    reqp = nlmsg_data(nlmsg_hdr(msg));
    printf("Kernel sent request: %d\n", *reqp);

    return message_to_kernel("ACK");

}

int init_si_kernel_comm() {
    int err;

    sock = nl_socket_alloc();
    if (!sock) {
        rlog("Could not allocate SI netlink socket\n");
        return -1;
    }

    port_num = nl_socket_get_local_port(sock);

    family_id = genl_ctrl_resolve(sock, "SI_COMM");

    // TODO: register the port number with the kernel

    err = nl_socket_modify_cb(sock, NL_CB_FINISH, NL_CB_CUSTOM,
                                handle_callstack_request, NULL);
    if (err < 0) {
        rlog("Could not register receive callback function. Error = %d\n", err);
        goto error;
    }

    err = genl_connect(sock);
    if (err) {
        rlog("SI netlink socket connection failed: %d\n", err);
        goto error;
    }

    return 0;

 error:
    rlog("Following libnl error occurred: %s\n", nl_geterror(err));
    nl_socket_free(sock);
    return err;
}

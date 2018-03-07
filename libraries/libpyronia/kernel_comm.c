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
    struct nlmsghdr *nl_hdr;
    struct genlmsghdr *genl_hdr;
    struct nlattr *attrs[SI_COMM_A_MAX];
    uint8_t *reqp;
    int err;

    rlog("The kernel module sent a message.\n");

    nl_hdr = nlmsg_hdr(msg);
    genl_hdr = genlmsg_hdr(nl_hdr);

    if (genl_hdr->cmd != SI_COMM_C_STACK_REQ) {
        rlog("Unsupported command %d\n", genl_hdr->cmd);
        return 0;
    }

    err = genlmsg_parse(nl_hdr, 0, attrs, SI_COMM_A_MAX, si_comm_genl_policy[1]);
    if (err)
        return nl_fail(err, "genlmsg_parse");

    // ignore any attributes other than the KERN_REQ
    if (attrs[SI_COMM_A_KERN_REQ]) {
        reqp = (uint8_t *)nla_data(attrs[SI_COMM_A_KERN_REQ));
        if (*reqp != STACK_REQ_CMD) {
            rlog("Unexpected kernel message: %u\n", *reqp);
            return -1;
        }
    }
    else {
        rlog("Null message from the kernel message\n");
        return -1;
    }

    // FIXME: Go collect the callstack and serialize it
    return message_to_kernel("ACK");
}

int init_si_kernel_comm() {
    int err;

    sock = nl_socket_alloc();
    if (!sock) {
        rlog("Could not allocate SI netlink socket\n");
        return -1;
    }
    nl_socket_disable_seq_check(sock);

    port_num = nl_socket_get_local_port(sock);

    family_id = genl_ctrl_resolve(sock, "SI_COMM");

    // TODO: register the port number with the kernel

    err = nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM,
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

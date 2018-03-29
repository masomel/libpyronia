#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <kernel_comm.h>
#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <netlink/socket.h>
#include <netlink/genl/genl.h>
#include <linux/pyronia_netlink.h>
#include <linux/pyronia_mac.h>

#include "pyronia_lib.h"

#define FAMILY_STR "SI_COMM"

static struct nl_sock *si_sock;
static int nl_sock;
static int nl_fam;
static uint32_t si_port;
static uint32_t nl_port;
static struct pyr_runtime *runtime;

/* libpyronia-specific wrapper around send_message in kernel_comm.h */
int pyr_to_kernel(int nl_cmd, int nl_attr, char *msg) {
    return send_message(nl_sock, nl_fam, nl_cmd, nl_attr, nl_port, msg);
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
    pyr_cg_node_t *callstack;
    int err;

    printf("The kernel module sent a message.\n");

    nl_hdr = nlmsg_hdr(msg);
    genl_hdr = genlmsg_hdr(nl_hdr);

    if (genl_hdr->cmd != SI_COMM_C_STACK_REQ) {
        printf("Unsupported command %d\n", genl_hdr->cmd);
        return 0;
    }

    err = genlmsg_parse(nl_hdr, 0, attrs, SI_COMM_A_MAX, si_comm_genl_policy);
    if (err)
      return err;

    // ignore any attributes other than the KERN_REQ
    if (attrs[SI_COMM_A_KERN_REQ]) {
        reqp = (uint8_t *)nla_data(attrs[SI_COMM_A_KERN_REQ]);
        if (*reqp != STACK_REQ_CMD) {
            printf("Unexpected kernel message: %u\n", *reqp);
            return -1;
        }
    }
    else {
        printf("Null message from the kernel message\n");
        return -1;
    }

    // Collect the callstack
    //callstack = runtime->collect_callstack_cb();

 out:
    return pyr_to_kernel(SI_COMM_C_STACK_REQ, SI_COMM_A_USR_MSG, "ACK");
}

static int init_si_kernel_comm() {
    int err;

    si_sock = nl_socket_alloc();
    if (!si_sock) {
        printf("Could not allocate SI netlink socket\n");
        return -1;
    }
    nl_socket_disable_seq_check(si_sock);
    nl_socket_disable_auto_ack(si_sock);

    si_port = nl_socket_get_local_port(si_sock);

    err = nl_socket_modify_cb(si_sock, NL_CB_VALID, NL_CB_CUSTOM,
                                handle_callstack_request, NULL);
    if (err < 0) {
        printf("Could not register receive callback function. Error = %d\n", err);
        goto error;
    }

    err = genl_connect(si_sock);
    if (err) {
        printf("SI netlink socket connection failed: %d\n", err);
        goto error;
    }

    return 0;

 error:
    printf("Following libnl error occurred: %s\n", nl_geterror(err));
    nl_socket_free(si_sock);
    return err;
}

/* Do all the necessary setup for a language runtime to use
 * the Pyronia extensions: open the stack inspection communication
 * channel and initialize the SMV backend.
 */
int pyr_init() {
    int err = 0;
    char str[12];

    /* Open the netlink socket */
    nl_sock = create_netlink_socket(0);
    if(nl_sock < 0){
        printf("create netlink socket failure\n");
        return 0;
    }

    /* Initialize the SI socket */
    err = init_si_kernel_comm();
    if (err) {
        printf("SI socket initialization failure\n");
    }

    nl_port = getpid();
    nl_fam = get_family_id(nl_sock, nl_port, FAMILY_STR);

    printf("[%s] Initialized socket at port %d; SI_COMM family id = %d\n",
           __func__, nl_port, nl_fam);

    sprintf(str, "%d", nl_port);
    err = pyr_to_kernel(SI_COMM_C_REGISTER_PROC, SI_COMM_A_USR_MSG, str);

    // We don't want the main thread's memdom to be
    // globally accessible, so init with 0.
    // err = smv_main_init(0);

    return err;
}

int pyr_init_runtime(pyr_cg_node_t *(*collect_callstack)(void)) {
    struct pyr_runtime *r;
    int err = 0;

    // TODO: allocate this in the secure memdom
    r = malloc(sizeof(struct pyr_runtime));
    if (!r) {
        printf("[%s] No memory for runtime properties\n", __func__);
        err = -ENOMEM;
        goto out;
    }

    if (!collect_callstack) {
        printf("[%s] Need non-null callstack collect callback\n", __func__);
        err = -EINVAL;
        goto out;
    }
    r->collect_callstack_cb = collect_callstack;
    runtime = r;

 out:
    free(r);
    return err;
}

/* Do all necessary teardown actions. */
void pyr_exit() {
  close(nl_sock);
}

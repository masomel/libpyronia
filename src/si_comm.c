/** Implements the Pyronia kernel communication definitions for
 * receiving callstack requests and sending back serialized callgraphs.
 *
 *@author Marcela S. Melara
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <kernel_comm.h>
#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <netlink/socket.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <linux/pyronia_netlink.h>

#include "si_comm.h"
#include "serialization.h"

static struct nl_sock *si_sock = NULL;
static int nl_fam = 0;
static uint32_t si_port = 0;
static pthread_t recv_th;

/* libpyronia-specific wrapper around send_message in kernel_comm.h */
static int pyr_to_kernel(int nl_cmd, int nl_attr, char *msg) {
  int err = -1;
  char *m = NULL;

  if (!msg)
      m = "ERR";
  else
      m = msg;

  err = send_message(nl_socket_get_fd(si_sock), nl_fam, nl_cmd, nl_attr, si_port, m);

 out:
  return err;
}

// this gets called in a separate receiver thread
// so just make the function signature fit what pthread_create expects
static void *pyr_recv_from_kernel(void *args) {
  int err = 0;

  while(1) {
    printf("[%s] Listening at port %d\n", __func__, si_port);

    // Receive messages
    err = nl_recvmsgs_default(si_sock);
    if (err < 0) {
      printf("[%s] Error: %d\n", __func__, err);
      break;
    }
  }
  return NULL;
}

/* Handle a callstack request from the kernel by calling
 * the callstack generator in the callstack library.
 * Once the callstack is generated, serialize and send the
 * callstack back to the kernel.
 */
static int pyr_handle_callstack_request(struct nl_msg *msg, void *arg) {
    struct nlmsghdr *nl_hdr = NULL;
    struct genlmsghdr *genl_hdr = NULL;
    struct nlattr *attrs[SI_COMM_A_MAX];
    uint8_t *reqp = NULL;
    pyr_cg_node_t *callstack = NULL;
    char *callstack_str = NULL;
    int err = -1;

    printf("[%s] The kernel module sent a message.\n", __func__);

    nl_hdr = nlmsg_hdr(msg);
    genl_hdr = genlmsg_hdr(nl_hdr);

    if (genl_hdr->cmd != SI_COMM_C_STACK_REQ) {
      printf("[%s] Unsupported command %d\n", __func__, genl_hdr->cmd);
        return 0;
    }

    err = genlmsg_parse(nl_hdr, 0, attrs, SI_COMM_A_MAX, si_comm_genl_policy);
    if (err)
      return err;

    // ignore any attributes other than the KERN_REQ
    if (attrs[SI_COMM_A_KERN_REQ]) {
        reqp = (uint8_t *)nla_data(attrs[SI_COMM_A_KERN_REQ]);
        if (*reqp != STACK_REQ_CMD) {
          printf("[%s] Unexpected kernel message: %u\n", __func__, *reqp);
            return -1;
        }
    }
    else {
      printf("[%s] Null message from the kernel message\n", __func__);
        return -1;
    }

    // Collect and serialize the callstack
    callstack = pyr_runtime_collect_callstack();
    err = pyr_serialize_callstack(&callstack_str, callstack);
    if (err > 0) {
        printf("[%s] Sending serialized callstack %s (%d bytes) to kernel\n", __func__, callstack_str, err);
    }

    err = pyr_to_kernel(SI_COMM_C_STACK_REQ, SI_COMM_A_USR_MSG, callstack_str);

 out:
    if (callstack)
        pyr_free_callgraph(&callstack);
    if (callstack_str)
        free(callstack_str);
    return err;

}

static int init_si_socket() {
    int err = -1;

    si_sock = nl_socket_alloc();
    if (!si_sock) {
      printf("[%s] Could not allocate SI netlink socket\n", __func__);
        return -1;
    }
    nl_socket_disable_seq_check(si_sock);
    nl_socket_disable_auto_ack(si_sock);

    si_port = getpid();
    nl_socket_set_local_port(si_sock, si_port);

    err = nl_socket_modify_cb(si_sock, NL_CB_VALID, NL_CB_CUSTOM,
                                handle_callstack_request, NULL);
    if (err < 0) {
      printf("[%s] Could not register receive callback function. Error = %d\n", __func__, err);
        goto fail;
    }

    err = genl_connect(si_sock);
    if (err) {
      printf("[%s] SI netlink socket connection failed: %d\n", __func__, err);
      goto fail;
    }

    nl_fam = get_family_id(nl_socket_get_fd(si_sock), si_port, FAMILY_STR);

    return 0;

 fail:
    printf("{%s] Following libnl error occurred: %s\n", __func__, nl_geterror(err));
    if (si_sock)
      nl_socket_free(si_sock);
    return err;
}

/* Open the netlink socket to communicate with the
 * kernel, and register this process as a Pyronia-secured process
 * with the given serialized library policy. */
int pyr_init_si_comm(pyr_cg_node_t *(*collect_callstack_cb)(void),
                     char *policy) {
    int err = 0;
    char *reg_str = NULL;

    /* Initialize the SI socket */
    err = init_si_socket();
    if (err) {
      printf("[%s] SI socket initialization failure\n", __func__);
      goto out;
    }

    reg_str = malloc(INT32_STR_SIZE+strlen(policy)+2);
    if (!reg_str) {
        goto out;
    }

    sprintf(reg_str, "%d:%s", si_port, policy);
    err = pyr_to_kernel(SI_COMM_C_REGISTER_PROC, SI_COMM_A_USR_MSG, reg_str);
    if (err) {
        goto out;
    }

 out:
    if (reg_str)
        free(reg_str);
    if (!err)
        printf("[%s] Registered process at port %d; SI_COMM family id = %d\n",
           __func__, si_port, nl_fam);
    return err;
}

void pyr_callstack_req_listen() {
    pthread_attr_t attr = NULL;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    pthread_create(&recv_th, &attr, pyr_recv_from_kernel, NULL);
}

void pyr_teardown_si_comm() {
    if (si_sock)
        nl_socket_free(si_sock);
}

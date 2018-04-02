/* Main Pyronia userspace API.
*
*@author Marcela S. Melara
*/

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/syscall.h>
#include <kernel_comm.h>
#include <pthread.h>
#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <netlink/socket.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <linux/pyronia_netlink.h>
#include <linux/pyronia_mac.h>

#include "pyronia_lib.h"

#define FAMILY_STR "SI_COMM"
#define INT32_STR_SIZE 12

static struct nl_sock *si_sock;
static int nl_fam;
static uint32_t si_port;
static struct pyr_runtime *runtime;

static pthread_t recv_th;

/* libpyronia-specific wrapper around send_message in kernel_comm.h */
static int pyr_to_kernel(int nl_cmd, int nl_attr, char *msg) {
  int err = -1;
  char *m;

  if (!msg)
      m = "ERR";
  else
      m = msg;

  err = send_message(nl_socket_get_fd(si_sock), nl_fam, nl_cmd, nl_attr, si_port, m);

 out:
  return err;
}

// Serialize a callstack "object" to a tokenized string
// that the LSM can then parse. Do basic input sanitation as well.
// The function uses strncat(), which appends a string to the given
// "dest" string, so the serialized callstack is ordered from root to leaf.
// Caller must free the string.
static int pyr_serialize_callstack(char **cs_str, pyr_cg_node_t *callstack) {
    pyr_cg_node_t *cur_node;
    char *ser = NULL, *out;
    uint32_t ser_len = 1; // for null-byte
    char *delim = CALLSTACK_STR_DELIM;
    int ret;

    if (!callstack)
        goto fail;

    cur_node = callstack;
    while (cur_node) {
        // let's sanity check our lib name first (i.e. it should not
        // contain our delimiter character
        if (strchr(cur_node->lib, *delim)) {
            printf("[%s] Oops, library name %s contains unacceptable characetr\n", __func__, cur_node->lib);
            goto fail;
        }

        ser = realloc(ser, ser_len+strlen(cur_node->lib)+1);
        if (!ser)
            goto fail;

        strncat(ser, cur_node->lib, strlen(cur_node->lib));
        if (cur_node->child)
            // only append a delimiter if the current lib will
            // be followed by another one (i.e. it's not the last)
            strncat(ser, CALLSTACK_STR_DELIM, 1);
        ser_len += strlen(cur_node->lib);
        cur_node = cur_node->child;
    }

    // now we need to pre-append the len so the kernel knows how many
    // nodes to expect to de-serialize
    out = malloc(sizeof(char)*(ser_len+INT32_STR_SIZE));
    if (out)
        goto fail;
    ret = sprintf(out, "%d,%s", ser_len, ser);
    free(ser);

    *cs_str = out;
    return ret;
 fail:
    if (ser)
        free(ser);
    *cs_str = NULL;
    return -1;
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
    char *callstack_str;
    int err;

    //printf("[%s] The kernel module sent a message.\n", __func__);

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
    callstack = runtime->collect_callstack_cb();
    err = pyr_serialize_callstack(&callstack_str, callstack);
    if (err > 0) {
        printf("[%s] Sending serialized callstack %s (%d bytes) to kernel\n", __func__, callstack_str, err);
    }

    err = send_message(nl_socket_get_fd(si_sock), nl_fam,
                        SI_COMM_C_STACK_REQ,
                        SI_COMM_A_USR_MSG, si_port, callstack_str);

 out:
    if (callstack)
        pyr_free_callgraph(callstack);
    if (callstack_str)
        free(callstack_str);
    return err;

}

// this gets called in a separate receiver thread
// so just make the function signature fit what pthread_create expects
static void *pyr_recv_from_kernel(void *args) {
  int err = 0;

  //printf("[%s] Listening at port %d\n", __func__, si_port);

  // FIXME: there's probably a much better way to do this, maybe
  // use condition variables?
  while(1) {
    // Receive messages
    err = nl_recvmsgs_default(si_sock);
    if (err < 0) {
      printf("[%s] Error: %d\n", __func__, err);
      break;
    }
  }
  return NULL;
}

static int init_si_kernel_comm() {
    int err;

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
        goto error;
    }

    err = genl_connect(si_sock);
    if (err) {
      printf("[%s] SI netlink socket connection failed: %d\n", __func__, err);
      goto error;
    }

    pthread_create(&recv_th, NULL, pyr_recv_from_kernel, NULL);

    return 0;

 error:
    printf("{%s] Following libnl error occurred: %s\n", __func__, nl_geterror(err));
    if (si_sock)
      nl_socket_free(si_sock);
    return err;
}

/* Do all the necessary setup for a language runtime to use
 * the Pyronia extensions: open the stack inspection communication
 * channel and initialize the SMV backend.
 */
int pyr_init() {
    int err = 0;
    char str[INT32_STR_SIZE];

    /* Initialize the SI socket */
    err = init_si_kernel_comm();
    if (err) {
      printf("[%s] SI socket initialization failure\n", __func__);
    }

    nl_fam = get_family_id(nl_socket_get_fd(si_sock), si_port, FAMILY_STR);

    sprintf(str, "%d", si_port);
    err = pyr_to_kernel(SI_COMM_C_REGISTER_PROC, SI_COMM_A_USR_MSG, str);

    if (!err)
          printf("[%s] Initialized socket at port %d; SI_COMM family id = %d\n",
           __func__, si_port, nl_fam);

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
  printf("[%s] Exiting Pyronia runtime\n", __func__);

  // TODO: kill the receiver thread

  if (si_sock)
    nl_socket_free(si_sock);
}

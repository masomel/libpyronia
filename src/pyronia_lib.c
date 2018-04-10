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
#include "serialization.h"

#define FAMILY_STR "SI_COMM"
#define NUM_CS_REQ_MSGS 1

static struct nl_sock *si_sock;
static int nl_fam;
static uint32_t si_port;
struct pyr_runtime *runtime;

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

/* Handle a callstack request from the kernel by calling
 * the callstack generator in the callstack library.
 * Once the callstack is generated, serialize and send the
 * callstack back to the kernel.
 */
static int handle_callstack_request(struct nl_msg *msg, void *arg) {
    struct nlmsghdr *nl_hdr = NULL;
    struct genlmsghdr *genl_hdr = NULL;
    struct nlattr *attrs[SI_COMM_A_MAX];
    uint8_t *reqp;
    pyr_cg_node_t *callstack = NULL;
    char *callstack_str = NULL;
    int err = -1;
    int count = 0; //used to make sure we're getting the right number of messages
    
    printf("[%s] The kernel module sent a message.\n", __func__);

    nl_hdr = nlmsg_hdr(msg);
    genl_hdr = genlmsg_hdr(nl_hdr);
    
    if (genl_hdr->cmd != SI_COMM_C_STACK_REQ) {
      printf("[%s] Unsupported command %d\n", __func__, genl_hdr->cmd);
      goto out;
    }
    
    err = genlmsg_parse(nl_hdr, 0, attrs, SI_COMM_A_MAX, si_comm_genl_policy);
    if (err)
      goto out;
    
    printf("[%s] Received GENL SI_COMM msg\n", __func__);
    
    // ignore any attributes other than the KERN_REQ
    if (attrs[SI_COMM_A_KERN_REQ]) {
      reqp = (uint8_t *)nla_data(attrs[SI_COMM_A_KERN_REQ]);
      if (*reqp != STACK_REQ_CMD) {
	printf("[%s] Unexpected kernel message: %u\n", __func__, *reqp);
	goto out;
      }
    }
    else {
      printf("[%s] Null message from the kernel message\n", __func__);
      goto out;
    }
    count++;
    
    // Collect and serialize the callstack
    callstack = runtime->collect_callstack_cb();
    err = pyr_serialize_callstack(&callstack_str, callstack);
    if (err > 0) {
      printf("[%s] Sending serialized callstack %s (%d bytes) to kernel\n", __func__, callstack_str, err);
      err = 0;
    }

 out:
    if (err) 
      err = pyr_to_kernel(SI_COMM_C_STACK_REQ, SI_COMM_A_USR_MSG, NULL);
    else
      err = pyr_to_kernel(SI_COMM_C_STACK_REQ, SI_COMM_A_USR_MSG, callstack_str);

    if (callstack)
        pyr_free_callgraph(&callstack);
    if (callstack_str)
        free(callstack_str);
    return err;
}

// this gets called in a separate receiver thread
// so just make the function signature fit what pthread_create expects
static void *pyr_recv_from_kernel(void *args) {
  int err = 0;

  while(1) {
    printf("[%s] Listening at port %d\n", __func__, nl_socket_get_local_port(si_sock));
    
    // Receive messages
    err = nl_recvmsgs_default(si_sock);
    if (err < 0) {
      printf("[%s] Error: %d\n", __func__, err);
      break;
    }
  }

  printf("[%s] Got here!!!!\n", __func__);
  pyr_exit();
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

    err = nl_socket_modify_cb(si_sock, NL_CB_MSG_IN, NL_CB_CUSTOM,
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

    return 0;

 fail:
    printf("{%s] Following libnl error occurred: %s\n", __func__, nl_geterror(err));
    if (si_sock)
      nl_socket_free(si_sock);
    return err;
}

static int init_runtime(pyr_cg_node_t *(*collect_callstack)(void)) {
    struct pyr_runtime *r;
    int err = 0;

    // TODO: allocate this in the secure memdom
    r = malloc(sizeof(struct pyr_runtime));
    if (!r) {
        printf("[%s] No memory for runtime properties\n", __func__);
        err = -ENOMEM;
        goto fail;
    }

    if (!collect_callstack) {
        printf("[%s] Need non-null callstack collect callback\n", __func__);
        err = -EINVAL;
        goto fail;
    }
    r->collect_callstack_cb = collect_callstack;
    runtime = r;

    printf("[%s] Successfully initialized the runtime\n", __func__);
    return 0;
 fail:
    if (r)
        free(r);
    return err;
}

static void init_callstack_req_thread() {
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    pthread_create(&recv_th, &attr, pyr_recv_from_kernel, NULL);
}

/* Do all the necessary setup for a language runtime to use
 * the Pyronia extensions: open the stack inspection communication
 * channel and initialize the SMV backend.
 */
int pyr_init(const char *lib_policy_file,
             pyr_cg_node_t *(*collect_callstack_cb)(void)) {
    int err = 0;
    char *reg_str;
    char *policy;

    /* Initialize the runtime metadata */
    err = init_runtime(collect_callstack_cb);
    if (err) {
      printf("[%s] Runtime initialization failure\n", __func__);
      goto out;
    }

    /* Initialize the SI socket */
    err = init_si_kernel_comm();
    if (err) {
      printf("[%s] SI socket initialization failure\n", __func__);
      goto out;
    }

    nl_fam = get_family_id(nl_socket_get_fd(si_sock), si_port, FAMILY_STR);

    /* Parse the library policy from disk */
    err = pyr_parse_lib_policy(lib_policy_file, &policy);
    if (err < 0) {
        printf("[%s] Parsing lib policy failure\n", __func__);
        goto out;
    }
    
    /* Register this process as a Pyronia-secured process */
    reg_str = malloc(INT32_STR_SIZE+strlen(policy)+2);
    if (!reg_str) {
        goto out;
    }

    sprintf(reg_str, "%d:%s", si_port, policy);
    err = pyr_to_kernel(SI_COMM_C_REGISTER_PROC, SI_COMM_A_USR_MSG, reg_str);
    if (err) {
        goto out;
    }

    printf("[%s] Sent registration message %s (%lu bytes)\n", __func__, reg_str, strlen(reg_str));
    
    /* Start the callstack request receiver thread */
    init_callstack_req_thread();

    // We don't want the main thread's memdom to be
    // globally accessible, so init with 0.
    // err = smv_main_init(0);
    
 out:
    if (policy)
      free(policy);
    if (reg_str)
      free(reg_str);

    if (!err)
      printf("[%s] Initialized socket at port %d; SI_COMM family id = %d\n",
           __func__, si_port, nl_fam);
    
    return err;
}

/* Do all necessary teardown actions. */
void pyr_exit() {
  printf("[%s] Exiting Pyronia runtime\n", __func__);

  if (si_sock)
    nl_socket_free(si_sock);
}

// Allocate a new callgraph node
int pyr_new_cg_node(pyr_cg_node_t **cg_root, const char* lib,
                        enum pyr_data_types data_type,
                        pyr_cg_node_t *child) {

    pyr_cg_node_t *n = malloc(sizeof(pyr_cg_node_t));

    if (n == NULL) {
        goto fail;
    }

    n->lib = malloc(strlen(lib)+1);
    if (!n->lib)
      goto fail;
    memset(n->lib, 0, strlen(lib)+1);
    memcpy(n->lib, lib, strlen(lib));
    n->data_type = data_type;
    n->child = child;

    *cg_root = n;
    return 0;
 fail:
    if (n)
        free(n);
    return -1;
}

// Recursively free the callgraph nodes
static void free_node(pyr_cg_node_t **node) {
    pyr_cg_node_t *n = *node;

    if (n == NULL) {
      return;
    }

    if (n->child == NULL) {
        free(n->lib);
        free(n);
    }
    else {
        free_node(&(n->child));
    }
    *node = NULL;
}

// Free a callgraph
void pyr_free_callgraph(pyr_cg_node_t **cg_root) {
    free_node(cg_root);
}

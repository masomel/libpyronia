/** Implements the Pyronia kernel communication definitions for
 * receiving callstack requests and sending back serialized callgraphs.
 *
 *@author Marcela S. Melara
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <kernel_comm.h>
#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <netlink/socket.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <linux/pyronia_netlink.h>
#include <memdom_lib.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include "pyronia_lib.h"
#include "si_comm.h"
#include "serialization.h"

struct nl_msg
{
	int			nm_protocol;
	int			nm_flags;
	struct sockaddr_nl	nm_src;
	struct sockaddr_nl	nm_dst;
	struct ucred		nm_creds;
	struct nlmsghdr *	nm_nlh;
	size_t			nm_size;
	int			nm_refcnt;
};

static struct nl_sock *si_sock = NULL;
static int nl_fam = 0;
static uint32_t si_port = 0;
static int epoll_fd = -1;

/* libpyronia-specific wrapper around send_message in kernel_comm.h */
static int pyr_to_kernel(int nl_cmd, int nl_attr, char *msg) {
  int err = -1;
  char *m = NULL;

  if (!msg)
      m = "ERR";
  else
      m = msg;

  rlog("[%s] Sending message %s\n", __func__, m);

  err = send_message(nl_socket_get_fd(si_sock), nl_fam, nl_cmd, nl_attr, si_port, m);
  
 out:
  return err;
}

static int get_si_fd() {
  return nl_socket_get_fd(si_sock);
}

static int init_epoll() {
  int err = -1;
  epoll_fd = epoll_create1(0);
  if (epoll_fd == -1) {
    printf("[%s] Could not create new epoll (error = %d)\n", __func__, errno);
    return err;
  }

  const int fd = get_si_fd();
  struct epoll_event ev = {
    .events = EPOLLIN,
    .data = { .fd = fd, },
  };

  err = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev);
  return err;
}

static int teardown_epoll() {
  const int fd = get_si_fd();
  int err = epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
  return err;
}

static void free_nl_msg(struct nl_msg **nm) {
  struct nl_msg *msg = *nm;

  if (!msg)
    return;

  msg->nm_refcnt--;
  if (msg->nm_refcnt < 0)
    return;

  if (msg->nm_refcnt <= 0) {
    memdom_free(msg->nm_nlh);
    memdom_free(msg);
  }
  *nm = NULL;
}

static int alloc_new_msg(struct nl_msg **new, size_t len) {
  struct nl_msg *nm = NULL;
  int err = -1;

  if (len < sizeof(struct nlmsghdr))
    len = sizeof(struct nlmsghdr);

  nm = memdom_alloc(si_memdom, sizeof(struct nl_msg));
  if (!nm)
    goto out;

  nm->nm_refcnt = 1;

  nm->nm_nlh = memdom_alloc(si_memdom, len);
  if (!nm->nm_nlh) {
    memdom_free(nm);
    goto out;
  }
  
  nm->nm_protocol = -1;
  nm->nm_size = len;
  nm->nm_nlh->nlmsg_len = nlmsg_total_size(0);
  err = 0;
  
 out:
  *new = nm;
  return err;
}

static int read_netlink_data(struct nl_msg **new_msg) {
  int err = -1;
  struct {
    struct nlmsghdr n;
    struct genlmsghdr g;
    char buf[256];
  } req;
  size_t num_read = 0;

  num_read = recv(get_si_fd(), &req, sizeof(req), 0);
  if (num_read == -1) {
    printf("[%s] Read failed with error %d\n", __func__, errno);
    return err;
  }

  printf("[%s] Received new SI message (%lu bytes)\n", __func__, num_read);
  
  /* Validate response message */
  if (!NLMSG_OK((&req.n), num_read)){
    rlog("invalid reply message\n");
    return -1;
  }

  if (req.n.nlmsg_type == NLMSG_ERROR) { /* error */
    rlog("received error\n");
    return -1;
  }

  if (si_memdom == -1) {
    printf("[%s] Bad si_memdom\n", __func__);\
    return -1;
  }
  
  struct nl_msg *nm = NULL;
  err = alloc_new_msg(&nm, req.n.nlmsg_len);
  if (err < 0)
    goto out;
  
  memcpy(nm->nm_nlh, &req.n, req.n.nlmsg_len);
  err = 0;
 out:
  *new_msg = nm;
  return err;
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

    printf("[%s] Handling call stack request...\n", __func__);
    
    // the condition will be set to false at the top of the
    // recv loop (i.e. after this function returns)
    pthread_mutex_lock(&security_ctx_mutex);
    is_inspecting_stack = true;
    pthread_mutex_unlock(&security_ctx_mutex);
    
    nl_hdr = nlmsg_hdr(msg);
    genl_hdr = genlmsg_hdr(nl_hdr);

    if (genl_hdr->cmd != SI_COMM_C_STACK_REQ) {
      printf("[%s] Unsupported command %d\n", __func__, genl_hdr->cmd);
      err = 0;
      goto out;
    }

    err = genlmsg_parse(nl_hdr, 0, attrs, SI_COMM_A_MAX, si_comm_genl_policy);
    if (err)
      goto out;
    
    // ignore any attributes other than the KERN_REQ
    if (attrs[SI_COMM_A_KERN_REQ]) {
        reqp = (uint8_t *)nla_data(attrs[SI_COMM_A_KERN_REQ]);
        if (*reqp != STACK_REQ_CMD) {
          printf("[%s] Unexpected kernel message: %u\n", __func__, *reqp);
	  err = -1;
	  goto out;
        }
    }
    else {
      printf("[%s] Null message from the kernel message\n", __func__);
      err = -1;
      goto out;
    }
    
    // Collect and serialize the callstack
    callstack = pyr_collect_runtime_callstack();
    err = pyr_serialize_callstack(&callstack_str, callstack);
    if (err > 0) {
        rlog("[%s] Sending serialized callstack %s (%d bytes) to kernel\n", __func__, callstack_str, err);
    }
    
 out:
    err = pyr_to_kernel(SI_COMM_C_STACK_REQ, SI_COMM_A_USR_MSG, callstack_str);
    if (callstack)
        pyr_free_callgraph(&callstack);
    if (callstack_str)
        memdom_free(callstack_str);

    return err;
}

// this gets called in a separate receiver thread
// so just make the function signature fit what pthread_create expects
void *pyr_recv_from_kernel(void *args) {
  int err = 0;
  int ready = 0;
  struct epoll_event events[1]; // we're only listening on one fd
  
  pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, 0);
  
  while(true) {
    pthread_mutex_lock(&security_ctx_mutex);
    is_inspecting_stack = false;
    pthread_cond_broadcast(&si_cond_var);
    pthread_mutex_unlock(&security_ctx_mutex);
    printf("[%s] Listening at port %d\n", __func__, si_port);
    
    /*ready = epoll_wait(epoll_fd, events, 1, 1000);
    if (ready == -1) {
      printf("[%s] Polling SI socket failed (error = %d)\n", __func__, errno);
      goto out;
    }
    else if (ready == 0) {
      printf("[%s] Polling SI socket timed out. Try again\n", __func__);
    }
    else if (ready == 1) {*/
      struct nl_msg *new_msg = NULL;
      err = read_netlink_data(&new_msg);
      if (err < 0) {
	goto out;
      }
      err = pyr_handle_callstack_request(new_msg, NULL);
      if (err < 0) {
	goto out;
      }
      free_nl_msg(&new_msg);
      //}
  }
 out:
  pthread_mutex_lock(&security_ctx_mutex);
  is_inspecting_stack = false;
  pthread_cond_broadcast(&si_cond_var);
  pthread_mutex_unlock(&security_ctx_mutex);
  return NULL;
}

static int init_si_socket() {
    int err = -1;

    si_sock = nl_socket_alloc();
    if (!si_sock) {
        rlog("[%s] Could not allocate SI netlink socket\n", __func__);
        return -1;
    }
    nl_socket_disable_seq_check(si_sock);
    nl_socket_disable_auto_ack(si_sock);

    si_port = getpid();
    nl_socket_set_local_port(si_sock, si_port);

    /*err = nl_socket_modify_cb(si_sock, NL_CB_VALID, NL_CB_CUSTOM,
                                pyr_handle_callstack_request, NULL);
    if (err < 0) {
      printf("[%s] Could not register receive callback function. Error = %d\n", __func__, err);
        goto fail;
	}*/

    err = genl_connect(si_sock);
    if (err) {
      printf("[%s] SI netlink socket connection failed: %d\n", __func__, err);
      goto fail;
    }

    nl_fam = get_family_id(nl_socket_get_fd(si_sock), si_port, FAMILY_STR);
    //nl_socket_set_nonblocking(si_sock);
    
    err = init_epoll();
    if (err == -1) {
      printf("[%s] Could not initialized epoll: %d\n", __func__, errno);
      goto fail;
    }
    
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
int pyr_init_si_comm(char *policy) {
    int err = 0;
    char *reg_str = NULL;

    /* Initialize the SI socket */
    err = init_si_socket();
    if (err) {
      printf("[%s] SI socket initialization failure\n", __func__);
      goto out;
    }

    reg_str = pyr_alloc_critical_runtime_state(INT32_STR_SIZE+strlen(policy)+2);
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
        pyr_free_critical_state(reg_str);
    if (!err)
        rlog("[%s] Registered process at port %d; SI_COMM family id = %d\n",
           __func__, si_port, nl_fam);
    return err;
}

void pyr_teardown_si_comm() {
    pyr_is_inspecting();
    if (si_sock) {
        printf("[%s] Closing the SI socket\n", __func__);
	teardown_epoll();
	nl_close(si_sock);
        nl_socket_free(si_sock);
    }
}

// mutex must be unlocked by caller
void pyr_is_inspecting(void) {
  pthread_mutex_lock(&security_ctx_mutex);
  while (is_inspecting_stack) {
    rlog("[%s] Waiting for stack inspector to finish\n", __func__);
    pthread_cond_wait(&si_cond_var, &security_ctx_mutex);
    rlog("[%s] Stack inspector signalled\n", __func__);
  }
  pthread_mutex_unlock(&security_ctx_mutex);
}

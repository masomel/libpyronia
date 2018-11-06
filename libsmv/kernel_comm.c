#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/genetlink.h>
#include "kernel_comm.h"
#include "smv_lib.h"

#define GENLMSG_DATA(glh) ((void *)(NLMSG_DATA(glh) + GENL_HDRLEN))
#define GENLMSG_PAYLOAD(glh) (NLMSG_PAYLOAD(glh, 0) - GENL_HDRLEN)
#define NLA_DATA(na) ((void *)((char*)(na) + NLA_HDRLEN))

int create_netlink_socket(int groups){
    socklen_t addr_len;
    int sd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if(sd < 0){
        rlog("cannot create netlink socket\n");
        return -1;
    }

    struct sockaddr_nl local;
    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;
    local.nl_groups = groups;

    int rc = bind(sd, (struct sockaddr *) &local, sizeof(local));
    if(rc < 0){
        rlog("cannot bind netlink socket\n");
        close(sd);
        return -1;
    }

    return sd;
}

void teardown_netlink_socket(int netlink_socket) {
    close(netlink_socket);
}

static int send_to_kernel(int netlink_socket, const char *message, int length){
    struct sockaddr_nl nladdr;
    int r;

    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;

    while ((r = sendto(netlink_socket, message, length, 0, (struct sockaddr *) &nladdr,
                       sizeof(nladdr))) < length) {
        if (r > 0) {
            message += r;
            length -= r;
        } else if (errno != EAGAIN)
            return -1;
    }
    return 0;
}

static int send_req(int netlink_socket, int type, int nl_cmd,
                    int nl_attr, uint32_t port_id, char *message) {
    struct {
        struct nlmsghdr n;
        struct genlmsghdr g;
        char buf[2048];
    } req;
    struct nlattr *na;

    req.n.nlmsg_type = type;
    req.n.nlmsg_flags = NLM_F_REQUEST;
    req.n.nlmsg_seq = 0;
    req.n.nlmsg_pid = port_id;
    req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
    req.g.cmd = nl_cmd;
    req.g.version = 0;

    na = (struct nlattr *) GENLMSG_DATA(&req);
    na->nla_type = nl_attr;
    na->nla_len = strlen(message) + 1 + NLA_HDRLEN;

    memcpy(NLA_DATA(na), message, na->nla_len);

    req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

    return send_to_kernel(netlink_socket, (char *) &req, req.n.nlmsg_len);
}

int get_family_id(int netlink_socket, uint32_t port_id, char *family_str){
    struct {
        struct nlmsghdr n;
        struct genlmsghdr g;
        char buf[256];
    } ans;

    int id;
    int rep_len;

    int rc = send_req(netlink_socket, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, CTRL_ATTR_FAMILY_NAME, port_id, family_str);
    if ( rc < 0){
        rlog("send_to_kernel failed...\n");
                return -1;
    }

    rep_len = recv(netlink_socket, &ans, sizeof(ans), 0);
    if (rep_len < 0){
                rlog("reply length < 0\n");
                return -1;
        }

    /* Validate response message */
    if (!NLMSG_OK((&ans.n), rep_len)){
                rlog("invalid reply message\n");
                return -1;
        }

    if (ans.n.nlmsg_type == NLMSG_ERROR) { /* error */
        rlog("received error\n");
        return -1;
    }

    struct nlattr *na;
    na = (struct nlattr *) GENLMSG_DATA(&ans);
    na = (struct nlattr *) ((char *) na + NLA_ALIGN(na->nla_len));
    if (na->nla_type == CTRL_ATTR_FAMILY_ID) {
        id = *(__u16 *) NLA_DATA(na);
    }
    return id;
}

// Send a generic message to the kernel.
// Must indicate the netlink, command, and attribute.
int send_message(int netlink_socket, int family_id, int nl_cmd, int nl_attr, uint32_t port_id, char *message){

    struct {
        struct nlmsghdr n;
        struct genlmsghdr g;
        char buf[256];
    } ans;

    int r = send_req(netlink_socket, family_id, nl_cmd, nl_attr, port_id, message);
    /* Recv message */
    int rep_len = recv(netlink_socket, &ans, sizeof(ans), 0);

    /* Validate response message */
    if (ans.n.nlmsg_type == NLMSG_ERROR) { /* error */
        rlog("error received NACK - leaving\n");
        return -1;
    }
    if (rep_len < 0) {
        rlog("error receiving reply message via Netlink\n");
        return -1;
    }
    if (!NLMSG_OK((&ans.n), rep_len)) {
        rlog("invalid reply message received via Netlink\n");
                return -1;
    }

    rep_len = GENLMSG_PAYLOAD(&ans.n);

    /* Parse reply message */
    struct nlattr *na;
    na = (struct nlattr *) GENLMSG_DATA(&ans);
    char * result = (char *)NLA_DATA(na);
    return(atoi(result));
}

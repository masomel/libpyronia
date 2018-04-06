#ifndef KERNEL_COMM_H
#define KERNEL_COMM_H

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

    int create_netlink_socket(int groups);
    void teardown_netlink_socket(int netlink_socket);
    int get_family_id(int netlink_socket, uint32_t port_id, char *family_str);
    int send_message(int netlink_socket, int family_id, int nl_cmd, int nl_attr, uint32_t port_id, char *message);

#ifdef __cplusplus
}
#endif

#endif

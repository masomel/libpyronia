/** Provides utility functions and definitions for performing end-to-end
 * tests of the Pyronia LSM.
 *
 *@author Marcela S. Melara
 */

#ifndef __TESTUTIL_H
#define __TESTUTIL_H

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <error.h>
#include <errno.h>
#include <linux/pyronia_mac.h>

static char *test_libs[3];

static const char *test_names[2];

#define NUM_DEFAULT 8
/*** Copied from Beej's Guide */
#define PORT "8000"
#define MAXDATASIZE 100

static inline void init_testlibs(void) {
    test_libs[0] = "cam";
    test_libs[1] = "http";
    test_libs[2] = "img_processing";
}

// get sockaddr, IPv4 or IPv6:
static void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

static int test_file_open() {
    FILE *f;

    f = fopen("/tmp/cam0", "r");
    printf("%s opened /tmp/cam0\n", __func__);
    
    if (f == NULL) {
        printf("%s\n", strerror(errno));
        return -1;
    }

    fclose(f);
    return 0;
}

static int test_file_open_name(const char *name) {
    FILE *f;
    f = fopen(name, "r");

    printf("Opening file %s\n", name);
    
    if (f == NULL) {
        printf("%s\n", strerror(errno));
        return -1;
    }

    fclose(f);
    return 0;
}

static int test_file_open_fail() {
    FILE *f;
    f = fopen("/tmp/cam1", "r");

    if (f != NULL) {
        printf("Expected error\n");
        fclose(f);
        return -1;
    }

    if (errno != EACCES) {
        printf("Expected %s, got %s\n", strerror(EACCES), strerror(errno));
        return -1;
    }

    return 0;
}

static int test_file_open_write() {
    FILE *f;
    f = fopen("/tmp/cam0", "w");

    if (f != NULL) {
        printf("Expected error\n");
        fclose(f);
        return -1;
    }

    if (errno != EACCES) {
        printf("Expected %s, got %s\n", strerror(EACCES), strerror(errno));
        return -1;
    }

    return 0;
}

static int test_connect() {
    int sockfd, numbytes;
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];
    char buf[MAXDATASIZE];
    int error = 0;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo("127.0.0.1", PORT, &hints, &servinfo)) != 0) {
        printf("getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    if ((sockfd = socket(servinfo->ai_family, servinfo->ai_socktype,
                         servinfo->ai_protocol)) == -1) {
      printf("socket create error: %s\n", strerror(errno));
      error = errno;
      goto out;
    }

    if (connect(sockfd, servinfo->ai_addr, servinfo->ai_addrlen) == -1) {
      close(sockfd);
      printf("socket connect error: %s\n", strerror(errno));
      error = errno;
      goto out;
    }

    if ((numbytes = recv(sockfd, buf, MAXDATASIZE-1, 0)) == -1) {
      printf("could not receive data from server: %s\n", strerror(errno));
      error = errno;
      goto out;
    }

    buf[numbytes] = '\0';
    printf("success: Server sent '%s'\n", buf);
    close(sockfd);

 out:
    freeaddrinfo(servinfo); // all done with this structure
    return error;
}

static int test_connect_fail() {
    int sockfd, numbytes;
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];
    int error = 0;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo("127.0.1.1", "80", &hints, &servinfo)) != 0) {
        printf("getaddrinfo: %s\n", strerror(errno));
        return -1;
    }

    if ((sockfd = socket(servinfo->ai_family, servinfo->ai_socktype,
                         servinfo->ai_protocol)) == -1) {
      printf("socket create error: %s\n", strerror(errno));
      error = errno;
      goto out;
    }

    if (connect(sockfd, servinfo->ai_addr, servinfo->ai_addrlen) != -1) {
        printf("Expected error\n");
        close(sockfd);
        error = -1;
        goto out;
    }

    if (errno != EACCES) {
        printf("Expected %s, got %s\n", strerror(EACCES), strerror(errno));
        error = -1;
        goto out;
    }

 out:
    freeaddrinfo(servinfo); // all done with this structure
    return error;
}

#endif

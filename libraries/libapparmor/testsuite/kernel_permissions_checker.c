/* User process used to test the Pyronia hooks in the LSM
 * checks.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <error.h>
#include <errno.h>

/*** Copied from Beej's Guide */
#define PORT "8000"
#define MAXDATASIZE 100

// get sockaddr, IPv4 or IPv6:
static void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

static int test_file_open() {
    printf("-- Test: authorized file open for reading... ");
    FILE *f;
    f = fopen("/tmp/cam0", "r");

    if (f == NULL) {
        printf("%s\n", strerror(errno));
        return -1;
    }

    printf("success\n");
    fclose(f);
    return 0;
}

static int test_file_open_fail() {
    printf("-- Test: unauthorized file open for reading... ");
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

    printf("\n");
    return 0;
}

static int test_file_open_write() {
    printf("-- Test: authorized file open for writing... ");
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

    printf("\n");
    return 0;
}

static int test_connect() {
    printf("-- Test: connect to authorized network address... ");
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
    printf("-- Test: connect to unauthorized network address...");
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

    printf("\n");

 out:
    freeaddrinfo(servinfo); // all done with this structure
    return error;
}

int main(int argc, char *argv[]) {

    int success = 0;
    int total_tests = 5;

    // open(file, r) --> expect success
    if (!test_file_open()) {
        success++;
    }

    // open(bad file, r) --> expect fail
    if (!test_file_open_fail()) {
        success++;
    }

    // open(file, w) --> expect fail
    if (!test_file_open_write()) {
        success++;
    }

    // connect(host, port) --> expect success
    if (!test_connect()) {
        success++;
    }

    // connect(bad host, bad port) --> expect fail
    if (!test_connect_fail()) {
        success++;
    }

    printf("%d / %d kernel permissions check tests passed\n", success, total_tests);

    return 0;
}

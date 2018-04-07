/** Implements the library for parsing and serializing a Pyronia-secured
 * application's callstack and library-level access policies.
 *
 *@author Marcela S. Melara
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <linux/pyronia_mac.h>

#include "serialization.h"

// Serialize a callstack "object" to a tokenized string
// that the LSM can then parse. Do basic input sanitation as well.
// The function uses strncat(), which appends a string to the given
// "dest" string, so the serialized callstack is ordered from root to leaf.
// Caller must free the string.
int pyr_serialize_callstack(char **cs_str, pyr_cg_node_t *callstack) {
    pyr_cg_node_t *cur_node;
    char *ser = NULL, *out;
    uint32_t ser_len = 1; // for null-byte
    char *delim = CALLSTACK_STR_DELIM;
    int ret, node_count = 0;

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

        ser = realloc(ser, sizeof(char)*(ser_len+strlen(cur_node->lib)+1));
        if (!ser)
            goto fail;

        strncat(ser, cur_node->lib, strlen(cur_node->lib));
        strncat(ser, CALLSTACK_STR_DELIM, 1);
        ser_len += strlen(cur_node->lib)+1;
        cur_node = cur_node->child;
        node_count++;
    }

    // now we need to pre-append the len so the kernel knows how many
    // nodes to expect to de-serialize
    out = malloc(sizeof(char)*(ser_len+INT32_STR_SIZE));
    if (!out)
        goto fail;
    ret = sprintf(out, "%d,%s", node_count, ser);
    free(ser);

    *cs_str = out;
    return ret;
 fail:
    if (ser)
        free(ser);
    *cs_str = NULL;
    return -1;
}

static int read_policy_file(const char *policy_fname, char **buf) {
    char * buffer = 0;
    int length;
    int read;
    FILE * f = fopen(policy_fname, "r");

    if (f) {
        fseek(f, 0, SEEK_END);
        length = ftell(f);
        fseek(f, 0, SEEK_SET);
        buffer = malloc(length);
        if (!buffer) {
            goto fail;
        }
        read = fread(buffer, 1, length, f);
        if (read != length) {
          printf("bad length: %d != %d\n", read, length);
          goto fail;
        }

        *buf = buffer;
        return length;
    }
 fail:
    if (buffer)
        free(buffer);
    if (f)
        fclose(f);
    *buf = NULL;
    return -1;
}

/* Reads the library policy at in the poliy file at policy_fname,
 * and serializes it for registration with the LSM.
 */
int pyr_parse_lib_policy(const char *policy_fname, char **parsed) {

  int count, rule_len;
    char *ser = NULL, *out;
    uint32_t ser_len = 1; // for null-byte
    int ret;

    char *policy;
    ret = read_policy_file(policy_fname, &policy);
    if (ret < 0) {
        goto fail;
    }

    // loop through the policy to serialize it into
    // a format that can be interpreted by the LSM
    char *next_rule = strsep(&policy, "\n");
    while(next_rule) {
        if (*next_rule == 0) {
           // our next rule is a null byte since we just parsed an empty line
           goto skip;
        }

        rule_len = strlen(next_rule);
        ser = realloc(ser, sizeof(char)*(ser_len+rule_len));
        if (!ser) {
            ret = -1;
            goto fail;
        }

        strncat(ser, next_rule, rule_len);

        ser_len += rule_len;
        count++;
    skip:
        next_rule = strsep(&policy, "\n");
    }

    if (count == 0) {
      // this means our file is malformed
      // bc we don't have a single valid rule line
      printf("[%s] Oops, malformed policy file %s. Rules need to be comma-separated\n", __func__, policy_fname);
      ret = -1;
      goto fail;
    }

    // now we need to pre-append the len so the kernel knows how many
    // nodes to expect to de-serialize
    out = malloc(sizeof(char)*(ser_len+INT32_STR_SIZE));
    if (!out) {
        ret = -1;
        goto fail;
    }

    ret = sprintf(out, "%d,%s", count, ser);
    free(ser);

    *parsed = out;
    return ret;
 fail:
    if (ser)
        free(ser);
    *parsed = NULL;
    return ret;
}

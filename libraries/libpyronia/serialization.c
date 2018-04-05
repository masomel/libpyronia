/** Implements the library for parsing and serializing a Pyronia-secured
 * application's callstack and library-level access policies.
 *
 *@author Marcela S. Melara
 */

#include <linux/pyronia_netlink.h>
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

        ser = realloc(ser, ser_len+strlen(cur_node->lib)+1);
        if (!ser)
            goto fail;

        strncat(ser, cur_node->lib, strlen(cur_node->lib));
        if (cur_node->child) {
            // only append a delimiter if the current lib will
            // be followed by another one (i.e. it's not the last)
            strncat(ser, CALLSTACK_STR_DELIM, 1);
            ser_len++;
        }
        ser_len += strlen(cur_node->lib);
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

    printf("[%s] Serialized callstack: %s\n", __func__, out);

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

    int count, c_idx = 0;
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
    while(c_idx < strlen(policy)) {
        char *next_rule = strchr(policy+c_idx, ',');
        if (!next_rule) {
            // this means our file is malformed
            // bc we don't have a valid rule line
            printf("[%s] Oops, malformed policy file %s. Rules need to be comma-separated\n", __func__, policy_fname);
            goto fail;
        }

        int rule_len = next_rule - (policy+c_idx);
        ser = realloc(ser, ser_len+rule_len);
        if (!ser)
            goto fail;

        strncat(ser, policy+c_idx, rule_len);
        c_idx += rule_len;

        // our policy likely has a rule on each line, so make sure
        // we advance the pointer accordingly
        while((policy[c_idx]) == '\n')
            c_idx++;

        ser_len += rule_len;
        count++;
    }

    // now we need to pre-append the len so the kernel knows how many
    // nodes to expect to de-serialize
    out = malloc(sizeof(char)*(ser_len+INT32_STR_SIZE));
    if (!out)
        goto fail;
    ret = sprintf(out, "%d,%s", count, ser);
    free(ser);

    printf("[%s] Serialized policy: %s\n", __func__, out);

    *parsed = out;
    return ret;
 fail:
    if (ser)
        free(ser);
    *parsed = NULL;
    return err;
}

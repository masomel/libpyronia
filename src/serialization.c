/** Implements the library for parsing and serializing a Pyronia-secured
 * application's callstack and library-level access policies.
 *
 *@author Marcela S. Melara
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <error.h>
#include <linux/pyronia_mac.h>
#include <memdom_lib.h>

#include "pyronia_lib.h"
#include "serialization.h"

// Serialize a callstack "object" to a tokenized string
// that the LSM can then parse. Do basic input sanitation as well.
// The function uses strncat(), which appends a string to the given
// "dest" string, so the serialized callstack is ordered from root to leaf.
// Caller must memdom_free the string.
int pyr_serialize_callstack(char **cs_str, pyr_cg_node_t *callstack) {
    pyr_cg_node_t *cur_node;
    char *ser = NULL, *out = NULL, *tmp_ser = NULL;
    uint32_t node_count = 0, ser_len = 1; // for null-byte
    char *delim = CALLSTACK_STR_DELIM;
    int ret = -1;

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

        tmp_ser = realloc(ser, ser_len+strlen(cur_node->lib)+1);
        if (!tmp_ser)
            goto fail;

        // UGH need to clear the very first allocation,
        // so we don't accidentally start concatenating to
        // junk that realloc spits out
        if (ser_len == 1) {
          memset(tmp_ser, 0, ser_len+strlen(cur_node->lib)+1);
        }

        ser = tmp_ser;

        strncat(ser, cur_node->lib, strlen(cur_node->lib));
        strncat(ser, CALLSTACK_STR_DELIM, 1);
        ser_len += strlen(cur_node->lib)+1;
        cur_node = cur_node->child;
        node_count++;

        printf("[%s] Serialized node: %s, # nodes %d\n", __func__, ser, node_count);
    }

    // now we need to pre-append the len so the kernel knows how many
    // nodes to expect to de-serialize
    out = pyr_alloc_critical_runtime_state(strlen(ser)+INT32_STR_SIZE+2);
    if (!out)
        goto fail;
    memset(out, 0, strlen(ser)+INT32_STR_SIZE+2);
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
    char *buffer = 0;
    int length;
    int read;
    FILE * f = fopen(policy_fname, "r");

    if (f) {
        fseek(f, 0, SEEK_END);
        length = ftell(f);
        fseek(f, 0, SEEK_SET);
        buffer = pyr_alloc_critical_runtime_state(length+1);
        if (!buffer) {
          printf("[%s] Could not allocate the protected buffer\n", __func__);
            goto fail;
        }
        read = fread(buffer, 1, length, f);
        if (read != length) {
          printf("[%s] Bad read length: %d != %d\n", __func__, read, length);
          goto fail;
        }
        buffer[length] = '\0';
        *buf = buffer;
        fclose(f);
        return length;
    }
    else {
        printf("[%s] Could not open the lib policy file %s\n", __func__, policy_fname);
    }
 fail:
    if (buffer)
        pyr_free_critical_state(buffer);
    if (f)
        fclose(f);
    *buf = NULL;
    return -1;
}

/* Reads the library policy (OS resources and data objects)
 * in the policy file at policy_fname,
 * and serializes it for registration with the LSM and the runtime.
 */
int pyr_parse_lib_policy(const char *policy_fname, char **parsed,
                         char **parsed_obj_rules, int *num_rules) {

    int rule_len;
    char *ser = NULL, *out = NULL, *tmp_ser = NULL;
    uint32_t count = 0, ser_len = 1; // for null-byte
    int ret;
    char *obj_rules[1024];
    int obj_rule_count = 0;
    char **out_obj_rules = NULL;

    char *policy;
    char *policyp;
    ret = read_policy_file(policy_fname, &policy);
    if (ret < 0) {
        goto fail;
    }
    policyp = policy;

    // loop through the policy to serialize it into
    // a format that can be interpreted by the LSM
    char *next_rule = strsep(&policy, "\n");
    while(next_rule) {
        if (!strlen(next_rule)) {
          // this means we've hit an empty line, so skip to next rule
          next_rule = strsep(&policy, "\n");
          continue;
        }

        rule_len = strlen(next_rule);
        tmp_ser = realloc(ser, ser_len+rule_len);
        if (!tmp_ser) {
          ret = -1;
          goto fail;
        }
        // UGH need to clear the very first allocation,
        // so we don't accidentally start concatenating to
        // junk that realloc spits out
        if (ser_len == 1) {
          memset(tmp_ser, 0, ser_len+rule_len);
        }
        ser = tmp_ser;

        // this is a data object rule, so keep is aside, and
        // deal with it later
        if (ser[0] == '-' || ser[0] == '+') {
            obj_rules[obj_rule_count] = ser;
            obj_rule_count++;
        }
        else {
            strncat(ser, next_rule, rule_len);
            ser_len = strlen(ser)+rule_len;
            count++;
        }
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
    out = pyr_alloc_critical_runtime_state(strlen(ser)+INT32_STR_SIZE+2);
    if (!out) {
        ret = -1;
        goto fail;
    }
    memset(out, 0, strlen(ser)+INT32_STR_SIZE+2);
    ret = sprintf(out, "%d,%s", count, ser);

    if (obj_rule_count) {
        int i = 0;
        out_obj_rules = malloc(sizeof(char *)*obj_rule_count);
        if (!out_obj_rules) {
            ret = -1;
            goto fail;
        }
        for (i = 0; i < obj_rule_count; i++) {
            out_obj_rules[i] = malloc(strlen(obj_rules[i])+1);
            if (!out_obj_rules[i]) {
                ret = -1;
                goto fail;
            }
            memset(out_obj_rules[i], 0, strlen(obj_rules[i])+1);
            memcpy(out_obj_rules[i], obj_rules[i], strlen(obj_rules[i]));
        }
        *num_rules = obj_rule_count;
    }
    goto done;

 fail:
    out = NULL;
    out_obj_rules = NULL;
 done:
    if (policyp)
      pyr_free_critical_state(policyp);
    if (ser)
        free(ser);
    *parsed = out;
    parsed_obj_rules = out_obj_rules;
    return ret;
}

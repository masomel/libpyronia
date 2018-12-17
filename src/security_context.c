/** Implements the Pyronia security context library used for
 * isolating security-critical runtime state and native libraries
 * into memory domains in Pyronia-aware language runtimes.
 *
 *@author Marcela S. Melara
 */
#include <stdlib.h>
#include <errno.h>
#include <memdom_lib.h>

#include "security_context.h"
#include "util.h"
#include "serialization.h"

void free_pyr_data_obj(pyr_data_obj_t **objp) {
    pyr_data_obj_t *o = *objp;
    if (!o)
        return;

    if (o->addr)
        memdom_free(o->addr);
    if (o->name)
        free(o->name);
    if (o->domain_label)
        free(o->domain_label);

    free(o);
    *objp = NULL;
}

void free_pyr_data_obj_domain(pyr_data_obj_domain_t **domp) {
    pyr_data_obj_domain_t *d = *domp;
    if (!d)
        return;

    if (d->memdom_id > 0)
      memdom_kill(d->memdom_id);

    if (d->label)
        free(d->label);

    free(d);
    d = NULL;
    *domp = NULL;
}

void free_dom_list(struct dom_list **dlp) {
    struct dom_list *dl = *dlp;
    if (!dl)
        return;

    if (dl->next)
        free_dom_list(&dl->next);

    if (dl->domain)
      free_pyr_data_obj_domain(&dl->domain);

    free(dl);
    *dlp = NULL;
}

void free_obj_list(struct obj_list **olp) {
    struct obj_list *ol = *olp;
    if (!ol)
        return;

    if (ol->next)
        free_obj_list(&ol->next);

    if (ol->obj)
        free_pyr_data_obj(&ol->obj);

    free(ol);
    *olp = NULL;
}

void free_pyr_func_sandbox(pyr_func_sandbox_t **sbp) {
    pyr_func_sandbox_t *s = *sbp;
    if (!s)
        return;

    if (s->func_name)
        free(s->func_name);

    // domains are freed by free_dom_list in pyr_security_context_free
    // which is called before this function
    /*printf("[%s] freeing read-only\n", __func__);
    if (s->read_only)
        free_dom_list(&s->read_only);
    */
    printf("[%s] freeing read-write\n", __func__);
    if (s->read_write)
        free_pyr_data_obj(&s->read_write);
    free(s);
    *sbp = NULL;
}

// the caller has checked that the domain for this object exists
int new_pyr_data_obj(pyr_data_obj_t **objp,
                     char *name, char *dom_label) {
    int err = -1;
    pyr_data_obj_t *o = NULL;

    o = malloc(sizeof(pyr_data_obj_t));
    if (!o)
        goto fail;

    o->name = NULL;
    o->domain_label = NULL;
    o->addr = NULL;
    o->size = 0;

    if (copy_str(name, &o->name))
        goto fail;
    if(copy_str(dom_label, &o->domain_label))
        goto fail;

    *objp = o;
    return 0;
 fail:
    if (o)
        free_pyr_data_obj(&o);
    *objp = NULL;
    return err;
}

// the caller has checked that the domain for this object exists
int new_pyr_data_obj_domain(pyr_data_obj_domain_t **domp,
                            char *label) {
    int err = -1;
    pyr_data_obj_domain_t *d = NULL;

    d = malloc(sizeof(pyr_data_obj_domain_t));
    if (!d)
        goto fail;

    d->label = NULL;
    d->memdom_id = -1;
    d->writable = false;

    if (copy_str(label, &d->label))
        goto fail;

    d->memdom_id = memdom_create();
    if (d->memdom_id <= 0) {
        goto fail;
    }
    // don't forget to add the main thread to this memdom
    smv_join_domain(d->memdom_id, MAIN_THREAD);

    *domp = d;
    return 0;
 fail:
    if (d)
        free_pyr_data_obj_domain(&d);
    *domp = NULL;
    return err;
}

int new_pyr_func_sandbox(pyr_func_sandbox_t **sbp, char *func_name) {
    int err = -1;
    pyr_func_sandbox_t *s = NULL;

    s = malloc(sizeof(pyr_func_sandbox_t));
    if (!s)
        goto fail;

    s->func_name = NULL;
    s->read_only = NULL;
    s->read_write = NULL;
    s->in_sandbox = false;
    s->next = NULL;

    if (copy_str(func_name, &s->func_name))
        goto fail;

    *sbp = s;
    return 0;
 fail:
    if (s)
        free_pyr_func_sandbox(&s);
    *sbp = NULL;
    return err;
}

pyr_func_sandbox_t *find_sandbox(char *func_name,
                                 pyr_func_sandbox_t *sb_list) {
    pyr_func_sandbox_t *cur_sb = sb_list;

    while(cur_sb) {
        if (!strncmp(cur_sb->func_name, func_name, strlen(cur_sb->func_name)))
            goto out;
        cur_sb = cur_sb->next;
    }
 out:
    return cur_sb;
}

pyr_data_obj_domain_t *find_domain(char *domain_label,
                                   struct dom_list *dom_list) {
    struct dom_list *cur_dom = dom_list;
    pyr_data_obj_domain_t *dom = NULL;

    while(cur_dom) {
        if (!strncmp(cur_dom->domain->label, domain_label,
                     strlen(cur_dom->domain->label))) {
            dom = cur_dom->domain;
            goto out;
        }
        cur_dom = cur_dom->next;
    }
 out:
    return dom;
}

pyr_data_obj_t *find_data_obj(char *obj_name,
                              struct obj_list *obj_list) {
    struct obj_list *cur_obj = obj_list;
    pyr_data_obj_t *obj = NULL;

    if (!obj_name)
      return NULL;

    while(cur_obj) {
        if (!strncmp(cur_obj->obj->name, obj_name,
                     strlen(cur_obj->obj->name))) {
            obj = cur_obj->obj;
            goto out;
        }
        cur_obj = cur_obj->next;
    }
 out:
    return obj;
}

pyr_data_obj_t *find_data_obj_in_dom(char *domain_label,
                              struct obj_list *obj_list) {
    struct obj_list *cur_obj = obj_list;
    pyr_data_obj_t *obj = NULL;

    while(cur_obj) {
      if (!strncmp(cur_obj->obj->domain_label, domain_label,
                   strlen(cur_obj->obj->domain_label))) {
        obj = cur_obj->obj;
        goto out;
      }
      cur_obj = cur_obj->next;
    }
 out:
    return obj;
}

static void insert_new_domain(pyr_data_obj_domain_t *dom,
                              struct dom_list **list) {
    struct dom_list *item = NULL;
    struct dom_list *l = *list;
    item = malloc(sizeof(struct dom_list));
    if (!item)
        return;

    item->domain = dom;
    item->next = l;
    l = item;
    *list = l;
}

static void insert_new_data_obj(pyr_data_obj_t *obj,
                                struct obj_list **list) {
    struct obj_list *item = NULL;
    struct obj_list *l = *list;
    item = malloc(sizeof(struct obj_list));
    if (!item)
        return;

    item->obj = obj;
    item->next = l;
    l = item;
    *list = l;
}

// Deserialize a lib policy string received from userspace
// profile is NOT NULL
int pyr_parse_data_obj_rules(char **obj_rules, int num_rules,
                             struct pyr_security_context **ctx) {
    int err = -1;
    char *next_rule, obj_marker, *obj_name, *dom_label, *func_name;
    int i = 0;
    int is_rw = 0;
    pyr_data_obj_domain_t *dom = NULL;
    pyr_data_obj_t *obj = NULL;
    pyr_func_sandbox_t *func_sb = NULL;

    for (i = 0; i < num_rules; i++) {
        next_rule = obj_rules[i];
        if (!next_rule)
            goto malformed;

        obj_marker = next_rule[0];
        if (obj_marker == '+') {
            is_rw = 1;
        }
        else if (obj_marker != '-') {
            goto malformed;
        }
        if (is_rw)
            strsep(&next_rule, RW_DATA_OBJ_MARKER);
        else
            strsep(&next_rule, RO_DATA_OBJ_MARKER);

        printf("[%s] Parsing %s rule %s\n", __func__,
               (is_rw ? "RW" : "RO"), next_rule);

        obj_name = strsep(&next_rule, DOMAIN_DELIM);
        if (!obj_name) {
            goto malformed;
        }
        dom_label = strsep(&next_rule, FUNC_NAME_DELIM);
        if (!dom_label) {
            goto malformed;
        }
        func_name = strsep(&next_rule, LIB_RULE_DELIM);
        if (!func_name) {
            goto malformed;
        }

        // let's create all new data structures and insert them
        // into our security context if they don't exist yet
        dom = find_domain(dom_label, (*ctx)->obj_domains_list);
        if (!dom) {
            err = new_pyr_data_obj_domain(&dom, dom_label);
            insert_new_domain(dom, &(*ctx)->obj_domains_list);
        }

        obj = find_data_obj(obj_name, (*ctx)->data_objs_list);
        if (!obj) {
            err = new_pyr_data_obj(&obj, obj_name, dom_label);
            insert_new_data_obj(obj, &(*ctx)->data_objs_list);
        }

        func_sb = find_sandbox(func_name, (*ctx)->func_sandboxes);
        if (!func_sb) {
            rlog("[%s] New function sandbox %s\n", __func__, func_name);
            new_pyr_func_sandbox(&func_sb, func_name);
            func_sb->next = (*ctx)->func_sandboxes;
            (*ctx)->func_sandboxes = func_sb;
        }

        // now we can actually determine the access rule
        if (is_rw && !func_sb->read_write)
            func_sb->read_write = obj;
        else if (!is_rw && !find_data_obj(obj_name, func_sb->read_only))
            insert_new_data_obj(obj, &func_sb->read_only);

        is_rw = 0; // need to reset this flag at each iteration
    }
    goto out;

 malformed:
    printf("[%s] Malformed data object policy rule %s\n", __func__,
           obj_rules[i]);
    err = -1;
 out:
    return err;
}

int pyr_security_context_alloc(struct pyr_security_context **ctxp,
                               pyr_cg_node_t *(*collect_callstack_cb)(void),
                               void (*interpreter_lock_acquire_cb)(void),
                               void (*interpreter_lock_release_cb)(void)) {
    int err = -1;
    struct pyr_security_context *c = NULL;
    int interp_memdom = -1;
    int i = 0;

    // we want this to be allocated in the interpreter memdom
    c = malloc(sizeof(struct pyr_security_context));
    if (!c)
      goto fail;

    c->func_sandboxes = NULL;
    c->data_objs_list = NULL;
    c->obj_domains_list = NULL;

    c->interp_doms = malloc(sizeof(pyr_interp_dom_alloc_t));
    if (!c->interp_doms)
      goto fail;
    if ((interp_memdom = memdom_create()) == -1) {
      printf("[%s] Could not create interpreter dom # %d\n", __func__, 1);
      goto fail;
    }

    // don't forget to add the main thread to this memdom
    smv_join_domain(interp_memdom, MAIN_THREAD);
    memdom_priv_add(interp_memdom, MAIN_THREAD, MEMDOM_READ | MEMDOM_WRITE);

    c->interp_doms->memdom_id = interp_memdom;
    c->interp_doms->start = NULL;
    c->interp_doms->end = NULL;
    c->interp_doms->has_space = true;
    c->interp_doms->writable = true;
    c->interp_doms->next = NULL;

    c->main_path = NULL;
    // this ensures that we really do revoke write access at the end of pyr_init
    c->nested_grants = 1;

    /*if (!collect_callstack_cb) {
        printf("[%s] Need non-null callstack collect callback\n", __func__);
        err = -EINVAL;
        goto fail;
        }*/
    c->collect_callstack_cb = collect_callstack_cb;
    c->interpreter_lock_acquire_cb = interpreter_lock_acquire_cb;
    c->interpreter_lock_release_cb = interpreter_lock_release_cb;

    *ctxp = c;
    return 0;
 fail:
    if (c)
      free(c);
    *ctxp = NULL;
    return err;
}

static void free_interp_doms(pyr_interp_dom_alloc_t **domp) {
    pyr_interp_dom_alloc_t *d = *domp;
    int memdom_id = -1;

    if (!d)
        return;

    if (d->next != NULL)
        free_interp_doms(&d->next);

    rlog("[%s] Interpreter allocation meta for memdom %d\n", __func__, d->memdom_id);

    if (d->start)
      memdom_free(d->start);
    memdom_kill(d->memdom_id);
    *domp = NULL;
}

void pyr_security_context_free(struct pyr_security_context **ctxp) {
    struct pyr_security_context *c = *ctxp;
    int i = 0;

    if (!c)
        return;

    rlog("[%s] Freeing security context %p\n", __func__, c);

    free_obj_list(&c->data_objs_list);
    free_dom_list(&c->obj_domains_list);
    free_pyr_func_sandbox(&c->func_sandboxes);
    free_interp_doms(&c->interp_doms);
    free(c);
    *ctxp = NULL;
}

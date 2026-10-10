// POC: credential-file opens, matched with LPM tries filled by the daemon
// (mon/src/bpf.rs, CRED_PATTERNS). Record only: matches are logged.
//
// Two tries cover the three kinds of pattern:
//   patterns     anchored at each '/' of the path:
//                  substring "/secrets/"     data "/secrets/"       prefixlen 9*8
//                  path tail "/.ssh/config"  data "/.ssh/config\0"  prefixlen 13*8
//                the NUL in a tail pattern only matches at the path's end.
//   name_suffix  the last path component, reversed: a suffix of the name is
//                a prefix of the reversed name, so "credentials" is stored as
//                "slaitnederc" and matches aws_credentials.
// A lookup's prefixlen stops at the path's NUL, so a match never runs into
// bytes left in the scratch buffer by an earlier, longer path.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "logger.h"
#include "mon.bpf.h"

#define PATH_BUF     4096   // a power of two
#define MAX_PAT      128    // longest '/'-anchored pattern, its NUL included
#define NAME_MAX_REV 64     // longest filename suffix
#define MAX_PATTERNS 1024
#define RULE_NAME    32

struct lpm_key {
    u32 prefixlen;          // in bits
    u8  data[MAX_PAT];
};

struct name_key {
    u32 prefixlen;          // in bits
    u8  data[NAME_MAX_REV];
};

// Value of both tries; name is the pattern as written, for the log.
struct cred_rule {
    u32  id;
    char name[RULE_NAME];
};

struct scratch {
    char path[PATH_BUF];
    char pad[MAX_PAT];      // lets a MAX_PAT read start at any path offset
    struct lpm_key key;
    struct name_key nkey;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, MAX_PATTERNS);
    __type(key, struct lpm_key);
    __type(value, struct cred_rule);
} patterns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, MAX_PATTERNS);
    __type(key, struct name_key);
    __type(value, struct cred_rule);
} name_suffix SEC(".maps");

// Too big for the stack.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct scratch);
} file2_scratch SEC(".maps");

struct scan_ctx {
    struct scratch *s;
    u32 len;                // path length, NUL included
    u32 last_slash;         // offset of the last '/' seen
    u32 match_off;          // offset in path where the pattern starts
    bool found;
    struct cred_rule rule;  // copied: no map pointer kept across bpf_loop
};

// bpf_loop callback, verified once whatever the path length: looks up the
// path from each '/' in the patterns trie. Returns 1 to stop the loop.
static long scan_cb(u64 idx, void *data)
{
    struct scan_ctx *c = data;
    struct scratch *s = c->s;
    struct cred_rule *rule;
    u32 i = idx, rem;

    if (!s || i >= c->len || i >= PATH_BUF)
        return 1;
    i &= PATH_BUF - 1;

    if (s->path[i] != '/')
        return 0;
    c->last_slash = i;

    // Never let the trie match past the end of the string.
    rem = c->len - i;
    if (rem > MAX_PAT)
        rem = MAX_PAT;
    s->key.prefixlen = rem * 8;

    if (bpf_probe_read_kernel(s->key.data, MAX_PAT, &s->path[i]))
        return 1;

    rule = bpf_map_lookup_elem(&patterns, &s->key);
    if (!rule)
        return 0;

    c->rule = *rule;
    c->match_off = i;
    c->found = true;
    return 1;
}

// Look up the last path component, reversed, in name_suffix. Names longer
// than NAME_MAX_REV are cut to their last NAME_MAX_REV characters, which
// is all a suffix pattern can cover.
static __always_inline struct cred_rule *name_lookup(struct scratch *s, u32 len,
                                                     u32 last_slash)
{
    u32 nlen = len - 2 - last_slash;   // characters after the '/'

    if (last_slash >= len - 2)
        return NULL;   // the path ends in '/'
    if (nlen > NAME_MAX_REV)
        nlen = NAME_MAX_REV;

    for (int k = 0; k < NAME_MAX_REV; k++) {
        if (k >= nlen)
            break;
        s->nkey.data[k] = s->path[(len - 2 - k) & (PATH_BUF - 1)];
    }
    s->nkey.prefixlen = nlen * 8;
    return bpf_map_lookup_elem(&name_suffix, &s->nkey);
}

SEC("fentry/security_file_open")
int BPF_PROG(mon_file2_open, struct file *file)
{
    struct scan_ctx c = {};
    struct scratch *s;
    u32 zero = 0;
    long len;

    if (!bpf_task_storage_get(&task_ctx_map, bpf_get_current_task_btf(), NULL, 0))
        return 0;

    s = bpf_map_lookup_elem(&file2_scratch, &zero);
    if (!s)
        return 0;

    // Length with the NUL, or < 0 (e.g. -ENAMETOOLONG): fail open.
    len = bpf_d_path(&file->f_path, s->path, PATH_BUF);
    if (len < 2 || len > PATH_BUF)
        return 0;

    c.s = s;
    c.len = len;
    bpf_loop(len, scan_cb, &c, 0);

    // The loop stops at the first match, so last_slash is only the
    // filename's '/' when nothing matched.
    if (!c.found) {
        struct cred_rule *rule = name_lookup(s, len, c.last_slash);

        if (!rule)
            return 0;
        c.rule = *rule;
        c.match_off = c.last_slash + 1;
    }

    log_info("file2: pid=%u rule=%u pat=%s off=%u path=%s",
             bpf_get_current_pid_tgid() >> 32, c.rule.id, c.rule.name,
             c.match_off, s->path);
    return 0;
}

// Required: bpf_d_path is GPL-only.
char LICENSE[] SEC("license") = "GPL";

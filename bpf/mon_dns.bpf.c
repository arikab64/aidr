// POC: DNS rule matching. Record only: every query from a tracked task is
// logged as a hit or a miss, nothing is blocked.
//
// Hooks fentry/udp_sendmsg and fentry/udpv6_sendmsg for destination port 53.
// They run in the sending task, so pid is the querier's. mon_net's own
// fentry/udp_sendmsg is unaffected: each program gets its own trampoline slot.
//
// Rules live in an LPM trie the daemon fills (mon/src/bpf.rs, DNS_RULES):
// lowercase names, byte-reversed, so a domain suffix becomes a trie prefix.
//   wildcard "*.example.com"   data "moc.elpmaxe."      prefixlen 12*8
//   exact    "api.example.com" data "moc.elpmaxe.ipa\0" prefixlen 16*8
// A wildcard does not cover the apex ("example.com"): the '.' it ends with
// must be in the name. Add an exact rule for the apex.
//
// Lookup key: the queried name, lowercased, reversed, then a NUL. One trie
// lookup per query; the longest (most specific) rule wins.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "logger.h"
#include "mon.bpf.h"

#define DNS_PORT     53
#define DNS_HDR      12
#define DNS_MIN      17      // header + root name + qtype + qclass

#define PKT_BUF      512     // a power of two
#define NAME_BUF     256     // a power of two; the kernel's LPM key data max
#define NAME_MAX_LEN 253     // longest dotted name
#define MAX_RULES    4096
#define RULE_NAME    64

struct dns_key {
    u32 prefixlen;           // in bits
    u8  data[NAME_BUF];
};

// Trie value; name is the rule as written, cut to RULE_NAME - 1, for the log.
struct dns_rule {
    u32  id;
    char name[RULE_NAME];
};

struct dns_scratch {
    char name[NAME_BUF];     // forward, lowercase, dotted
    u8   pkt[PKT_BUF];       // raw DNS message
    u8   rev[NAME_BUF];      // reversed name, right-aligned
    u8   nul;                // never written: the terminator after rev
    u8   pad[NAME_BUF];      // lets a NAME_BUF read start anywhere in rev
    struct dns_key key;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, MAX_RULES);
    __type(key, struct dns_key);
    __type(value, struct dns_rule);
} dns_rules SEC(".maps");

// Too big for the stack.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct dns_scratch);
} dns_scratch SEC(".maps");

// Pre-6.4 kernels name the iovec pointer `iov`; newer ones `__iov`.
struct iov_iter___old {
    const struct iovec *iov;
} __attribute__((preserve_access_index));

// User-space address of the first payload byte, or NULL if unsupported.
static __always_inline const void *payload_base(struct msghdr *msg)
{
    size_t off = BPF_CORE_READ(msg, msg_iter.iov_offset);
    u8 type = BPF_CORE_READ(msg, msg_iter.iter_type);
    const struct iovec *iovp;
    struct iovec iov;

    if (bpf_core_enum_value_exists(enum iter_type, ITER_UBUF) &&
        type == bpf_core_enum_value(enum iter_type, ITER_UBUF))
        return BPF_CORE_READ(msg, msg_iter.ubuf) + off;

    if (type != bpf_core_enum_value(enum iter_type, ITER_IOVEC))
        return NULL;   // kernel-internal sender (kvec, bvec, ...)

    if (bpf_core_field_exists(msg->msg_iter.__iov)) {
        iovp = BPF_CORE_READ(msg, msg_iter.__iov);
    } else {
        struct iov_iter___old *old = (void *)msg +
            bpf_core_field_offset(struct msghdr, msg_iter);

        iovp = BPF_CORE_READ(old, iov);
    }
    // First segment only: a DNS query is sent as one buffer in practice.
    if (bpf_probe_read_kernel(&iov, sizeof(iov), iovp))
        return NULL;
    return iov.iov_base + off;
}

struct qname_ctx {
    struct dns_scratch *s;
    u32 rd;                  // valid bytes in s->pkt
    u32 remain;              // bytes left in the current label
    u32 out;                 // characters emitted so far
    u32 end;                 // pkt offset of the terminating zero
    u32 done;
};

static __always_inline int emit(struct qname_ctx *c, struct dns_scratch *s, u8 ch)
{
    u32 o = c->out;

    if (o >= NAME_MAX_LEN)
        return -1;
    // Keeps clang from dropping the masks below as no-ops (see qname_cb).
    barrier_var(o);
    s->name[o & (NAME_BUF - 1)] = ch;
    s->rev[(NAME_BUF - 1 - o) & (NAME_BUF - 1)] = ch;
    c->out = o + 1;
    return 0;
}

// bpf_loop callback, one wire byte per call:
// "\3www\7example\3com\0" -> "www.example.com". Returns 1 to stop.
static long qname_cb(u64 idx, void *data)
{
    struct qname_ctx *c = data;
    struct dns_scratch *s = c->s;
    u32 pos = DNS_HDR + (u32)idx;
    u8 ch;

    if (!s || pos >= c->rd || pos >= PKT_BUF)
        return 1;
    // Clang can prove pos < PKT_BUF from the check above, drops the mask,
    // and reloads pos through a register the verifier has no bounds for.
    // barrier_var hides the value from clang, so the mask stays.
    barrier_var(pos);
    ch = s->pkt[pos & (PKT_BUF - 1)];

    if (c->remain == 0) {   // length byte
        if (ch == 0) {
            c->end = pos;
            c->done = 1;
            return 1;
        }
        if (ch & 0xc0)      // compression: not valid in a query
            return 1;
        c->remain = ch;
        if (c->out && emit(c, s, '.'))
            return 1;
        return 0;
    }

    if (ch >= 'A' && ch <= 'Z')
        ch += 'a' - 'A';
    if (emit(c, s, ch))
        return 1;
    c->remain--;
    return 0;
}

static __always_inline int handle_send(struct msghdr *msg, size_t len,
                                       u8 family, __be16 dport)
{
    struct qname_ctx c = {};
    struct dns_scratch *s;
    struct dns_rule *rule;
    const void *ubase;
    u32 zero = 0, n, rd, e, qtype = 0;
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (dport != bpf_htons(DNS_PORT) || len < DNS_MIN)
        return 0;

    ubase = payload_base(msg);
    if (!ubase)
        return 0;

    s = bpf_map_lookup_elem(&dns_scratch, &zero);
    if (!s)
        return 0;

    rd = len > PKT_BUF ? PKT_BUF : len;
    if (bpf_probe_read_user(s->pkt, rd, ubase))
        return 0;

    // A standard query with exactly one question.
    if ((s->pkt[2] & 0x80) || s->pkt[4] != 0 || s->pkt[5] != 1)
        return 0;

    c.s = s;
    c.rd = rd;
    bpf_loop(NAME_BUF, qname_cb, &c, 0);
    if (!c.done || c.out == 0) {
        log_debug("dns: pid=%u <unparsed query>", pid);
        return 0;
    }

    n = c.out & (NAME_BUF - 1);   // 1..253
    s->name[n] = 0;

    // rev is right-aligned: the reversed name starts at NAME_BUF - n and is
    // followed by the always-zero nul byte, which the key includes.
    s->key.prefixlen = (n + 1) * 8;
    if (bpf_probe_read_kernel(s->key.data, NAME_BUF,
                              &s->rev[(NAME_BUF - n) & (NAME_BUF - 1)]))
        return 0;

    // QTYPE is the 2 bytes after the name's terminating zero. Mask the
    // indexes before the check, where clang can't prove the masks redundant,
    // and hide them with barrier_var so it doesn't recompute them unmasked
    // (see qname_cb).
    e = c.end;
    u32 qhi = (e + 1) & (PKT_BUF - 1), qlo = (e + 2) & (PKT_BUF - 1);

    barrier_var(qhi);
    barrier_var(qlo);
    if (e + 2 < rd && e + 2 < PKT_BUF)
        qtype = s->pkt[qhi] << 8 | s->pkt[qlo];

    rule = bpf_map_lookup_elem(&dns_rules, &s->key);
    if (rule)
        log_info("dns: pid=%u hit rule=%u pat=%s name=%s qtype=%u af=%u",
                 pid, rule->id, rule->name, s->name, qtype, family);
    else
        log_info("dns: pid=%u miss name=%s qtype=%u af=%u",
                 pid, s->name, qtype, family);
    return 0;
}

// Skip untracked tasks.
static __always_inline bool task_tracked(void)
{
    return bpf_task_storage_get(&task_ctx_map, bpf_get_current_task_btf(), NULL, 0);
}

SEC("fentry/udp_sendmsg")
int BPF_PROG(mon_dns_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
    struct sockaddr_in sin = {};
    void *name;
    __be16 dport;

    if (!task_tracked())
        return 0;

    name = BPF_CORE_READ(msg, msg_name);
    if (name) {   // sendto()/sendmsg() with an address
        if (bpf_probe_read_kernel(&sin, sizeof(sin), name))
            return 0;
        dport = sin.sin_port;
    } else {      // connected socket
        dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    }
    return handle_send(msg, len, AF_INET, dport);
}

SEC("fentry/udpv6_sendmsg")
int BPF_PROG(mon_dns_udpv6_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
    struct sockaddr_in6 sin6 = {};
    struct in6_addr daddr;
    void *name;
    __be16 dport;

    if (!task_tracked())
        return 0;

    name = BPF_CORE_READ(msg, msg_name);
    if (name) {
        if (bpf_probe_read_kernel(&sin6, sizeof(sin6), name))
            return 0;
        // An AF_INET destination on a v6 socket is passed on to
        // udp_sendmsg(), which reports it.
        if (sin6.sin6_family != AF_INET6)
            return 0;
        daddr = sin6.sin6_addr;
        dport = sin6.sin6_port;
    } else {
        daddr = BPF_CORE_READ(sk, __sk_common.skc_v6_daddr);
        dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    }

    // v4-mapped destinations also go through udp_sendmsg(): skip here.
    if (daddr.in6_u.u6_addr32[0] == 0 && daddr.in6_u.u6_addr32[1] == 0 &&
        daddr.in6_u.u6_addr32[2] == bpf_htonl(0x0000ffff))
        return 0;

    return handle_send(msg, len, AF_INET6, dport);
}

char LICENSE[] SEC("license") = "GPL";

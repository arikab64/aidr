#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include "logger.h"
#include "mon.bpf.h"
#include "mon_progs.bpf.h"

#define DNS_PORT    53
#define MDNS_PORT   5353

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD

struct conn_ident {
    u64 workload_id;
    u64 leader_start_boottime;  /* disambiguates tgid under pid reuse */
    u32 tgid;
    u32 tid;                    /* the connecting thread */
    sock_tuple_t tuple;         /* the 5-tuple of the socket, in host byte order */
};

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct conn_ident);
} conn_ident_map SEC(".maps");

// Userspace writes these right before bpf_iter_create() to select the
// workload and the operation of the pass. Single threaded daemon, so passes
// never overlap. mon_iter_task_file only seeds, so it reads just the
// workload id; the op selects what mon_iter_tcp does.
volatile u64 mon_net_iter_workload_id = 0;
enum mon_net_iter_op {
    MON_NET_ITER_UNMARK = 0, // drop every conn_ident whose workload_id matches
    MON_NET_ITER_DUMP   = 1, // print every conn_ident (workload_id != 0 filters)
};
volatile u32 mon_net_iter_op = MON_NET_ITER_DUMP;


// Fill *t from a sock_common, the prefix every socket kind shares (full,
// request, and timewait socks alike), so this also serves iter/tcp. proto
// is passed in because it lives outside sock_common.
static __always_inline void sock_tuple_from_skc(struct sock_common *skc,
                                                u8 proto, sock_tuple_t *t)
{
    u16 sport = skc->skc_num;

    t->ipv4 = skc->skc_family != AF_INET6;
    t->proto = proto;
    t->sport = sport ? sport : -1;
    t->dport = bpf_ntohs(skc->skc_dport);

    if (t->ipv4) {
        t->saddr.v4 = skc->skc_rcv_saddr;
        t->daddr.v4 = skc->skc_daddr;
    } else {
        t->saddr.v6 = skc->skc_v6_rcv_saddr;
        t->daddr.v6 = skc->skc_v6_daddr;
    }
}

// Fill *t from a full socket.
static __always_inline void sock_tuple_from_sk(struct sock *sk, sock_tuple_t *t)
{
    sock_tuple_from_skc(&sk->__sk_common, sk->sk_protocol, t);
}


// Fill *ci from a task known to be tracked. group_leader->start_boottime is
// stable for the life of the thread group, so (tgid, leader_start_boottime)
// still names the right process after the tgid has been reused.
static __always_inline void fill_conn_ident(struct conn_ident *ci,
                                            struct task_struct *task,
                                            task_ctx_t *tc, u32 tid, sock_tuple_t *tuple)
{
    ci->workload_id = tc->workload_id;
    ci->leader_start_boottime = BPF_CORE_READ(task, group_leader, start_boottime);
    ci->tgid = task->tgid;
    ci->tid = tid;
    ci->tuple = *tuple;
}

// tcp_connect() sends the SYN, synchronously on the connect(2) path, so
// current is still the connecting thread. It is TCP only (v4 and v6), runs
// once per real SYN, and by now the socket carries the full 4-tuple.
SEC("fentry/tcp_connect")
int BPF_PROG(mon_net_connect, struct sock *sk)
{
    struct task_struct *task = bpf_get_current_task_btf();
    task_ctx_t *tc = bpf_task_storage_get(&task_ctx_map, task, NULL, 0);
    if (!tc)
        return 0;

    struct conn_ident *ci = bpf_sk_storage_get(&conn_ident_map, sk, NULL,
                                               BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!ci) {
        log_warn("net_connect [%llu]: tid=%u no conn ident: storage alloc failed",
                 tc->workload_id, tc->tid);
        return 0;
    }

    sock_tuple_t tuple;
    sock_tuple_from_sk(sk, &tuple);
    fill_conn_ident(ci, task, tc, (u32)bpf_get_current_pid_tgid(), &tuple);
    sock_tuple_t *t = &ci->tuple;

    log_info("net_connect [%llu]: pid=%u tid=%u leader_start=%llu conn ident stored",
             ci->workload_id, ci->tgid, ci->tid, ci->leader_start_boottime);

    if (t->ipv4)
        log_info("net_connect [%llu]: pid=%u proto=%u %pI4:%d -> %pI4:%u",
                 ci->workload_id, ci->tgid, t->proto,
                 &t->saddr.v4, t->sport, &t->daddr.v4, t->dport);
    else
        log_info("net_connect [%llu]: pid=%u proto=%u [%pI6]:%d -> [%pI6]:%u",
                 ci->workload_id, ci->tgid, t->proto,
                 &t->saddr.v6, t->sport, &t->daddr.v6, t->dport);

    return 0;
}

// tcp_sendmsg() is called when sending data on a TCP socket.
// We use this to detect the first send and log the need to parse.
#ifndef ITER_UBUF
#define ITER_UBUF 0
#endif
#ifndef ITER_IOVEC
#define ITER_IOVEC 1
#endif

#define MAX_SNI_READ 255

static __always_inline void parse_sni(struct msghdr *msg, struct conn_ident *ci) {
    u8 iter_type = BPF_CORE_READ(msg, msg_iter.iter_type);
    void *buf = NULL;
    size_t len = 0;

    if (iter_type == ITER_UBUF) {
        buf = BPF_CORE_READ(msg, msg_iter.ubuf);
        len = BPF_CORE_READ(msg, msg_iter.count);
    } else if (iter_type == ITER_IOVEC) {
        const struct iovec *iov = BPF_CORE_READ(msg, msg_iter.__iov);
        buf = BPF_CORE_READ(iov, iov_base);
        len = BPF_CORE_READ(iov, iov_len);
    }

    if (!buf || len < 47) return;

    char data[MAX_SNI_READ];
    size_t read_len = len;
    if (read_len > MAX_SNI_READ) read_len = MAX_SNI_READ;
    
    if (bpf_probe_read_user(data, read_len & 0xFF, buf) < 0) {
        return;
    }

    if (data[0] != 0x16) return; // Handshake
    if (data[1] != 0x03) return; // Version
    if (data[5] != 0x01) return; // Client Hello

    int offset = 43;
    if (offset >= read_len) return;
    u8 session_id_len = data[(offset) & 0xFF];
    offset += 1 + session_id_len;

    if (offset + 2 > read_len) return;
    u16 cipher_suites_len = (data[(offset) & 0xFF] << 8) | data[(offset + 1) & 0xFF];
    offset += 2 + cipher_suites_len;

    if (offset + 1 > read_len) return;
    u8 comp_methods_len = data[(offset) & 0xFF];
    offset += 1 + comp_methods_len;

    if (offset + 2 > read_len) return;
    u16 ext_len = (data[(offset) & 0xFF] << 8) | data[(offset + 1) & 0xFF];
    offset += 2;

    int limit = offset + ext_len;
    if (limit > read_len) limit = read_len;

    #pragma unroll
    for (int i = 0; i < 10; i++) {
        if (offset + 4 > limit) break;
        u16 ext_type = (data[(offset) & 0xFF] << 8) | data[(offset + 1) & 0xFF];
        u16 ext_length = (data[(offset + 2) & 0xFF] << 8) | data[(offset + 3) & 0xFF];
        offset += 4;

        if (ext_type == 0) { // SNI
            if (offset + 2 > limit) break;
            u16 sni_list_len = (data[(offset) & 0xFF] << 8) | data[(offset + 1) & 0xFF];
            offset += 2;
            
            if (offset + 3 > limit) break;
            u8 sni_type = data[(offset) & 0xFF];
            u16 sni_len = (data[(offset + 1) & 0xFF] << 8) | data[(offset + 2) & 0xFF];
            offset += 3;

            if (sni_type == 0 && offset + sni_len <= limit) {
                char sni[64] = {0};
                int cp_len = sni_len;
                if (cp_len > sizeof(sni) - 1) cp_len = sizeof(sni) - 1;
                
                for (int j = 0; j < sizeof(sni); j++) {
                    if (j >= (cp_len & 0x3F)) break;
                    sni[j] = data[(offset + j) & 0xFF];
                }
                
                log_info("net_sendmsg [%llu]: pid=%u tid=%u SNI: %s",
                         ci->workload_id, ci->tgid, ci->tid, sni);
                return;
            }
        }
        offset += ext_length;
    }
}
SEC("fentry/tcp_sendmsg")
int BPF_PROG(mon_net_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
    struct task_struct *task = bpf_get_current_task_btf();
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    u64 bytes_sent = BPF_CORE_READ(tp, bytes_sent);
    
    struct conn_ident *ci = bpf_sk_storage_get(&conn_ident_map, sk, NULL, 0);
    if (!ci) {
        task_ctx_t *tc = bpf_task_storage_get(&task_ctx_map, task, NULL, 0);
        if (!tc)
            return 0;

        ci = bpf_sk_storage_get(&conn_ident_map, sk, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
        if (!ci) {
            log_warn("net_sendmsg [%llu]: tid=%u no conn ident: storage alloc failed",
                     tc->workload_id, tc->tid);
            return 0;
        }

        sock_tuple_t tuple;
        sock_tuple_from_sk(sk, &tuple);
        fill_conn_ident(ci, task, tc, (u32)bpf_get_current_pid_tgid(), &tuple);
        
        log_info("net_sendmsg [%llu]: pid=%u tid=%u leader_start=%llu conn ident stored",
                 ci->workload_id, ci->tgid, ci->tid, ci->leader_start_boottime);
    }
    
    if (bytes_sent == 0) {
        if (ci->tuple.dport == 443) {
            parse_sni(msg, ci);
        } else {
            log_info("net_sendmsg [%llu]: pid=%u tid=%u need to parse",
                     ci->workload_id, ci->tgid, ci->tid);
        }
    }

    return 0;
}

SEC("fentry/udp_sendmsg")
int BPF_PROG(mon_net_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
    struct task_struct *task = bpf_get_current_task_btf();
    
    struct conn_ident *ci = bpf_sk_storage_get(&conn_ident_map, sk, NULL, 0);
    if (!ci) {
        task_ctx_t *tc = bpf_task_storage_get(&task_ctx_map, task, NULL, 0);
        if (!tc)
            return 0;

        ci = bpf_sk_storage_get(&conn_ident_map, sk, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
        if (!ci) {
            log_warn("udp_sendmsg [%llu]: tid=%u no conn ident: storage alloc failed",
                     tc->workload_id, tc->tid);
            return 0;
        }

        sock_tuple_t tuple;
        sock_tuple_from_sk(sk, &tuple);
        fill_conn_ident(ci, task, tc, (u32)bpf_get_current_pid_tgid(), &tuple);
        
        log_info("udp_sendmsg [%llu]: pid=%u tid=%u leader_start=%llu conn ident stored",
                 ci->workload_id, ci->tgid, ci->tid, ci->leader_start_boottime);
    }

    return 0;
}

// Seed pass, run right after mon_iter_task has marked a workload: walk the
// open files of every task, and give each TCP socket owned by a task of
// mon_net_iter_workload_id a conn_ident. This is the iterator that can reach
// the owner, because it starts from the task instead of the socket: a task
// knows its files and a file knows its socket, but a socket knows no task.
// One linear walk over the host's open files, with the kernel holding the
// references. Threads sharing a files table are visited once.
//
// The connecting thread is unknowable for a socket that already existed, so
// tid is left 0. A socket already stamped for another workload (fd passed
// across workloads) is left alone: the first identity wins.
SEC("iter/task_file")
int mon_iter_task_file(struct bpf_iter__task_file *ctx)
{
    struct seq_file *seq = ctx->meta->seq;
    struct task_struct *task = ctx->task;
    struct file *file = ctx->file;

    if (!task || !file)
        return 0;

    if (ctx->meta->seq_num == 0)
        BPF_SEQ_PRINTF(seq, "%5s %5s %5s\n", "PID", "TID", "FD");

    task_ctx_t *tc = bpf_task_storage_get(&task_ctx_map, task, NULL, 0);
    if (!tc || tc->workload_id != mon_net_iter_workload_id)
        return 0;

    struct socket *sock = bpf_sock_from_file(file);
    if (!sock)
        return 0;

    struct sock *sk = sock->sk;
    if (!sk || (sk->sk_protocol != IPPROTO_TCP && sk->sk_protocol != IPPROTO_UDP))
        return 0;

    // Stamped already, by tcp_connect or an earlier pass.
    if (bpf_sk_storage_get(&conn_ident_map, sk, NULL, 0))
        return 0;

    struct conn_ident *ci = bpf_sk_storage_get(&conn_ident_map, sk, NULL,
                                               BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!ci)
        return 0;

    sock_tuple_t t;
    sock_tuple_from_sk(sk, &t);
    fill_conn_ident(ci, task, tc, 0, &t);

    log_info("SOCK: %5d %5d %5u\n", task->tgid, task->pid, ctx->fd);
    BPF_SEQ_PRINTF(seq, "%5d %5d %5u\n", task->tgid, task->pid, ctx->fd);
    return 0;
}

static __always_inline void seq_print_conn(struct seq_file *seq,
                                           struct sock_common *skc,
                                           struct conn_ident *ci)
{
    u8 state = skc->skc_state;
    sock_tuple_t t;

    // iter/tcp only ever hands out TCP sockets.
    sock_tuple_from_skc(skc, IPPROTO_TCP, &t);

    if (t.ipv4)
        BPF_SEQ_PRINTF(seq, "%llu %llu %5u %5u %2u %pI4:%d %pI4:%u\n",
                       ci->workload_id, ci->leader_start_boottime,
                       ci->tgid, ci->tid, state,
                       &t.saddr.v4, t.sport, &t.daddr.v4, t.dport);
    else
        BPF_SEQ_PRINTF(seq, "%llu %llu %5u %5u %2u [%pI6]:%d [%pI6]:%u\n",
                       ci->workload_id, ci->leader_start_boottime,
                       ci->tgid, ci->tid, state,
                       &t.saddr.v6, t.sport, &t.daddr.v6, t.dport);
}

// Walks every TCP socket (all states, both families). Sockets without a
// conn_ident belong to untracked tasks and are skipped.
//
// UNMARK: conn_idents of the workload are printed and deleted.
// DUMP:   conn_idents are printed, all workloads or one.
SEC("iter/tcp")
int mon_iter_tcp(struct bpf_iter__tcp *ctx)
{
    struct seq_file *seq = ctx->meta->seq;
    struct sock_common *skc = ctx->sk_common;

    if (!skc)
        return 0;

    if (ctx->meta->seq_num == 0)
        BPF_SEQ_PRINTF(seq, "%s %s %5s %5s %2s %s %s\n",
                       "WORKLOAD", "LEADER_START", "PID", "TID", "ST", "SRC", "DST");

    struct conn_ident *ci = bpf_sk_storage_get(&conn_ident_map, skc, NULL, 0);
    if (!ci)
        return 0;

    u64 workload_id = mon_net_iter_workload_id;

    if (mon_net_iter_op == MON_NET_ITER_UNMARK) {
        if (ci->workload_id != workload_id)
            return 0;
        seq_print_conn(seq, skc, ci);
        bpf_sk_storage_delete(&conn_ident_map, skc);
        return 0;
    }

    if (workload_id && ci->workload_id != workload_id)
        return 0;

    seq_print_conn(seq, skc, ci);
    return 0;
}

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 2);
    __type(key, u32);
    __type(value, u32);
} jmp_table SEC(".maps");

struct dns_parse_state {
    int offset;
    u16 ancount;
    char qname[64];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct dns_parse_state);
} dns_state_map SEC(".maps");

#define MAX_DNS_READ 255

static __always_inline void parse_dns_qname(struct msghdr *msg, struct conn_ident *ci, void *ctx) {
    u8 iter_type = BPF_CORE_READ(msg, msg_iter.iter_type);
    void *buf = NULL;
    size_t len = 0;

    if (iter_type == ITER_UBUF) {
        buf = BPF_CORE_READ(msg, msg_iter.ubuf);
        len = BPF_CORE_READ(msg, msg_iter.count);
    } else if (iter_type == ITER_IOVEC) {
        const struct iovec *iov = BPF_CORE_READ(msg, msg_iter.__iov);
        buf = BPF_CORE_READ(iov, iov_base);
        len = BPF_CORE_READ(iov, iov_len);
    }

    if (!buf || len < 12) return;

    char data[MAX_DNS_READ];
    size_t read_len = len;
    if (read_len > MAX_DNS_READ) read_len = MAX_DNS_READ;
    
    if (bpf_probe_read_user(data, read_len & 0xFF, buf) < 0) {
        return;
    }

    if ((data[2] & 0x80) == 0) return;

    u16 qdcount = (data[4] << 8) | data[5];
    if (qdcount > 1 || qdcount == 0) return;

    u16 ancount = (data[6] << 8) | data[7];
    if (ancount == 0) return;

    u32 key = 0;
    struct dns_parse_state *state = bpf_map_lookup_elem(&dns_state_map, &key);
    if (!state) return;

    state->ancount = ancount;
    state->offset = 12; // Start of QNAME
    state->qname[0] = '\0';
    int qname_idx = 0;
    u8 label_len = 0;

    #pragma unroll
    for (int i = 0; i < 64; i++) {
        if (state->offset >= read_len) break;
        
        if (label_len == 0) {
            label_len = data[state->offset & 0xFF];
            if (label_len == 0) break; // End of QNAME
            if ((label_len & 0xC0) == 0xC0) break; // Pointer compression

            if (qname_idx > 0 && qname_idx < 63) {
                state->qname[qname_idx & 0x3F] = '.';
                qname_idx++;
            }
        } else {
            if (qname_idx < 63) {
                state->qname[qname_idx & 0x3F] = data[state->offset & 0xFF];
                qname_idx++;
            }
            label_len--;
        }
        state->offset++;
    }

    if (qname_idx < 64) {
        state->qname[qname_idx & 0x3F] = '\0';
    }

    if (state->offset < read_len) {
        u8 val = data[state->offset & 0xFF];
        if (val == 0) {
            state->offset++;
        } else if ((val & 0xC0) == 0xC0) {
            state->offset += 2;
        }
    }

    state->offset += 4; // Skip QTYPE and QCLASS

    bpf_tail_call(ctx, &jmp_table, 1);
}

static __always_inline void parse_dns_answers(struct msghdr *msg, struct conn_ident *ci) {
    u8 iter_type = BPF_CORE_READ(msg, msg_iter.iter_type);
    void *buf = NULL;
    size_t len = 0;

    if (iter_type == ITER_UBUF) {
        buf = BPF_CORE_READ(msg, msg_iter.ubuf);
        len = BPF_CORE_READ(msg, msg_iter.count);
    } else if (iter_type == ITER_IOVEC) {
        const struct iovec *iov = BPF_CORE_READ(msg, msg_iter.__iov);
        buf = BPF_CORE_READ(iov, iov_base);
        len = BPF_CORE_READ(iov, iov_len);
    }

    if (!buf || len < 12) return;

    char data[MAX_DNS_READ];
    size_t read_len = len;
    if (read_len > MAX_DNS_READ) read_len = MAX_DNS_READ;
    
    if (bpf_probe_read_user(data, read_len & 0xFF, buf) < 0) {
        return;
    }

    u32 key = 0;
    struct dns_parse_state *state = bpf_map_lookup_elem(&dns_state_map, &key);
    if (!state) return;

    int offset = state->offset;
    u16 ancount = state->ancount;

    #pragma unroll
    for (int ans = 0; ans < 4; ans++) {
        if (ans >= ancount) break;
        if (offset >= read_len) break;

        if (offset < read_len) {
            u8 val = data[offset & 0xFF];
            if ((val & 0xC0) == 0xC0) {
                offset += 2;
            } else {
                break;
            }
        }

        if (offset + 10 > read_len) break;

        u16 type = (data[offset & 0xFF] << 8) | data[(offset + 1) & 0xFF];
        u16 class = (data[(offset + 2) & 0xFF] << 8) | data[(offset + 3) & 0xFF];
        u16 rdlength = (data[(offset + 8) & 0xFF] << 8) | data[(offset + 9) & 0xFF];
        offset += 10;

        if (offset + rdlength > read_len) break;

        if (type == 1 && class == 1 && rdlength == 4) { // A record
            int safe_offset = offset & 0xFF;
            if (safe_offset + 4 <= MAX_DNS_READ) {
                u32 ip;
                __builtin_memcpy(&ip, &data[safe_offset], 4);
                log_info("dns [%llu]: pid=%u tid=%u qname=%s ip=%pI4", ci->workload_id, ci->tgid, ci->tid, state->qname, &ip);
            }
        } else if (type == 28 && class == 1 && rdlength == 16) { // AAAA record
            int safe_offset = offset & 0xFF;
            if (safe_offset + 16 <= MAX_DNS_READ) {
                struct in6_addr ip6;
                __builtin_memcpy(&ip6, &data[safe_offset], 16);
                log_info("dns [%llu]: pid=%u tid=%u qname=%s ip=[%pI6]", ci->workload_id, ci->tgid, ci->tid, state->qname, &ip6);
            }
        }
        
        offset += rdlength;
    }
}

SEC("fexit/udp_recvmsg")
int BPF_PROG(mon_parse_dns_qname, struct sock *sk, struct msghdr *msg)
{
    struct conn_ident *ci = bpf_sk_storage_get(&conn_ident_map, sk, NULL, 0);
    if (!ci) return 0;
    
    parse_dns_qname(msg, ci, ctx);
    return 0;
}

SEC("fexit/udp_recvmsg")
int BPF_PROG(mon_parse_dns_answers, struct sock *sk, struct msghdr *msg)
{
    struct conn_ident *ci = bpf_sk_storage_get(&conn_ident_map, sk, NULL, 0);
    if (!ci) return 0;
    
    parse_dns_answers(msg, ci);
    return 0;
}

SEC("fexit/udp_recvmsg")
int BPF_PROG(mon_udp_recvmsg, struct sock *sk, struct msghdr *msg)
{
    struct conn_ident *ci = bpf_sk_storage_get(&conn_ident_map, sk, NULL, 0);
    if (!ci)
        return 0;

    bpf_tail_call(ctx, &jmp_table, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

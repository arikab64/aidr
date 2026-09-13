#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include "logger.h"
#include "mon.bpf.h"

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
    if (!sk || sk->sk_protocol != IPPROTO_TCP)
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

char LICENSE[] SEC("license") = "GPL";

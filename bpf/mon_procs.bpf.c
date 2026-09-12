#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "logger.h"
#include "mon.bpf.h"

// Userspace write it right before bpf_iter_create() to mark the root of the iteration. 
// The iteration is on a single threaded, so no two pass overlaps.
volatile u32 mon_iter_root_pid = 0;

#define MAX_DEPTH 16

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, u32);
    __type(value, task_ctx_t);
} task_ctx_map SEC(".maps");


static __always_inline int depth_below(struct task_struct *t, u32 root_pid, struct task_struct **root)
{
    struct task_struct *cur = t;
    for (int i = 0; i < MAX_DEPTH; i++) {
        if (BPF_CORE_READ(cur, tgid) == root_pid) {
            *root = cur;
            return i;
        }
        struct task_struct *parent = BPF_CORE_READ(cur, real_parent);
        if (parent == cur)
            break; // reached the root of the tree
        cur = parent;
    }
    return -1; // not below the root
}


static __always_inline int resolve_ancestor(struct task_struct *t, u32 root_pid, root_id_t *root)
{
    // Fast path - parent is already marked for this root, so we are one deeper. 
    struct task_struct *parent = t->real_parent;
    task_ctx_t *pc = bpf_task_storage_get(&task_ctx_map, parent, NULL, 0);
    if (pc && pc->root.id == root_pid && parent != t) {
        *root = pc->root;
        return pc->depth + 1;
    }

    // Slow path - walk up the parent chain to find a root.
    struct task_struct *root_task = NULL;
    int depth = depth_below(t, root_pid, &root_task);
    if (depth < 0)
        return -1; // not below the root

    root->id = root_pid;
    root->starttime = BPF_CORE_READ(root_task, start_time);

    return depth;
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(mon_proc_fork, struct task_struct *parent, struct task_struct *child)
{
    u32 parent_pid = parent->tgid;
    u32 child_pid = child->tgid;
    bool is_thread = child_pid == parent_pid;

    if (is_thread) 
        return 0;

    // Inherit the task context from the parent.
    task_ctx_t *pc = bpf_task_storage_get(&task_ctx_map, parent, NULL, 0);
    if (pc) {
        task_ctx_t *cc = bpf_task_storage_get(&task_ctx_map, child, NULL,
                                              BPF_LOCAL_STORAGE_GET_F_CREATE);
        if (cc) {
            cc->root = pc->root;
            cc->tgid = child_pid;
            cc->tid = child->pid;
            cc->depth = is_thread ? pc->depth : pc->depth + 1;
            log_info("proc_fork: tid=%u pid=%u root=%u depth=%u inherited task ctx from tid=%u",
                      cc->tid, cc->tgid, cc->root.id, cc->depth, parent->pid);
        } else {
            log_warn("proc_fork: tid=%u pid=%u no task ctx: storage alloc failed",
                     child->pid, child_pid);
        }
    }

    // A new thread shares the tgid, which is already in the map.
    if (is_thread)
        return 0;

    if (!bpf_map_lookup_elem(&tracked_pids, &parent_pid))
        return 0;

    u8 val = 1;
    long err = bpf_map_update_elem(&tracked_pids, &child_pid, &val, BPF_ANY);
    if (err < 0) {
        log_warn("proc_fork: pid=%u parent=%u not tracked: map full", child_pid, parent_pid);
        return 0;
    }

    log_debug("proc_fork: pid=%u inherited tracking from parent=%u", child_pid, parent_pid);
    return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(mon_proc_exec, struct task_struct *task, pid_t old_pid,
             struct linux_binprm *bprm)
{
    task_ctx_t *tc = bpf_task_storage_get(&task_ctx_map, task, NULL, 0);
    if (!tc)
        return 0;

    // Update the task context with the new identity. The root and depth are unchanged.
    tc->tgid = task->tgid;
    tc->tid = task->pid;

    log_info("proc_exec: pid=%u old_tid=%d root=%u depth=%u %s",
             tc->tgid, old_pid, tc->root.id, tc->depth, task->comm);
    return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(mon_proc_exit, struct task_struct *task, bool group_dead)
{
    // The kernel frees task storage with the task_struct, but a zombie keeps
    // its task_struct until reaped. Drop the context now so an unreaped
    // child cannot serve as a fast-path parent in resolve_ancestor, and so
    // memory is not held hostage by a parent that never wait()s.
    if (bpf_task_storage_delete(&task_ctx_map, task) == 0)
        log_info("proc_exit: tid=%u pid=%u task ctx removed %s", task->pid, task->tgid, task->comm);

    if (!group_dead)
        return 0;

    u32 pid = task->tgid;

    if (bpf_map_delete_elem(&tracked_pids, &pid) == 0)
        log_debug("proc_exit: pid=%u removed from tracked_pids", pid);

    return 0;
}

extern struct task_struct *bpf_task_from_pid(s32 pid) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;

SEC("syscall")
int mon_track_pid(struct mon_track_req *req)
{
    if (!req)
        return -22; // -EINVAL

    u32 pid = req->pid;
    struct task_struct *task = bpf_task_from_pid((s32)pid);
    if (!task)
        return -3; // -ESRCH

    pid_t task_pid = BPF_CORE_READ(task, pid);
    pid_t task_tgid = BPF_CORE_READ(task, tgid);
    if (task_pid != task_tgid) {
        bpf_task_release(task);
        return -22; // -EINVAL, tid given
    }

    u8 val = 1;
    long err = bpf_map_update_elem(&tracked_pids, &pid, &val, BPF_ANY);
    if (err < 0) {
        bpf_task_release(task);
        return (int)err;
    }

    // Check liveness only *after* the insert, so it cannot race with the
    // exit path. On the exiting side the last thread decrements
    // signal->live and later reaches trace_sched_process_exit, where
    // mon_proc_exit deletes the entry. Both map ops take the same bucket
    // lock, so whichever lands first: if their delete came first, the
    // decrement is visible to the read below and we undo our insert; if our
    // insert came first, their delete removes it. A check-before-insert
    // would leave a window where a dead PID stays tracked until the kernel
    // reuses it for an unrelated process.
    //
    // signal->live rather than PF_EXITING: a group leader that called
    // pthread_exit() carries PF_EXITING while its other threads are still
    // running, and that group is perfectly trackable.
    int live = BPF_CORE_READ(task, signal, live.counter);
    bpf_task_release(task);
    if (live <= 0) {
        bpf_map_delete_elem(&tracked_pids, &pid);
        return -3; // -ESRCH
    }

    log_info("track_pid: pid=%u added to tracked_pids", pid);
    return 0;
}

SEC("syscall")
int mon_untrack_pid(struct mon_track_req *req)
{
    if (!req)
        return -22; // -EINVAL

    u32 pid = req->pid;
    long err = bpf_map_delete_elem(&tracked_pids, &pid);
    if (err < 0)
        return (int)err;

    log_info("untrack_pid: pid=%u removed from tracked_pids", pid);
    return 0;
}

SEC("iter/task")
int mon_iter_task(struct bpf_iter__task *ctx)
{
    struct seq_file *seq = ctx->meta->seq;
    struct task_struct *t = ctx->task;

    if (!t)
        return 0;

    if (ctx->meta->seq_num == 0)
        BPF_SEQ_PRINTF(seq, "%5s %5s %5s %s\n", "PID", "PPID", "DEPTH", "COMM");

    // Processes only: skip every task that is not its thread group leader.
    if (t->pid != t->tgid)
        return 0;

    u32 root_pid = mon_iter_root_pid;
    root_id_t root;

    int depth = resolve_ancestor(t, root_pid, &root);
    if (depth < 0)
        return 0;
    
    task_ctx_t *tc = bpf_task_storage_get(&task_ctx_map, t, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!tc)
        return 0;

    tc->root = root;
    tc->tgid = t->tgid;
    tc->tid = t->pid;
    tc->depth = depth;

    BPF_SEQ_PRINTF(seq, "%5d %5d %5u %s\n",
            t->tgid, BPF_CORE_READ(t, real_parent, tgid), tc->depth, t->comm);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";


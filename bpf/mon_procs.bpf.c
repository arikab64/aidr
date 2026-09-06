#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "logger.h"
#include "mon.bpf.h"

// Children of a tracked process are tracked too, so registering e.g. a shell
// script also covers the find/dd/md5sum it forks. This fires inside
// copy_process before the child ever runs, so the child cannot exit (and
// have mon_proc_exit miss it) before the entry is in place.
SEC("tp_btf/sched_process_fork")
int BPF_PROG(mon_proc_fork, struct task_struct *parent, struct task_struct *child)
{
    u32 parent_pid = BPF_CORE_READ(parent, tgid);
    u32 child_pid = BPF_CORE_READ(child, tgid);

    // A new thread shares the tgid, which is already in the map.
    if (child_pid == parent_pid)
        return 0;

    if (!bpf_map_lookup_elem(&tracked_pids, &parent_pid))
        return 0;

    u8 val = 1;
    long err = bpf_map_update_elem(&tracked_pids, &child_pid, &val, BPF_ANY);
    if (err < 0) {
        log_warn("proc_fork: pid=%u parent=%u not tracked: map full", child_pid, parent_pid);
        return 0;
    }

    log_info("proc_fork: pid=%u inherited tracking from parent=%u", child_pid, parent_pid);
    return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(mon_proc_exit, struct task_struct *task, bool group_dead)
{
    if (!group_dead)
        return 0;

    u32 pid = BPF_CORE_READ(task, tgid);

    if (bpf_map_delete_elem(&tracked_pids, &pid) == 0) 
        log_info("proc_exit: pid=%u removed from tracked_pids", pid);

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

char LICENSE[] SEC("license") = "GPL";


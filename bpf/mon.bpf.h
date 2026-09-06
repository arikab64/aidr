#ifndef MON_BPF_H
#define MON_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct mon_track_req {
    u32 pid;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u8);
} tracked_pids SEC(".maps");

#endif // MON_BPF_H

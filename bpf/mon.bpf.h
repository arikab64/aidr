#ifndef MON_BPF_H
#define MON_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct root_id {
    u32 id;
    u64 starttime;
} root_id_t;

typedef struct task_ctx {
    root_id_t root;
    u32 tgid;
    u32 tid;
    u32 depth;
} task_ctx_t;


struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, u32);
    __type(value, task_ctx_t);
} task_ctx_map SEC(".maps");

#endif // MON_BPF_H

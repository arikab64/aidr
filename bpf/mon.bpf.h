#ifndef MON_BPF_H
#define MON_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

typedef struct task_ctx {
    u64 workload_id;
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

// Address families are #defines in the kernel, so BTF does not carry them.
#ifndef AF_INET
#define AF_INET  2
#define AF_INET6 10
#endif

// The 5-tuple of a socket, in host byte order, for both address families.
// ipv4 says which half of the address unions is live. sport is -1 until the
// kernel has assigned a local port (bind, connect, or accept); a socket
// fresh from socket(2) has none yet.
typedef struct sock_tuple {
    bool ipv4;       // true: saddr.v4/daddr.v4; false: saddr.v6/daddr.v6
    u8   proto;      // IPPROTO_*
    s32  sport;      // local port, -1 = not assigned
    u16  dport;      // peer port, 0 when not connected
    union {
        u32 v4;
        struct in6_addr v6;
    } saddr, daddr;
} sock_tuple_t;

#endif // MON_BPF_H

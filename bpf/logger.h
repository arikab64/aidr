#ifndef MON_BPF_LOG_H
#define MON_BPF_LOG_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

enum mon_log_level {
    MON_LOG_DEBUG = 0,
    MON_LOG_INFO  = 1,
    MON_LOG_WARN  = 2,
    MON_LOG_ERROR = 3,
    MON_LOG_NONE  = 4,
};

// Set from userspace between open and load (rodata is frozen at load time),
// so the verifier sees the final value and removes disabled log calls as
// dead code.
const volatile u32 mon_log_level = MON_LOG_INFO;

// For guarding work only needed when a level is live, e.g.
// if (log_enabled(DEBUG)). Dead-code-eliminated like the log calls.
#define log_enabled(lvl) (MON_LOG_##lvl >= mon_log_level)

#define mon_log(lvl, tag, fmt, ...)                                     \
    do {                                                                \
        if ((lvl) >= mon_log_level)                                     \
            bpf_printk(tag " " fmt , ##__VA_ARGS__);                \
    } while (0)

#define log_debug(fmt, ...) mon_log(MON_LOG_DEBUG, "DBG", fmt, ##__VA_ARGS__)
#define log_info(fmt, ...)  mon_log(MON_LOG_INFO,  "INF", fmt, ##__VA_ARGS__)
#define log_warn(fmt, ...)  mon_log(MON_LOG_WARN,  "WRN", fmt, ##__VA_ARGS__)
#define log_error(fmt, ...) mon_log(MON_LOG_ERROR, "ERR", fmt, ##__VA_ARGS__)

#endif /* MON_BPF_LOG_H */

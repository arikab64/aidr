#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "logger.h"
#include "mon.bpf.h"

// AIDR_TEST_FENTRY: attach to the security_* functions with fentry instead
// of BPF-LSM. Same body, same verifier path (bpf_d_path allowlists
// security_file_open), but return values are ignored — record-only. For
// kernels without lsm=bpf, or CI verifier runs. Build with:
// cmake -DAIDR_TEST_FENTRY=ON ..
#ifdef AIDR_TEST_FENTRY
#define AIDR_SEC_FILE_OPEN    "fentry/security_file_open"
#define AIDR_SEC_INODE_UNLINK "fentry/security_inode_unlink"
#define AIDR_RET(x)           ((void)(x), 0)   // fentry must return 0 
#else
#define AIDR_SEC_FILE_OPEN    "lsm/file_open"
#define AIDR_SEC_INODE_UNLINK "lsm/inode_unlink"
#define AIDR_RET(x)           (x)
#endif

// Stack is capped at 512 bytes, so this is well short of PATH_MAX. Longer
// paths make bpf_d_path fail with -ENAMETOOLONG rather than truncate.
#define AIDR_PATH_MAX 256

SEC(AIDR_SEC_FILE_OPEN)
int BPF_PROG(mon_files_open, struct file *file)
{
    char path[AIDR_PATH_MAX];

    // Upper 32 bits are the tgid, i.e. the PID as userspace knows it; the
    // lower half is the kernel task id (what userspace calls the thread id).
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (!bpf_map_lookup_elem(&tracked_pids, &pid))
        return AIDR_RET(0);

    // bpf_d_path only accepts a trusted struct path *; &file->f_path from an
    // LSM/fentry argument qualifies. It NUL-terminates on success.
    long len = bpf_d_path(&file->f_path, path, sizeof(path));

    if (len < 0)
        log_info("file_open: pid=%u <d_path failed: %ld>", pid, len);
    else
        log_info("file_open: pid=%u %s", pid, path);

    return AIDR_RET(0);
}

// Required: BPF-LSM (and the bpf_d_path helper) reject non-GPL programs.
char LICENSE[] SEC("license") = "GPL";

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
// mmap_file is not listed: its security_* function and LSM hook take
// different arguments, so it has its own #ifdef at the program.
#ifdef AIDR_TEST_FENTRY
#define AIDR_SEC_FILE_OPEN       "fentry/security_file_open"
#define AIDR_SEC_FILE_PERMISSION "fentry/security_file_permission"
#define AIDR_SEC_FILE_TRUNCATE   "fentry/security_file_truncate"
#define AIDR_SEC_FILE_FREE       "fentry/security_file_free"
#define AIDR_SEC_PATH_UNLINK     "fentry/security_path_unlink"
#define AIDR_SEC_PATH_RMDIR      "fentry/security_path_rmdir"
#define AIDR_SEC_PATH_RENAME     "fentry/security_path_rename"
#define AIDR_RET(x)              ((void)(x), 0)   // fentry must return 0
#else
#define AIDR_SEC_FILE_OPEN       "lsm/file_open"
#define AIDR_SEC_FILE_PERMISSION "lsm/file_permission"
#define AIDR_SEC_FILE_TRUNCATE   "lsm/file_truncate"
#define AIDR_SEC_FILE_FREE       "lsm/file_free_security"
#define AIDR_SEC_PATH_UNLINK     "lsm/path_unlink"
#define AIDR_SEC_PATH_RMDIR      "lsm/path_rmdir"
#define AIDR_SEC_PATH_RENAME     "lsm/path_rename"
#define AIDR_RET(x)              (x)
#endif

// Stack is capped at 512 bytes, so this is well short of PATH_MAX. Longer
// paths make bpf_d_path fail with -ENAMETOOLONG rather than truncate.
#define AIDR_PATH_MAX 256

// The extension is a '.' within the last 10 characters: at most 10 bytes
// plus the NUL.
#define AIDR_EXT_MAX 12

// Mount-crossing parent walk for removals; deeper paths stop counting here.
#define AIDR_WALK_MAX 32

// From include/linux/fs.h and the uapi headers; vmlinux.h carries types,
// not #defines.
#define FMODE_WRITE     0x2
#define FMODE_CREATED   0x100000
#define MAY_WRITE       0x2
#define MAY_READ        0x4
#define PROT_READ       0x1
#define PROT_WRITE      0x2
#define MAP_SHARED      0x01
#define RENAME_EXCHANGE 0x2
#define S_IFMT          0170000
#define S_IFDIR         0040000

// The codon verbs (arch/aidr-file-genome-design.md §1):
//   C  file_open, when the open created the file (FMODE_CREATED)
//   R  file_permission / mmap_file, the first actual read of an open file
//   W  file_permission / mmap_file / file_truncate, the first actual write
//   D  path_unlink, path_rmdir, or a rename that replaces an existing file
// R and W come from real I/O, not the open mode: plenty of O_RDWR opens
// never write. file_open only resolves the path and parks it in open_files;
// the verb is logged when the file is actually used.
#define AIDR_SEEN_R 0x1
#define AIDR_SEEN_W 0x2

// The codon's root field (arch/aidr-file-genome-design.md §1), from the
// path's first component:
//   HOME   /home, /root
//   ETC    /etc
//   VAR    /var, /run (the old /var/run)
//   TMP    /tmp
//   PROC   /proc
//   SYS    /sys
//   USR    /usr, and /bin, /sbin, /lib, /lib64 (merged-/usr links)
//   MNT    /mnt, /media
//   OTHER  everything else: /dev, /opt, /srv, /boot...
// WS, the agent's workspace, is per identity and can't be told from the
// path alone: it is learned from the first read of <dir>/.git/HEAD (see
// ws_learn), and from then on paths under <dir> are WS, with depth counted
// below <dir>. D codons carry only the leaf name, so they never read as WS.
// OTHER is 0 so a zeroed value reads as OTHER.
enum aidr_root {
    AIDR_ROOT_OTHER = 0,
    AIDR_ROOT_WS,
    AIDR_ROOT_HOME,
    AIDR_ROOT_ETC,
    AIDR_ROOT_VAR,
    AIDR_ROOT_TMP,
    AIDR_ROOT_PROC,
    AIDR_ROOT_SYS,
    AIDR_ROOT_USR,
    AIDR_ROOT_MNT,
};

// The codon's nameclass field (§1), from the extension. A coarse bias term,
// not a security control: renaming .env to notes.txt defeats it (§11).
// OTHER is 0 so a zeroed value reads as OTHER.
enum aidr_nameclass {
    AIDR_NC_OTHER = 0,
    AIDR_NC_SRC,
    AIDR_NC_CFG,
    AIDR_NC_ENV,
    AIDR_NC_DB,
    AIDR_NC_BIN,
    AIDR_NC_MEDIA,
};

typedef struct file_info {
    char path[AIDR_PATH_MAX];
    char ext[AIDR_EXT_MAX] __attribute__((aligned(8)));   // read as words
    u32  depth;
    u8   root;      // enum aidr_root
    u8   nameclass; // enum aidr_nameclass
    u8   seen;      // AIDR_SEEN_*: verbs already logged for this open file
} file_info_t;

// Open files of tracked tasks, keyed by struct file pointer. Entries are
// removed in file_free; LRU keeps a missed free from filling the map.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, u64);
    __type(value, file_info_t);
} open_files SEC(".maps");

// file_info_t does not fit on the stack; file_open builds it here.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, file_info_t);
} file_info_scratch SEC(".maps");

// The workspace root of an identity, with its trailing '/' so a prefix
// match can't take /repo2 for /repo.
typedef struct ws_root {
    char path[AIDR_PATH_MAX];
    u32  len;     // bytes of path, the '/' included; 0 while being set
    u32  depth;   // components in path
} ws_root_t;

// Keyed by workload_id: git runs as a child of the agent, so the workspace
// found by one task holds for the whole identity. Set once, never moved.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, ws_root_t);
} ws_roots SEC(".maps");

// Zeroed value to create ws_roots entries from; too big for the stack.
static const ws_root_t ws_zero;

// The current task's context, NULL for untracked tasks.
// bpf_task_storage_get needs a BTF-typed task pointer;
// bpf_get_current_task() returns a plain scalar the verifier rejects, so
// use the _btf variant.
static __always_inline task_ctx_t *task_ctx(void)
{
    struct task_struct *task = bpf_get_current_task_btf();

    return bpf_task_storage_get(&task_ctx_map, task, NULL, 0);
}

// Skip untracked tasks.
static __always_inline bool task_tracked(void)
{
    return task_ctx() != NULL;
}

// True when the first n bytes of s and p match. n is a constant at every
// call site, so the verifier sees only constant offsets.
static __always_inline bool bytes_eq(const char *s, const char *p, int n)
{
#pragma unroll
    for (int i = 0; i < n; i++)
        if (s[i] != p[i])
            return false;
    return true;
}

// s starts with the string literal lit.
#define has_prefix(s, lit) bytes_eq(s, lit, sizeof(lit) - 1)

// The first n (<= 8) bytes of a string literal as a little-endian word.
// Always called with literals, so clang folds it to a constant.
static __always_inline u64 lit_word(const char *s, int n)
{
    u64 w = 0;

#pragma unroll
    for (int i = 0; i < 8; i++)
        if (i < n)
            w |= (u64)(u8)s[i] << (8 * i);
    return w;
}

// Match the first n (<= 24) bytes of lit against w, a string loaded as
// words: one masked compare per 8 bytes instead of one per byte.
static __always_inline bool words_match(const u64 *w, const char *lit, int n)
{
#pragma unroll
    for (int i = 0; i < 3; i++) {
        int k = n - 8 * i;

        if (k <= 0)
            break;
        u64 mask = k >= 8 ? ~0ULL : (1ULL << (8 * k)) - 1;
        if ((w[i] & mask) != lit_word(lit + 8 * i, k >= 8 ? 8 : k))
            return false;
    }
    return true;
}

// w starts with lit / w is exactly lit (the compare includes its NUL).
#define w_prefix(w, lit) words_match(w, lit, sizeof(lit) - 1)
#define w_eq(w, lit)     words_match(w, lit, sizeof(lit))

// Two or four characters as the integer the first bytes of a word load as,
// for case labels (which need a constant expression, so no string literal).
#define C2(a, b)       ((u16)(a) | (u16)(b) << 8)
#define C4(a, b, c, d) ((u32)(a) | (u32)(b) << 8 | (u32)(c) << 16 | (u32)(d) << 24)

// x holds a path component as a word: is it exactly lit (<= 7 chars)?
// The byte after it must end the component, as '/' in a path or NUL in a
// dentry name, so /homework is not /home.
static __always_inline bool name_is(u64 x, const char *lit, int k)
{
    u64 mask = (1ULL << (8 * k)) - 1;
    u8 end = x >> (8 * k);

    return (x & mask) == lit_word(lit, k) && (end == '/' || end == '\0');
}

#define ROOT_IF(x, lit, root) \
    return name_is(x, lit, sizeof(lit) - 1) ? (root) : AIDR_ROOT_OTHER

// enum aidr_root of a first path component, given as a word (see name_is).
// Switches on the first two letters, which are distinct for every name.
static __always_inline u8 root_of(u64 x)
{
    switch ((u16)x) {
    case C2('h', 'o'): ROOT_IF(x, "home",  AIDR_ROOT_HOME);
    case C2('r', 'o'): ROOT_IF(x, "root",  AIDR_ROOT_HOME);
    case C2('e', 't'): ROOT_IF(x, "etc",   AIDR_ROOT_ETC);
    case C2('v', 'a'): ROOT_IF(x, "var",   AIDR_ROOT_VAR);
    case C2('r', 'u'): ROOT_IF(x, "run",   AIDR_ROOT_VAR);
    case C2('t', 'm'): ROOT_IF(x, "tmp",   AIDR_ROOT_TMP);
    case C2('p', 'r'): ROOT_IF(x, "proc",  AIDR_ROOT_PROC);
    case C2('s', 'y'): ROOT_IF(x, "sys",   AIDR_ROOT_SYS);
    case C2('u', 's'): ROOT_IF(x, "usr",   AIDR_ROOT_USR);
    case C2('b', 'i'): ROOT_IF(x, "bin",   AIDR_ROOT_USR);
    case C2('s', 'b'): ROOT_IF(x, "sbin",  AIDR_ROOT_USR);
    case C2('m', 'n'): ROOT_IF(x, "mnt",   AIDR_ROOT_MNT);
    case C2('m', 'e'): ROOT_IF(x, "media", AIDR_ROOT_MNT);
    case C2('l', 'i'):
        if (name_is(x, "lib", 3) || name_is(x, "lib64", 5))
            return AIDR_ROOT_USR;
        break;
    }
    return AIDR_ROOT_OTHER;
}

// Extension (without its dot, lowercase, NUL-padded) → enum aidr_nameclass.
// Empty here: the daemon fills it between open and load, from
// ext_classes.json (mon/src/bpf.rs), and it is frozen with the rest of
// .rodata. nameclass_of binary-searches the first ext_classes_n entries, so
// the daemon sorts them bytewise: "c" before "cc" before "cfg".
#define AIDR_EXT_CLASSES_MAX 512

struct ext_class {
    char ext[8] __attribute__((aligned(8)));   // read as a word
    u8   nc;
};

const volatile struct ext_class ext_classes[AIDR_EXT_CLASSES_MAX] = {};
const volatile u32 ext_classes_n = 0;

// Binary search of ext_classes for key, an extension as a big-endian word,
// whose order is the bytewise order the table is sorted in.
// Written for the verifier, which walks every branch it can't rule out:
// - Global and __noinline, so it is verified once, on its own, with key
//   unknown, not again for every path of each caller.
// - No branch on the comparison. key and k are both unknown to the
//   verifier, which then can't carry what one compare learned to the next:
//   a branching search let it explore impossible paths on which the range
//   never narrowed, and ran mon_files_open past the 1M instruction limit.
//   Here each round is straight-line code, so there is one path through
//   the loop and a single branch at the end.
__noinline int ext_class_find(u64 key)
{
    u32 n = ext_classes_n;
    u32 base = 0;

    if (n == 0 || n > AIDR_EXT_CLASSES_MAX)
        return AIDR_NC_OTHER;

    // Lower bound: keep base at the last entry <= key. Each round halves n;
    // 10 rounds take 512 entries down to 1.
    for (int i = 0; i < 10; i++) {
        u32 half = n / 2;
        u64 k = __builtin_bswap64(
            *(const volatile u64 *)ext_classes[(base + half) & (AIDR_EXT_CLASSES_MAX - 1)].ext);
        // key < k is the borrow out of key - k (Hacker's Delight 2-13);
        // barrier_var keeps clang from turning it back into a compare.
        u64 lt = ((~key & k) | (~(key ^ k) & (key - k))) >> 63;

        barrier_var(lt);
        base += half & ((u32)lt - 1);   // += half when key >= k
        n -= half;
    }

    base &= AIDR_EXT_CLASSES_MAX - 1;
    if (__builtin_bswap64(*(const volatile u64 *)ext_classes[base].ext) != key)
        return AIDR_NC_OTHER;
    return ext_classes[base].nc;
}

// enum aidr_nameclass of an extension as path_scan stores it: a '.' then
// up to 10 characters, NUL-terminated, in an 8-byte aligned buffer of at
// least 16 bytes. Bytes after the NUL may be stale, so they are masked off.
static __always_inline u8 nameclass_of(const char *ext)
{
    const u64 *e = (const u64 *)ext;

    if (ext[0] != '.')
        return AIDR_NC_OTHER;

    u64 x = e[0] >> 8 | e[1] << 56;   // the 8 bytes after the dot
    u64 mask = 0;

#pragma unroll
    for (int i = 0; i < 8; i++) {
        if (!(u8)(x >> (8 * i)))
            break;
        mask |= 0xffULL << (8 * i);
    }
    // Empty, or longer than 8 characters: not in the table.
    if (!mask || (mask == ~0ULL && ext[9] != '\0'))
        return AIDR_NC_OTHER;

    // OR-ing 0x20 lowercases letters and leaves digits alone.
    return ext_class_find(__builtin_bswap64((x | 0x2020202020202020ULL) & mask));
}

// The nameclass's name as a NUL-padded word, for %s in the log.
static __always_inline u64 nameclass_word(u8 nc)
{
    switch (nc) {
    case AIDR_NC_SRC:   return lit_word("SRC", 3);
    case AIDR_NC_CFG:   return lit_word("CFG", 3);
    case AIDR_NC_ENV:   return lit_word("ENV", 3);
    case AIDR_NC_DB:    return lit_word("DB", 2);
    case AIDR_NC_BIN:   return lit_word("BIN", 3);
    case AIDR_NC_MEDIA: return lit_word("MEDIA", 5);
    }
    return lit_word("OTHER", 5);
}

// The root's name as a NUL-padded word, for %s in the log.
static __always_inline u64 root_word(u8 root)
{
    switch (root) {
    case AIDR_ROOT_WS:   return lit_word("WS", 2);
    case AIDR_ROOT_HOME: return lit_word("HOME", 4);
    case AIDR_ROOT_ETC:  return lit_word("ETC", 3);
    case AIDR_ROOT_VAR:  return lit_word("VAR", 3);
    case AIDR_ROOT_TMP:  return lit_word("TMP", 3);
    case AIDR_ROOT_PROC: return lit_word("PROC", 4);
    case AIDR_ROOT_SYS:  return lit_word("SYS", 3);
    case AIDR_ROOT_USR:  return lit_word("USR", 3);
    case AIDR_ROOT_MNT:  return lit_word("MNT", 3);
    }
    return lit_word("OTHER", 5);
}

// /home/<user>/.cache/. The user name varies in length, so look for the
// '/' after it; k is the loop counter, an exact offset each time round, so
// the verifier needs no bounds work.
static __always_inline bool in_home_cache(const char *p)
{
    for (int k = 6; k < 64; k++) {
        if (p[k] == '/')
            return has_prefix(&p[k], "/.cache/");
        if (p[k] == '\0')
            return false;
    }
    return false;
}

// What to keep out of the log, as AIDR_SEEN_* bits preset on the open file.
// The point is meaningful codons: routine opens, above all ones spread over
// many distinct directories (/proc/<pid>, /dev/pts/N, random temp dirs),
// would use up the expressed-genes budget and flip a normal agent to
// aneuploid (arch/aidr-file-genome-design.md §5). So they are dropped, not
// counted.
//   R and W (and C): device sinks, terminals, per-user caches.
//   R only: the loader and shared libraries, binaries read at exec, /proc,
//           /sys/devices, mktemp and tempfile directories, /run/user. A
//           write there still matters (library tampering, staging in /tmp,
//           changing device settings).
// /proc/<pid>/environ and mem stay loud: another process's environ is a
// lethal gene (§4). D follows W, see remove_quiet.
// Runs on every open by a tracked task, so it compares 8 bytes at a time and
// switches on the first 4 bytes to test only that top directory's rules.
// w is the first 24 bytes of fi->path as words. Reading 24 bytes of a
// shorter path is safe: path is a 256-byte buffer, and a compare never
// matches across the path's NUL.
static __always_inline u8 quiet_mask(struct file *file, const file_info_t *fi,
                                     const u64 *w)
{
    switch ((u32)w[0]) {
    case C4('/', 'd', 'e', 'v'):
        if (w_eq(w, "/dev/null") || w_eq(w, "/dev/zero") || w_eq(w, "/dev/full") ||
            w_eq(w, "/dev/random") || w_eq(w, "/dev/urandom") || w_eq(w, "/dev/ptmx") ||
            w_prefix(w, "/dev/pts/") || w_prefix(w, "/dev/tty"))
            return AIDR_SEEN_R | AIDR_SEEN_W;
        break;
    case C4('/', 'h', 'o', 'm'):
        if (w_prefix(w, "/home/") && in_home_cache(fi->path))
            return AIDR_SEEN_R | AIDR_SEEN_W;
        break;
    case C4('/', 'r', 'o', 'o'):
        if (w_prefix(w, "/root/.cache/"))
            return AIDR_SEEN_R | AIDR_SEEN_W;
        break;
    case C4('/', 'u', 's', 'r'):
        if (w_prefix(w, "/usr/lib/") || w_prefix(w, "/usr/lib64/") ||
            w_prefix(w, "/usr/bin/") || w_prefix(w, "/usr/sbin/"))
            return AIDR_SEEN_R;
        break;
    case C4('/', 'l', 'i', 'b'):
        if (w_prefix(w, "/lib/") || w_prefix(w, "/lib64/"))
            return AIDR_SEEN_R;
        break;
    case C4('/', 'b', 'i', 'n'):
        if (w_prefix(w, "/bin/"))
            return AIDR_SEEN_R;
        break;
    case C4('/', 's', 'b', 'i'):
        if (w_prefix(w, "/sbin/"))
            return AIDR_SEEN_R;
        break;
    case C4('/', 'e', 't', 'c'):
        if (w_eq(w, "/etc/ld.so.cache"))
            return AIDR_SEEN_R;
        break;
    case C4('/', 't', 'm', 'p'):
        // mktemp's tmp.XXXXXXXXXX, Python's tmpXXXXXXXX.
        if (w_prefix(w, "/tmp/tmp"))
            return AIDR_SEEN_R;
        break;
    case C4('/', 'r', 'u', 'n'):
        if (w_prefix(w, "/run/user/"))
            return AIDR_SEEN_R;
        break;
    case C4('/', 's', 'y', 's'):
        if (w_prefix(w, "/sys/devices/"))
            return AIDR_SEEN_R;
        break;
    case C4('/', 'p', 'r', 'o'):
        if (w_prefix(w, "/proc/")) {
            u64 name[2];

            bpf_probe_read_kernel_str(name, sizeof(name),
                                      BPF_CORE_READ(file, f_path.dentry, d_name.name));
            if (!w_eq(name, "environ") && !w_eq(name, "mem"))
                return AIDR_SEEN_R;
        }
        break;
    }
    return 0;
}

// Walk buf backwards once, from its last character down to index lo, and
// return the number of '/' separators seen. ext receives the extension: the
// first '.' within the last 10 characters before any '/'. Copying it on the
// spot, rather than saving the dot's index, keeps the verifier from tracking
// every possible index separately.
// len is a bpf_d_path or bpf_probe_read_kernel_str result: it counts the
// trailing NUL, so the last character is at len - 2. Callers bound it to
// (1, AIDR_PATH_MAX].
static __always_inline u32 path_scan(const char *buf, long len, u32 lo, char *ext)
{
    u32 slashes = 0;
    bool want_ext = true;

    ext[0] = '\0';
    for (int n = 0; n < AIDR_PATH_MAX; n++) {
        // Past the start of buf, j wraps to a huge u32 and ends the loop.
        u32 j = len - 2 - n;

        // Clang can prove j < AIDR_PATH_MAX from the len check and would
        // drop this bound, but the verifier can't follow that proof.
        barrier_var(j);
        if (j >= AIDR_PATH_MAX)
            break;

        if (buf[j] == '/') {
            slashes++;
            want_ext = false;   // any earlier '.' is in a directory name
        } else if (want_ext && buf[j] == '.') {
            bpf_probe_read_kernel_str(ext, AIDR_EXT_MAX, &buf[j]);
            want_ext = false;
        }

        if (n == 9)
            want_ext = false;

        // Checked here rather than next to the bound check: clang merged
        // the two and then read buf[j] through a register the verifier
        // had no bounds for.
        if (j <= lo)
            break;
    }
    return slashes;
}

// If fi is <dir>/.git/HEAD, make <dir> the workspace of identity id and
// return its entry. git reads HEAD in whatever repo it works on, so this is
// the repo the agent works in. The agent picks which repo that is, so the
// guards keep it from naming a region that would launder the rest of its
// codons into WS (arch/aidr-file-genome-design.md §8): no system roots
// (/etc is often a repo, via etckeeper), nothing shallower than /x/y, and
// never a whole home directory (a dotfiles repo in ~). The first repo wins.
// len is fi->path's bpf_d_path length, w its first 24 bytes as words.
static __always_inline ws_root_t *ws_learn(u64 id, const file_info_t *fi,
                                           long len, const u64 *w)
{
    // The '/' of "/.git/HEAD"; len counts the NUL.
    u32 off = len - 11;

    barrier_var(off);
    if (off >= AIDR_PATH_MAX - 10 || !bytes_eq(&fi->path[off], "/.git/HEAD", 10))
        return NULL;

    // <dir> has fi->depth - 2 components.
    if (fi->depth < 4 || (w_prefix(w, "/home/") && fi->depth < 5))
        return NULL;
    switch (fi->root) {
    case AIDR_ROOT_HOME:
    case AIDR_ROOT_MNT:
    case AIDR_ROOT_TMP:
    case AIDR_ROOT_OTHER:
        break;
    default:
        return NULL;
    }

    // Fails when another CPU got there first: that one fills the entry.
    if (bpf_map_update_elem(&ws_roots, &id, &ws_zero, BPF_NOEXIST))
        return NULL;
    ws_root_t *ws = bpf_map_lookup_elem(&ws_roots, &id);
    if (!ws)
        return NULL;

    // off < AIDR_PATH_MAX - 10 was checked above, but clang recomputes
    // off + 1 from a register the verifier only knows as signed. The mask
    // gives it the bound again; barrier_var keeps clang, which can prove
    // the mask a no-op, from dropping it.
    u32 n = off + 1;

    barrier_var(n);
    n &= AIDR_PATH_MAX - 1;
    bpf_probe_read_kernel(ws->path, n, fi->path);
    ws->depth = fi->depth - 2;
    ws->len = off + 1;   // last: a reader seeing len sees the path
    log_info("file: workload=%llu ws=%s", id, ws->path);
    return ws;
}

// path starts with the workspace root: ws->len bytes, compared a word at a
// time. Both buffers are AIDR_PATH_MAX long and 8-byte aligned.
static __always_inline bool in_ws(const char *path, const ws_root_t *ws)
{
    const u64 *a = (const u64 *)path, *b = (const u64 *)ws->path;
    u32 n = ws->len;

    if (n == 0 || n > AIDR_PATH_MAX)
        return false;
    for (int i = 0; i < AIDR_PATH_MAX / 8; i++) {
        int k = n - 8 * i;

        if (k <= 0)
            break;
        u64 mask = k >= 8 ? ~0ULL : (1ULL << (8 * k)) - 1;
        if ((a[i] ^ b[i]) & mask)
            return false;
    }
    return true;
}

// Reclassify fi as WS, with depth below the workspace root, when it lies in
// identity id's workspace; learn the workspace first if there is none yet.
static __always_inline void ws_apply(u64 id, file_info_t *fi, long len, const u64 *w)
{
    ws_root_t *ws = bpf_map_lookup_elem(&ws_roots, &id);

    if (!ws)
        ws = ws_learn(id, fi, len, w);
    if (!ws || !in_ws(fi->path, ws))
        return;
    fi->root = AIDR_ROOT_WS;
    fi->depth -= ws->depth;
}

static __always_inline void log_file(u32 pid, char verb, const file_info_t *fi)
{
    u64 root = root_word(fi->root);
    u64 nc = nameclass_word(fi->nameclass);

    log_info("file: pid=%u verb=%c root=%s depth=%u nameclass=%s ext=%s path=%s",
             pid, verb, &root, fi->depth, &nc, fi->ext, fi->path);
}

// Log verb for file the first time it happens to this open file. bit is the
// verb's AIDR_SEEN_* bit; covers marks other verbs this operation stands in
// for, so they are not logged for it later. Two CPUs racing on the same file
// can at worst log it twice.
static __always_inline void note_access(struct file *file, u8 bit, u8 covers, char verb)
{
    u64 key = (u64)file;
    file_info_t *fi = bpf_map_lookup_elem(&open_files, &key);

    if (!fi || (fi->seen & bit))
        return;
    fi->seen |= bit | covers;
    log_file(bpf_get_current_pid_tgid() >> 32, verb, fi);
}

// Depth of dentry below the task's root, counted like the '/' in a
// bpf_d_path result. The path_* hooks give no struct path for the dentry
// itself, so walk d_parent up, stepping into the parent mount at each mount
// root, until the task's root (a chroot or container root included).
// top receives the dentries of path levels 1-3 (top[0] is the one right
// under the root); entries stay NULL when the path is shallower, or when the
// walk gave up at AIDR_WALK_MAX before reaching the root.
static __always_inline u32 dentry_depth(const struct path *dir, struct dentry *dentry,
                                        struct dentry *top[3])
{
    struct task_struct *task = bpf_get_current_task_btf();
    struct dentry *root_dentry = BPF_CORE_READ(task, fs, root.dentry);
    struct vfsmount *root_mnt = BPF_CORE_READ(task, fs, root.mnt);
    struct vfsmount *vfsmnt = BPF_CORE_READ(dir, mnt);
    struct mount *mnt = (void *)vfsmnt - bpf_core_field_offset(struct mount, mnt);
    struct dentry *l1 = NULL, *l2 = NULL, *l3 = NULL;
    bool at_root = false;
    u32 depth = 0;

    for (int i = 0; i < AIDR_WALK_MAX; i++) {
        if (dentry == root_dentry && vfsmnt == root_mnt) {
            at_root = true;
            break;
        }

        struct dentry *parent = BPF_CORE_READ(dentry, d_parent);

        if (dentry == BPF_CORE_READ(vfsmnt, mnt_root) || dentry == parent) {
            // Top of this mount: carry on from its mountpoint in the parent.
            struct mount *up = BPF_CORE_READ(mnt, mnt_parent);

            if (up == mnt) {
                at_root = true;   // the namespace root
                break;
            }
            dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
            mnt = up;
            vfsmnt = (void *)up + bpf_core_field_offset(struct mount, mnt);
            continue;
        }

        // The last three components counted before the root are levels 1-3.
        l3 = l2;
        l2 = l1;
        l1 = dentry;
        depth++;
        dentry = parent;
    }

    if (at_root) {
        top[0] = l1;
        top[1] = l2;
        top[2] = l3;
    }
    return depth;
}

// Reads the first 7 characters of a dentry's name, NUL-terminated, as a word
// for w_eq: enough for "home", "root" and ".cache", and a longer name keeps
// a non-NUL byte where those have their NUL, so it can't match.
static __always_inline void dentry_word(u64 *w, struct dentry *dentry)
{
    bpf_probe_read_kernel_str(w, sizeof(*w), BPF_CORE_READ(dentry, d_name.name));
}

// D is a write, so it is dropped where quiet_mask drops W. Of those paths
// only the per-user caches see deletes: /home/<user>/.cache/ and
// /root/.cache/. top holds the dentries of path levels 1-3, l1 the name of
// the first as a word (dentry_word).
static __always_inline bool remove_quiet(struct dentry *top[3], u64 l1)
{
    u64 ln;

    if (w_eq(&l1, "home")) {
        if (!top[2])
            return false;
        dentry_word(&ln, top[2]);
        return w_eq(&ln, ".cache");
    }
    if (w_eq(&l1, "root")) {
        if (!top[1])
            return false;
        dentry_word(&ln, top[1]);
        return w_eq(&ln, ".cache");
    }
    return false;
}

// Log a D for dentry, about to be removed from directory dir. Only the leaf
// name is at hand, so it is logged in place of the full path.
static __always_inline void log_remove(const struct path *dir, struct dentry *dentry)
{
    struct dentry *top[3] = {};
    char name[AIDR_PATH_MAX];
    u64 ext[2] = {};   // nameclass_of reads 16 aligned bytes
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 l1 = 0;

    u32 depth = dentry_depth(dir, dentry, top);
    if (top[0])
        dentry_word(&l1, top[0]);
    if (remove_quiet(top, l1))
        return;

    long len = bpf_probe_read_kernel_str(name, sizeof(name),
                                         BPF_CORE_READ(dentry, d_name.name));
    if (len <= 1 || len > AIDR_PATH_MAX)
        return;

    path_scan(name, len, 0, (char *)ext);

    u64 root = root_word(root_of(l1));
    u64 nc = nameclass_word(nameclass_of((char *)ext));

    log_info("file: pid=%u verb=D root=%s depth=%u nameclass=%s ext=%s name=%s",
             pid, &root, depth, &nc, ext, name);
}

SEC(AIDR_SEC_FILE_OPEN)
int BPF_PROG(mon_files_open, struct file *file)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 zero = 0;

    task_ctx_t *tc = task_ctx();
    if (!tc)
        return AIDR_RET(0);

    // Directory opens are listings (getdents reaches file_permission as
    // MAY_READ), not file reads: never park them, so they never log R.
    // Removing a directory still shows up as D via path_rmdir.
    if ((file->f_inode->i_mode & S_IFMT) == S_IFDIR)
        return AIDR_RET(0);

    file_info_t *fi = bpf_map_lookup_elem(&file_info_scratch, &zero);
    if (!fi)
        return AIDR_RET(0);

    // bpf_d_path only accepts a trusted struct path *; &file->f_path from an
    // LSM/fentry argument qualifies. It NUL-terminates on success.
    long len = bpf_d_path(&file->f_path, fi->path, sizeof(fi->path));

    if (len <= 1 || len > AIDR_PATH_MAX) {
        log_error("file_open: pid=%u <d_path failed: %ld>", pid, len);
        return AIDR_RET(0);
    }
    log_debug("file_open: pid=%u %s", pid, fi->path);

    // path[0] is always '/' and the first folder has at least 3 letters (/usr,
    // /etc, /home...), so path[1..3] never hold a '/': count the leading '/'
    // up front and stop the walk at index 4.
    fi->depth = 1 + path_scan(fi->path, len, 4, fi->ext);

    // The first 24 bytes as words, for the root and the quiet rules. Map
    // values are 8-byte aligned. Bytes 1-8 hold the first component.
    const u64 *p = (const u64 *)fi->path;
    u64 w[3] = { p[0], p[1], p[2] };

    fi->root = root_of(w[0] >> 8 | w[1] << 56);
    fi->nameclass = nameclass_of(fi->ext);
    fi->seen = quiet_mask(file, fi, w);
    ws_apply(tc->workload_id, fi, len, w);

    // A create is the stronger fact than the reads and writes that follow on
    // this open file, so it stands in for them. Where writes are dropped,
    // creates are too.
    if ((file->f_mode & FMODE_CREATED) && !(fi->seen & AIDR_SEEN_W)) {
        log_file(pid, 'C', fi);
        fi->seen = AIDR_SEEN_R | AIDR_SEEN_W;
    }

    u64 key = (u64)file;
    bpf_map_update_elem(&open_files, &key, fi, BPF_ANY);

    return AIDR_RET(0);
}

// Called by rw_verify_area on every read and write: read(2), write(2), their
// p/v variants, io_uring, splice, sendfile and copy_file_range.
SEC(AIDR_SEC_FILE_PERMISSION)
int BPF_PROG(mon_files_permission, struct file *file, int mask)
{
    // The hottest hook here: drop untracked tasks before the hash lookup.
    if (!task_tracked())
        return AIDR_RET(0);

    if (mask & MAY_WRITE)
        note_access(file, AIDR_SEEN_W, 0, 'W');
    else if (mask & MAY_READ)
        note_access(file, AIDR_SEEN_R, 0, 'R');

    return AIDR_RET(0);
}

// Pages of a mapping are read and written without syscalls, so
// file_permission never sees them: the mapping itself counts as the access.
#ifdef AIDR_TEST_FENTRY
SEC("fentry/security_mmap_file")
int BPF_PROG(mon_files_mmap, struct file *file, unsigned long prot,
             unsigned long flags)
#else
SEC("lsm/mmap_file")
int BPF_PROG(mon_files_mmap, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags)
#endif
{
    // Anonymous mappings have no file.
    if (!file || !task_tracked())
        return AIDR_RET(0);

    // A private writable mapping is copy-on-write and never reaches the file.
    // One mmap is one operation, so it yields one codon: W stands in for the
    // read that comes with it, as C does for R and W.
    if ((prot & PROT_WRITE) && (flags & MAP_SHARED) && (file->f_mode & FMODE_WRITE))
        note_access(file, AIDR_SEEN_W, AIDR_SEEN_R, 'W');
    else if (prot & PROT_READ)
        note_access(file, AIDR_SEEN_R, 0, 'R');

    return AIDR_RET(0);
}

// ftruncate(2) and open(O_TRUNC) change the file without a write(2).
SEC(AIDR_SEC_FILE_TRUNCATE)
int BPF_PROG(mon_files_truncate, struct file *file)
{
    if (task_tracked())
        note_access(file, AIDR_SEEN_W, 0, 'W');

    return AIDR_RET(0);
}

SEC(AIDR_SEC_FILE_FREE)
int BPF_PROG(mon_files_free, struct file *file)
{
    // Not gated on task_tracked(): the last fput can run in another task,
    // such as a kworker.
    u64 key = (u64)file;

    bpf_map_delete_elem(&open_files, &key);

    return AIDR_RET(0);
}

SEC(AIDR_SEC_PATH_UNLINK)
int BPF_PROG(mon_files_unlink, const struct path *dir, struct dentry *dentry)
{
    if (task_tracked())
        log_remove(dir, dentry);

    return AIDR_RET(0);
}

SEC(AIDR_SEC_PATH_RMDIR)
int BPF_PROG(mon_files_rmdir, const struct path *dir, struct dentry *dentry)
{
    if (task_tracked())
        log_remove(dir, dentry);

    return AIDR_RET(0);
}

// Renaming onto an existing file destroys it; an exchange keeps both.
SEC(AIDR_SEC_PATH_RENAME)
int BPF_PROG(mon_files_rename, const struct path *old_dir, struct dentry *old_dentry,
             const struct path *new_dir, struct dentry *new_dentry, unsigned int flags)
{
    if (task_tracked() && new_dentry->d_inode && !(flags & RENAME_EXCHANGE))
        log_remove(new_dir, new_dentry);

    return AIDR_RET(0);
}

// Required: BPF-LSM (and the bpf_d_path helper) reject non-GPL programs.
char LICENSE[] SEC("license") = "GPL";

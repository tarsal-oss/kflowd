/*
 * kflowd.bpf.c
 *
 * Authors: Dirk Tennie <dirk@kflow.co>
 *          Barrett Lyon <blyon@kflow.co>
 *
 * Copyright (c) 2024 Kflow.co
 *
 */
#include "vmlinux.h"
#include "kflowd.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL v2";

/* bpf maps */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, sizeof(struct RECORD_FS) * 8192);
} ringbuf_records SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAP_RECORDS_MAX);
    __type(key, __u64);
    __type(value, struct RECORD_FS);
} hash_records SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct RECORD_FS);
} heap_record_fs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct RECORD_SOCK);
} heap_record_sock SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAP_SOCKS_MAX);
    __type(key, __u64);
    __type(value, struct SOCK_INFO);
} hash_socks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct SOCK_INFO);
} heap_sock SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAP_SOCKS_MAX);
    __type(key, struct SOCK_TUPLE);
    __type(value, __u64);
} hash_tuples SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct SOCK_TUPLE);
} heap_tuple SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAP_XFILES_MAX);
    __type(key, char[TASK_COMM_LEN]);
    __type(value, struct XFILES);
} hash_xfiles SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(max_entries, MAP_SOCKS_MAX);
    __type(value, __u64[2]);
} queue_socks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct STATS);
} stats SEC(".maps");

/* glabal variables shared with userspace */
const volatile __u64 ts_start;
const volatile __u32 agg_events_max;
const volatile __u32 agg_idle_timeout;
const volatile __u32 agg_active_timeout;
const volatile __u16 output_udp_port[UDP_SERVER_MAX];
const volatile __u16 app_proto[APP_MAX][APP_PORT_MAX];
const volatile __u16 app_port[APP_MAX][APP_PORT_MAX];
const volatile pid_t pid_self;
const volatile pid_t pid_shell;
volatile __u32       monitor = MONITOR_NONE;

/* debug helpers for process debugging and kernel stack */
static __always_inline void debug_dump_stack(void *, const char *);
static __always_inline bool debug_proc(char *, char *);
static __always_inline bool debug_file_is_tp(char *);
const volatile char         debug[DBG_LEN_MAX];

/* handle all filesystem events for aggregation */
static __always_inline int handle_fs_event(void *ctx, const struct FS_EVENT_INFO *event) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct dentry      *dentry;
    struct dentry      *dentry_old;
    struct inode       *inode;
    struct dentry      *dparent;
    struct RECORD_FS   *r;
    struct STATS       *s;
    const __u8         *dname;
    const __u8         *pathnode[FILEPATH_NODE_MAX] = {0};
    char                filename[FILENAME_LEN_MAX] = {0};
    char               *func;
    bool                agg_end;
    umode_t             imode;
    pid_t               gppid;
    pid_t               ppid;
    pid_t               pid;
    pid_t               tid;
    __u64               ts = bpf_ktime_get_ns();
    __u64               ts_now;
    __u32               num_nodes = 0;
    __u32               offset = 0;
    __u32               len = 0;
    __u64               key;
    __u32               zero = 0;
    __u32               index;
    __u32               ino;
    __u32               cnt;

    /* ignore file system events from self and parent shells to prevent amplification loops
     * in shell pipelines, e.g. kflowd | curl */
    pid = bpf_get_current_pid_tgid() >> 32;
    tid = bpf_get_current_pid_tgid();
    ppid = BPF_CORE_READ(task, real_parent, tgid);
    gppid = BPF_CORE_READ(task, real_parent, real_parent, tgid);
    if (pid_self == pid || (pid_shell > 1 && (pid_shell == ppid || pid_shell == gppid)))
        return 0;

    /* get fs event info */
    index = event->index;
    dentry = event->dentry;
    dentry_old = event->dentry_old;
    func = event->func;

    /* get inode and filename */
    inode = BPF_CORE_READ((dentry_old ? dentry_old : dentry), d_inode);
    bpf_probe_read_kernel_str(filename, sizeof(filename), BPF_CORE_READ(dentry, d_name.name));
    if (!inode || !filename[0])
        return 0;

    /* get pid, inode and mode to detect file or link */
    ino = BPF_CORE_READ(inode, i_ino);
    imode = BPF_CORE_READ(inode, i_mode);
    if (!(S_ISREG(imode) || S_ISLNK(imode)))
        return 0;

    /* insert or update element in hashmap */
    key = KEY_PID_INO(pid, ino);
    r = bpf_map_lookup_elem(&hash_records, &key);
    s = bpf_map_lookup_elem(&stats, &zero);
    if (r) {
        /* update record */
        if (fsevt[index].value == FS_MOVED_TO) {
            __builtin_memset(r->filename_to - 1, 0, sizeof(r->filename_to) + 1);
            bpf_probe_read_kernel_str(&r->filename_to, sizeof(r->filename_to), BPF_CORE_READ(dentry, d_name.name));
        }
        r->rc.ts = bpf_ktime_get_ns();
    } else {
        /* get record storage on heap and populate initial data */
        r = bpf_map_lookup_elem(&heap_record_fs, &zero);
        if (!r)
            return 0;
        task = (struct task_struct *)bpf_get_current_task();
        r->ino = ino;
        r->rc.pid = pid;
        r->rc.tid = tid;
        r->rc.ppid = ppid;
        r->rc.uid = bpf_get_current_uid_gid();
        r->rc.gid = bpf_get_current_uid_gid() >> 32;
        __builtin_memset(r->rc.proc, 0, sizeof(r->rc.proc));
        bpf_get_current_comm(&r->rc.proc, sizeof(r->rc.proc));
        __builtin_memset(r->rc.comm, 0, sizeof(r->rc.comm));
        bpf_probe_read_kernel_str(&r->rc.comm, sizeof(r->rc.comm),
                                  BPF_CORE_READ(task, mm, exe_file, f_path.dentry, d_name.name));
        __builtin_memset(r->rc.comm_parent, 0, sizeof(r->rc.comm_parent));
        bpf_probe_read_kernel_str(&r->rc.comm_parent, sizeof(r->rc.comm_parent),
                                  BPF_CORE_READ(task, real_parent, mm, exe_file, f_path.dentry, d_name.name));
        __builtin_memset(r->filename, 0, sizeof(r->filename));
        bpf_probe_read_kernel_str(&r->filename, sizeof(r->filename), BPF_CORE_READ(dentry, d_name.name));
        r->isize_first = BPF_CORE_READ(inode, i_size);
        r->mtime_nsec_first = BPF_CORE_READ(inode, i_mtime.tv_sec) * (u64)1e9 + BPF_CORE_READ(inode, i_mtime.tv_nsec);
        r->rc.ts_first = r->rc.ts = bpf_ktime_get_ns();

        /* build path by path-walking backwards in kernel dentry tree */
        for (cnt = 0; cnt < FILEPATH_NODE_MAX; cnt++) {
            dname = BPF_CORE_READ(dentry, d_name.name);
            dparent = BPF_CORE_READ(dentry, d_parent);
            pathnode[cnt] = dname;
            if (BPF_CORE_READ(dentry, d_inode, i_ino) == BPF_CORE_READ(dparent, d_inode, i_ino))
                break;
            dentry = dparent;
        }
        num_nodes = 0;
        if (cnt < FILEPATH_NODE_MAX)
            num_nodes = cnt;
        __builtin_memset(r->filepath, 0, sizeof(r->filepath));
        for (cnt = num_nodes; cnt > 0; cnt--) {
            if (pathnode[cnt] && offset < (sizeof(r->filepath) - DNAME_INLINE_LEN)) {
                len = bpf_probe_read_kernel_str(&r->filepath[offset], sizeof(r->filepath) - DNAME_INLINE_LEN,
                                                (void *)pathnode[cnt]);
                if (len && offset < (sizeof(r->filepath)) - len) {
                    offset += (len - 1);
                    if (cnt != num_nodes && offset < (sizeof(r->filepath))) {
                        r->filepath[offset] = '/';
                        offset++;
                    }
                }
            }
            // verifier issue
            // else
            //    break;
        }

        /* init incremental counters */
        r->events = 0;
        for (cnt = 0; cnt < FS_EVENT_MAX; ++cnt)
            r->event[cnt] = 0;
        r->inlink++;

        /* stats */
        if (s)
            s->fs_records++;
    }
    if (s)
        s->fs_events++;

    /* populate remaining record data */
    r->rc.age = r->rc.ts - BPF_CORE_READ(task, start_time);
    r->imode = imode;
    r->isize = BPF_CORE_READ(inode, i_size);
    r->inlink = BPF_CORE_READ(inode, i_nlink);
    if (index == I_CREATE && dentry_old) /* increment link count */
        r->inlink++;
    r->iuid = BPF_CORE_READ(inode, i_uid.val);
    r->igid = BPF_CORE_READ(inode, i_gid.val);
    r->idev = GETDEV(BPF_CORE_READ(inode, i_sb, s_dev));
    r->atime_nsec = BPF_CORE_READ(inode, i_atime.tv_sec) * (u64)1e9 + BPF_CORE_READ(inode, i_atime.tv_nsec);
    r->mtime_nsec = BPF_CORE_READ(inode, i_mtime.tv_sec) * (u64)1e9 + BPF_CORE_READ(inode, i_mtime.tv_nsec);
    r->ctime_nsec = BPF_CORE_READ(inode, i_ctime.tv_sec) * (u64)1e9 + BPF_CORE_READ(inode, i_ctime.tv_nsec);
    r->events++;
    r->event[index]++;

    /* create/update record in hash table */
    if (bpf_map_update_elem(&hash_records, &key, r, BPF_ANY) < 0) {
        if (!debug_file_is_tp(r->filename))
            bpf_printk("WARNING: Failed to create or update record for key %u-%u", pid, ino);
        return 0;
    }

    /* submit to ringbuffer at end of aggregation */
    agg_end = false;
    if (index == I_CLOSE_WRITE || index == I_CLOSE_NOWRITE || index == I_DELETE || index == I_MOVED_TO ||
        (index == I_CREATE && (S_ISLNK(imode) || r->inlink > 1)))
        agg_end = true;
    if (!agg_end && agg_events_max)
        if (r->events >= agg_events_max)
            agg_end = true;
    if (agg_end) {
        r->rc.type = RECORD_TYPE_FILE;
        __u32 output_len = sizeof(*r);
        if (bpf_ringbuf_output(&ringbuf_records, r, output_len, 0)) {
            __u64 rbsize = bpf_ringbuf_query(&ringbuf_records, BPF_RB_RING_SIZE);
            __u64 rbdata = bpf_ringbuf_query(&ringbuf_records, BPF_RB_AVAIL_DATA);
            if (!debug_file_is_tp(r->filename)) {
                bpf_printk("WARNING: Failed to submit record to ringbuffer for key %u-%u", pid, ino);
                bpf_printk("Ringbuffer size is %lu (%lu records)", rbsize, rbsize / sizeof(*r));
                bpf_printk("Ringbuffer unconsumed data is %lu (%lu records)\n", rbdata, rbdata / sizeof(*r));
            }
            if (s)
                s->fs_records_dropped++;
        }
        if (bpf_map_delete_elem(&hash_records, &key)) {
            if (!debug_file_is_tp(r->filename))
                bpf_printk("WARNING: Failed to delete record for key %u-%u", pid, ino);
            return 0;
        }
        if (s)
            s->fs_records_deleted++;
    }

    /* debug */
    if (!debug_proc(r->rc.comm, r->filename))
        return 0;
    bpf_printk("KPROBE:    %s", func);
    if (S_ISLNK(imode) || r->inlink > 1)
        bpf_printk("FS_EVENT:  LINK_%s  %s  #%u", fsevt[index].name, r->filename, r->events);
    else
        bpf_printk("FS_EVENT:  FILE_%s  %s  #%u", fsevt[index].name, r->filename, r->events);
    bpf_printk("COMM:      %s  GID: %u  UID: %u", r->rc.comm, r->rc.gid, r->rc.uid);
    bpf_printk("PID/INO:   %u/%u %s in hashmap", pid, ino, r->rc.ts ? "" : "NOT");
    bpf_printk("TID:       %u  PPID: %u", r->rc.tid, r->rc.ppid);
    if ((s = bpf_map_lookup_elem(&stats, &zero))) {
        __u64 rsz = sizeof(*r);
        rsz += (8 - rsz % 8);
        if (s->fs_records == 1) {
            s->fs_records_rb_max = bpf_ringbuf_query(&ringbuf_records, BPF_RB_RING_SIZE) / rsz;
        }
        __u64 records_rb_curr = bpf_ringbuf_query(&ringbuf_records, BPF_RB_AVAIL_DATA) / rsz;
        __u64 records_rb_in = bpf_ringbuf_query(&ringbuf_records, BPF_RB_PROD_POS) / rsz;
        __u64 records_rb_out = bpf_ringbuf_query(&ringbuf_records, BPF_RB_CONS_POS) / rsz;
        ts_now = bpf_ktime_get_ns();
        if ((ts_now - ts_start) > (u64)1e9) {
            bpf_printk("RECORDS        Total (%lu sec, %lu events)", (ts_now - ts_start) / (u64)1e9, s->fs_events);
            bpf_printk("  Created      %lu   %lu/sec", s->fs_records, (s->fs_records * (u64)1e9) / (ts_now - ts_start));
            bpf_printk("  Deleted      %lu", s->fs_records_deleted);
            bpf_printk("  Dropped      %lu", s->fs_records_dropped);
            bpf_printk("  Ringbuf-in   %lu   %lu/sec", records_rb_in, (records_rb_in * (u64)1e9) / (ts_now - ts_start));
            bpf_printk("  Ringbuf-out  %lu   %lu/sec", records_rb_out,
                       (records_rb_out * (u64)1e9) / (ts_now - ts_start));
            bpf_printk("  Ringbuf-@    %lu pct (%lu/%lu)", (records_rb_curr * 100) / s->fs_records_rb_max,
                       records_rb_curr, s->fs_records_rb_max);
        }
    }
    debug_dump_stack(ctx, func);
    ts_now = bpf_ktime_get_ns();
    bpf_printk("KPROBE processed in %lus %luns\n", (ts_now - ts) / (u64)1e9, (ts_now - ts) % (u64)1e9);

    return 0;
}

/* kretprobe for FS_CREATE event of regular file */
SEC("kretprobe/do_filp_open")
int BPF_KRETPROBE(do_filp_open, struct file *filp) {
    KPROBE_SWITCH(MONITOR_FILE);
    if (BPF_CORE_READ(filp, f_mode) & FMODE_CREATED) {
        struct FS_EVENT_INFO event = {I_CREATE, BPF_CORE_READ(filp, f_path.dentry), NULL, "do_filp_open"};
        handle_fs_event(ctx, &event);
    }
    return 0;
}

/* kprobe for FS_CREATE event of hard link */
SEC("kprobe/security_inode_link")
int BPF_KPROBE(security_inode_link, struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry) {
    KPROBE_SWITCH(MONITOR_FILE);
    struct FS_EVENT_INFO event = {I_CREATE, new_dentry, old_dentry, "security_inode_link"};
    handle_fs_event(ctx, &event);
    return 0;
}

/* dependent kprobes for FS_CREATE event of symbolic link */
struct dentry *dentry_symlink = NULL;
SEC("kprobe/security_inode_symlink")
int BPF_KPROBE(security_inode_symlink, struct inode *dir, struct dentry *dentry, const char *old_name) {
    KPROBE_SWITCH(MONITOR_FILE);
    dentry_symlink = dentry;
    return 0;
}
SEC("kprobe/dput")
int BPF_KPROBE(dput, struct dentry *dentry) {
    KPROBE_SWITCH(MONITOR_FILE);
    int imode = BPF_CORE_READ(dentry, d_inode, i_mode);
    int ino = BPF_CORE_READ(dentry, d_inode, i_ino);
    /* only continue for existing symbolic link */
    if (!(S_ISLNK(imode) && ino && dentry_symlink == dentry))
        return 0;
    dentry_symlink = NULL;
    struct FS_EVENT_INFO event = {I_CREATE, dentry, NULL, "dput+security_inode_symlink"};
    handle_fs_event(ctx, &event);
    return 0;
}

/* kprobe for FS_OPEN event */
SEC("kprobe/fd_install")
int BPF_KPROBE(fd_install, unsigned int fd, struct file *file) {
    KPROBE_SWITCH(MONITOR_FILE);
    struct FS_EVENT_INFO event = {I_OPEN, BPF_CORE_READ(file, f_path.dentry), NULL, "fd_install"};
    handle_fs_event(ctx, &event);
    return 0;
}

/* kprobe for FS_OPEN_EXEC event */
SEC("kretprobe/do_open_execat")
int BPF_KRETPROBE(do_open_execat, struct file *file) {
    KPROBE_SWITCH(MONITOR_FILE);
    struct FS_EVENT_INFO event = {I_OPEN_EXEC, BPF_CORE_READ(file, f_path.dentry), NULL, "do_open_execat"};
    handle_fs_event(ctx, &event);
    return 0;
}

/* kprobe for FS_ACCESS event */
SEC("kprobe/__kernel_read")
int BPF_KPROBE(__kernel_read, struct file *file) {
    KPROBE_SWITCH(MONITOR_FILE);
    struct FS_EVENT_INFO event = {I_ACCESS, BPF_CORE_READ(file, f_path.dentry), NULL, "__kernel_read"};
    handle_fs_event(ctx, &event);
    return 0;
}

/* kprobe for FS_ATTRIB, FS_ACCESS and FS_MODIFY eventis */
SEC("kprobe/notify_change")
int BPF_KPROBE(notify_change, struct dentry *dentry, struct iattr *attr) {
    KPROBE_SWITCH(MONITOR_FILE);
    __u32 mask = 0;

    /* get attribute mask */
    int ia_valid = BPF_CORE_READ(attr, ia_valid);
    if (ia_valid & ATTR_UID)
        mask |= FS_ATTRIB;
    if (ia_valid & ATTR_GID)
        mask |= FS_ATTRIB;
    if (ia_valid & ATTR_SIZE)
        mask |= FS_MODIFY;
    if ((ia_valid & (ATTR_ATIME | ATTR_MTIME)) == (ATTR_ATIME | ATTR_MTIME))
        mask |= FS_ATTRIB;
    else if (ia_valid & ATTR_ATIME)
        mask |= FS_ACCESS;
    else if (ia_valid & ATTR_MTIME)
        mask |= FS_MODIFY;
    if (ia_valid & ATTR_MODE)
        mask |= FS_ATTRIB;

    /* handle event */
    if (mask & FS_ATTRIB) {
        struct FS_EVENT_INFO event_attrib = {I_ATTRIB, dentry, NULL, "notify_change"};
        handle_fs_event(ctx, &event_attrib);
    }
    if (mask & FS_MODIFY) {
        struct FS_EVENT_INFO event_modify = {I_MODIFY, dentry, NULL, "notify_change"};
        handle_fs_event(ctx, &event_modify);
    }
    if (mask & FS_ACCESS) {
        struct FS_EVENT_INFO event_access = {I_ACCESS, dentry, NULL, "notify_change"};
        handle_fs_event(ctx, &event_access);
    }

    return 0;
}

/* kprobe for FS_ATTRIB and FS_MODIFY events */
SEC("kprobe/__fsnotify_parent")
int BPF_KPROBE(__fsnotify_parent, struct dentry *dentry, __u32 mask, const void *data, int data_type) {
    KPROBE_SWITCH(MONITOR_FILE);
    if (mask & FS_ATTRIB) {
        struct FS_EVENT_INFO event_attrib = {I_ATTRIB, dentry, NULL, "__fsnotify_parent"};
        handle_fs_event(ctx, &event_attrib);
    }
    if (mask & FS_MODIFY) {
        struct FS_EVENT_INFO event_modify = {I_MODIFY, dentry, NULL, "__fsnotify_parent"};
        handle_fs_event(ctx, &event_modify);
    }
    if (mask & FS_ACCESS) {
        struct FS_EVENT_INFO event_access = {I_ACCESS, dentry, NULL, "__fsnotify_parent"};
        handle_fs_event(ctx, &event_access);
    }
    return 0;
}

/* kprobe for CLOSE_WRITE, CLOSE_NOWRITE events */
SEC("kprobe/__fput")
int BPF_KPROBE(__fput, struct file *file) {
    KPROBE_SWITCH(MONITOR_FILE);
    int                  nowrite = !(BPF_CORE_READ(file, f_mode) & FMODE_WRITE);
    struct FS_EVENT_INFO event = {nowrite ? I_CLOSE_NOWRITE : I_CLOSE_WRITE, BPF_CORE_READ(file, f_path.dentry), NULL,
                                  "__fput"};
    handle_fs_event(ctx, &event);
    return 0;
}

/* kprobe for FS_MOVED_FROM snd FS_MOVED_TO event */
SEC("kprobe/security_inode_rename")
int BPF_KPROBE(security_inode_rename, struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir,
               struct dentry *new_dentry) {
    KPROBE_SWITCH(MONITOR_FILE);
    /* check if dir */
    if (((BPF_CORE_READ(old_dentry, d_flags) & DCACHE_ENTRY_TYPE) == DCACHE_DIRECTORY_TYPE) ||
        ((BPF_CORE_READ(old_dentry, d_flags) & DCACHE_ENTRY_TYPE) == DCACHE_AUTODIR_TYPE))
        return 0;
    /* handle both events */
    struct FS_EVENT_INFO event_from = {I_MOVED_FROM, old_dentry, NULL, "security_inode_rename"};
    handle_fs_event(ctx, &event_from);
    struct FS_EVENT_INFO event_to = {I_MOVED_TO, new_dentry, old_dentry, "security_inode_rename"};
    handle_fs_event(ctx, &event_to);
    return 0;
}

/* kprobe for FS_DELETE event */
SEC("kprobe/security_inode_unlink")
int BPF_KPROBE(security_inode_unlink, struct inode *dir, struct dentry *dentry) {
    KPROBE_SWITCH(MONITOR_FILE);
    struct FS_EVENT_INFO event = {I_DELETE, dentry, NULL, "security_inode_unlink"};
    handle_fs_event(ctx, &event);
    return 0;
}

/* tracepoint for process exit events  */
SEC("tracepoint/sched/sched_process_exit")
int sched_process_exit(void *ctx) {
    struct task_struct *task;
    pid_t               pid;
    pid_t               ppid;
    char                comm[TASK_COMM_LEN] = {0};
    __u64               start_time;
    __u64               exit_time;
    int                 exit_code;
    __u32               sig;
    int                 rc;

    /* get pid, family and protocol */
    task = (struct task_struct *)bpf_get_current_task();
    ppid = BPF_CORE_READ(task, real_parent, tgid);
    pid = bpf_get_current_pid_tgid() >> 32;
    exit_code = BPF_CORE_READ(task, exit_code);

    start_time = BPF_CORE_READ(task, start_time);
    exit_time = bpf_ktime_get_ns();
    BPF_CORE_READ(task, real_parent, tgid);
    sig = exit_code & 0xff;
    rc = exit_code >> 8;
    bpf_probe_read_kernel_str(comm, sizeof(comm), BPF_CORE_READ(task, mm, exe_file, f_path.dentry, d_name.name));

    /* debug */
    if (debug_proc(comm, NULL)) {
        bpf_printk("SCHED_PROCESS_EXIT:");
        bpf_printk("  PROCESS: %s   PID: %u  PPID: %u", comm, pid, ppid);
        bpf_printk("  SIGNAL: %u   RC: %u", sig, rc);
        bpf_printk("  START: %lus  END: %lus  AGE: %lums\n", start_time / (u64)1e9, exit_time / (u64)1e9,
                   (exit_time - start_time) / (u64)1e6);
    }

    return 0;
}

/* submit tcp or udp socket record to ringbuffer */
static __always_inline int submit_sock_record(struct SOCK_INFO *sinfo) {
    struct RECORD_SOCK *r;
    __u32               cnt;
    __u32               zero = 0;

    r = bpf_map_lookup_elem(&heap_record_sock, &zero);
    if (!r)
        return 0;

    struct sock *sock = sinfo->sock;
    __u32        output_len = sizeof(*r);
    r->rc.type = RECORD_TYPE_SOCK;
    r->rc.pid = sinfo->pid;
    r->rc.tid = sinfo->tid;
    r->rc.ppid = sinfo->ppid;
    r->rc.uid = sinfo->uid;
    r->rc.gid = sinfo->gid;
    r->rc.age = bpf_ktime_get_ns() - sinfo->ts_proc;
    __builtin_memset(r->rc.proc, 0, sizeof(r->rc.proc));
    bpf_probe_read_kernel_str(r->rc.proc, sizeof(r->rc.proc), sinfo->proc);
    __builtin_memset(r->rc.comm, 0, sizeof(r->rc.comm));
    bpf_probe_read_kernel_str(r->rc.comm, sizeof(r->rc.comm), sinfo->comm);
    __builtin_memset(r->rc.comm_parent, 0, sizeof(r->rc.comm_parent));
    bpf_probe_read_kernel_str(r->rc.comm_parent, sizeof(r->rc.comm_parent), sinfo->comm_parent);
    // TBD: set on socket init instead first packet
    r->rc.ts_first = sinfo->ts_first;
    r->rc.ts = bpf_ktime_get_ns();
    r->family = sinfo->family;
    r->role = sinfo->role;
    r->proto = sinfo->proto;
    r->state = sinfo->state;
    bpf_probe_read_kernel(r->laddr, IP_ADDR_LEN_MAX, sinfo->laddr);
    bpf_probe_read_kernel(r->raddr, IP_ADDR_LEN_MAX, sinfo->raddr);
    r->lport = sinfo->lport;
    r->rport = sinfo->rport;
    r->rx_ifindex = sinfo->rx_ifindex;
    r->rx_ts_first = sinfo->rx_ts_first;
    r->rx_ts = sinfo->rx_ts;
    r->tx_ifindex = sinfo->tx_ifindex;
    r->tx_ts_first = sinfo->tx_ts_first;
    r->tx_ts = sinfo->tx_ts;
    if (sinfo->proto == IPPROTO_TCP) {
        r->rx_data_packets = sinfo->rx_data_packets;
        r->rx_packets = sinfo->rx_packets;
        if (sinfo->rx_flags_map[0] == TCP_SYN)
            r->rx_packets += 2; /* kernel not counting server rx syn and rx ack in tcp handshake */
        if (sinfo->rx_flags_map[0] == (TCP_SYN | TCP_ACK))
            r->rx_packets++; /* kernel not counting client rx syn-ack in tcp handshake */
        r->rx_packets_queued = sinfo->rx_packets_queued;
        r->rx_packets_drop = sinfo->rx_packets_drop[1];
        r->rx_packets_reorder = sinfo->rx_packets_reorder[1];
        r->rx_packets_frag = sinfo->rx_packets_frag;
        r->rx_events = sinfo->rx_events;
        for (cnt = 0; cnt < SOCK_FLAGS_MAX; cnt++) {
            r->rx_flags[cnt] = sinfo->rx_flags_map[cnt];
            r->rx_event[cnt] = sinfo->rx_event[cnt];
            if (!sinfo->rx_flags_map[cnt])
                break;
        }
        r->rx_bytes = sinfo->rx_bytes;
        r->rx_ttl = r->rx_packets ? sinfo->rx_ttl / r->rx_packets : 0;
        r->tx_data_packets = sinfo->tx_data_packets;
        r->tx_packets = sinfo->tx_packets;
        if (sinfo->tx_flags_map[0] == TCP_SYN)
            r->tx_packets++; /* kernel not counting client tx syn in tcp handshake */
        if (sinfo->tx_flags_map[0] == (TCP_SYN | TCP_ACK))
            r->tx_packets++; /* kernel not counting server tx syn-ack in tcp handshake */
        r->tx_packets_retrans = sinfo->tx_packets_retrans[1];
        r->tx_packets_dups = sinfo->tx_packets_dups[1];
        r->tx_events = sinfo->tx_events;
        for (cnt = 0; cnt < SOCK_FLAGS_MAX; cnt++) {
            r->tx_flags[cnt] = sinfo->tx_flags_map[cnt];
            r->tx_event[cnt] = sinfo->tx_event[cnt];
            if (!sinfo->tx_flags_map[cnt])
                break;
        }
        r->tx_bytes = sinfo->tx_bytes;
        r->tx_bytes_acked = sinfo->tx_bytes_acked[1];
        r->tx_bytes_retrans = sinfo->tx_bytes_retrans[1];
        r->tx_rto = sinfo->tx_rto;
        r->rtt = sinfo->rtt;
        r->app_msg.cnt = sinfo->app_msg.cnt;
        if (sinfo->app_msg.cnt)
            bpf_probe_read_kernel(&r->app_msg, sizeof(r->app_msg), &sinfo->app_msg);

        /* update intermediate counters needed after tcp timeouts */
        sinfo->rx_data_packets = 0;
        sinfo->rx_packets = 0;
        sinfo->rx_packets_frag = 0;
        sinfo->rx_packets_drop[0] += r->rx_packets_drop;
        sinfo->rx_packets_reorder[0] += r->rx_packets_reorder;
        sinfo->rx_events = 0;
        for (cnt = 0; cnt < SOCK_FLAGS_MAX; cnt++) {
            sinfo->rx_flags_map[cnt] = 0;
            sinfo->rx_event[cnt] = 0;
        }
        sinfo->rx_flags_map_cnt = 0;
        sinfo->rx_bytes = 0;
        sinfo->rx_ttl = 0;
        sinfo->rx_ts_first = sinfo->rx_ts = 0;
        sinfo->tx_data_packets = 0;
        sinfo->tx_packets = 0;
        sinfo->tx_packets_retrans[0] += r->tx_packets_retrans;
        sinfo->tx_packets_dups[0] += r->tx_packets_dups;
        sinfo->tx_events = 0;
        for (cnt = 0; cnt < SOCK_FLAGS_MAX; cnt++) {
            sinfo->tx_flags_map[cnt] = 0;
            sinfo->tx_event[cnt] = 0;
        }
        sinfo->tx_flags_map_cnt = 0;
        sinfo->tx_bytes = 0;
        sinfo->tx_bytes_acked[0] += r->tx_bytes_acked;
        sinfo->tx_bytes_retrans[0] += r->tx_bytes_retrans;
        sinfo->tx_ts_first = sinfo->tx_ts = 0;
        sinfo->app_msg.cnt = 0;
    } else if (sinfo->proto == IPPROTO_UDP) {
        r->rx_packets = sinfo->rx_packets;
        r->rx_packets_queued = sinfo->rx_packets_queued;
        r->rx_packets_drop = sinfo->rx_packets_drop[1];
        r->rx_packets_frag = sinfo->rx_packets_frag;
        r->rx_bytes = sinfo->rx_bytes;
        r->rx_ttl = r->rx_packets ? sinfo->rx_ttl / r->rx_packets : 0;
        r->tx_packets = sinfo->tx_packets;
        r->tx_bytes = sinfo->tx_bytes;
        r->app_msg.cnt = sinfo->app_msg.cnt;
        if (sinfo->app_msg.cnt)
            bpf_probe_read_kernel(&r->app_msg, sizeof(r->app_msg), &sinfo->app_msg);
    }

    /* submit to ringbuffer */
    if (bpf_ringbuf_output(&ringbuf_records, r, output_len, 0))
        bpf_printk("WARNING: Failed to submit %s socket record to ringbuffer for sock %u", GET_ROLE_STR(sinfo->role),
                   sinfo->sock);

    return 0;
}

/* check for expired records */
static __always_inline void expire_sock_records() {
    struct SOCK_INFO *sq_sinfo;
    struct SOCK_QUEUE sq = {0};
    struct STATS     *s;
    __u64             qlen = 0;
    __u64             ts_now;
    __u32             zero = 0;
    int               cnt;

    s = bpf_map_lookup_elem(&stats, &zero);
    if (s) {
        qlen = s->q_push_added + s->q_push_updated - s->q_pop_expired - s->q_pop_ignored - s->q_pop_missed;
        if (!qlen)
            return;
        if (debug_proc(NULL, NULL))
            bpf_printk("EXPIRE_SOCK_RECORDS: %lu records in queue", qlen);
    }
    ts_now = bpf_ktime_get_ns();
    for (cnt = 0; cnt < SOCK_EXP_MAX; cnt++) {
        if (s && cnt >= qlen)
            break;
        if (!bpf_map_pop_elem(&queue_socks, &sq)) {
            sq_sinfo = bpf_map_lookup_elem(&hash_socks, &sq.key);
            if (sq_sinfo) {
                __u64 ts_last = MAX(sq_sinfo->rx_ts, sq_sinfo->tx_ts);
                if (debug_proc(NULL, NULL))
                    bpf_printk("Popped socket key %lx with lport %u and rport %u from queue", sq.key, sq_sinfo->lport,
                               sq_sinfo->rport);
                if (sq.ts < ts_last) {
                    if (debug_proc(NULL, NULL))
                        bpf_printk("Ignored socket key %lx with %lu outdated timestamp %lu", sq.key, ts_last - sq.ts,
                                   sq.ts);
                    if (s)
                        s->q_pop_ignored++;
                } else if (sq.ts > ts_last) {
                    bpf_printk("WARNING: Timestamp for %s socket key %lx is %lu greater than last timestamp",
                               GET_ROLE_STR(sq_sinfo->role), sq.key, sq.ts - ts_last);
                    if (s)
                        s->q_pop_missed++;
                } else if (ts_now - sq.ts > agg_idle_timeout * (u64)1e9 ||
                           ts_now - sq_sinfo->ts_first > agg_active_timeout * (u64)1e9) {
                    /* set udp state to close on idle timeout */
                    if (sq_sinfo->proto == IPPROTO_UDP && ts_now - sq.ts > agg_idle_timeout * (u64)1e9)
                        sq_sinfo->state = UDP_CLOSE;
                    submit_sock_record(sq_sinfo);
                    if (s)
                        s->q_pop_expired++;
                    if (debug_proc(NULL, NULL)) {
                        bpf_printk("Expired socket %s key %lx for pid %u", GET_ROLE_STR(sq_sinfo->role), sq.key,
                                   sq_sinfo->pid);
                        if (ts_now - sq.ts > agg_idle_timeout * (u64)1e9)
                            bpf_printk("Expired socket key with %lu idle timestamp %lu", ts_now - sq.ts, sq.ts);
                        else
                            bpf_printk("Expired socket key with %lu active timestamp %lu", ts_now - sq_sinfo->ts_first,
                                       sq_sinfo->ts_first);
                    }
                    /* delete only UDP socket since TCP socket is deleted on TCP_CLOSE in state machine */
                    if (sq_sinfo->proto == IPPROTO_UDP) {
                        if (bpf_map_delete_elem(&hash_socks, &sq.key))
                            bpf_printk("WARNING: Failed to delete %s socket for pid %u", GET_ROLE_STR(sq_sinfo->role),
                                       sq_sinfo->pid);
                    }
                } else {
                    if (!bpf_map_push_elem(&queue_socks, &sq, BPF_EXIST)) {
                        if (s)
                            s->q_push_readded++;
                        if (debug_proc(NULL, NULL))
                            bpf_printk("Repushed socket key %lx with lport %u and rport %u to queue", sq.key,
                                       sq_sinfo->lport, sq_sinfo->rport);
                    }
                }
            } else if (debug_proc(NULL, NULL)) {
                if (s)
                    s->q_pop_missed++;
                bpf_printk("Popped socket key %lx not found", sq.key);
            }
        }
    }

    if (debug_proc(NULL, NULL) && s) {
        qlen = s->q_push_added + s->q_push_updated - s->q_pop_expired - s->q_pop_ignored - s->q_pop_missed;
        bpf_printk("  QUEUE: %lu records", qlen);
        bpf_printk("  PUSH: %u added   %u updated   %u readded", s->q_push_added, s->q_push_updated, s->q_push_readded);
        bpf_printk("  POP: %u expired   %u ignored   %u missed\n", s->q_pop_expired, s->q_pop_ignored, s->q_pop_missed);
    }
}

/* handle tcp socket tx and rx events */
static __always_inline int handle_tcp_event(void *ctx, const struct SOCK_EVENT_INFO *event) {
    pid_t               pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct SOCK_INFO   *sinfo;
    struct SOCK_TUPLE  *stuple;
    struct sock        *sock;
    char                comm[TASK_COMM_LEN] = {0};
    __u16               family;
    __u8                addr[IP_ADDR_LEN_MAX];
    __u16               lport;
    __u16               rport;
    __u8               *laddr;
    __u8               *raddr;
    __u8                tcp_state_old;
    __u8                tcp_state;
    char               *func;
    __u64               key;
    __u64               key_alt;
    __u32               zero = 0;
    __u32               cnt;

    /* ignore network events from self to prevent amplification loops */
    if (pid_self == pid)
        return 0;

    /* get socket event info */
    bpf_probe_read_kernel_str(comm, sizeof(comm), BPF_CORE_READ(task, mm, exe_file, f_path.dentry, d_name.name));
    sock = event->sock;
    family = event->family;
    func = event->func;

    /* validate family */
    if (!(family == AF_INET || family == AF_INET6))
        return 0;

    /* handle tcp client and server sockets */
    if (event->args && !sock) {
        struct trace_event_raw_inet_sock_set_state *args = event->args;

        /* get socket and ports */
        sock = (struct sock *)BPF_CORE_READ(args, skaddr);
        key = KEY_SOCK(BPF_CORE_READ(sock, __sk_common.skc_hash));
        lport = BPF_CORE_READ(args, sport);
        rport = BPF_CORE_READ(args, dport);
        laddr = BPF_CORE_READ(args, saddr);
        raddr = BPF_CORE_READ(args, daddr);
        stuple = bpf_map_lookup_elem(&heap_tuple, &zero);
        if (!stuple)
            return 0;
        // TBD: consolidate
        if (family == AF_INET) {
            bpf_probe_read_kernel(stuple->laddr, sizeof(args->saddr), BPF_CORE_READ(args, saddr));
            bpf_probe_read_kernel(stuple->raddr, sizeof(args->daddr), BPF_CORE_READ(args, daddr));
        } else {
            bpf_probe_read_kernel(stuple->laddr, sizeof(args->saddr_v6), BPF_CORE_READ(args, saddr_v6));
            bpf_probe_read_kernel(stuple->raddr, sizeof(args->daddr_v6), BPF_CORE_READ(args, daddr_v6));
        }
        stuple->lport = lport;
        stuple->rport = rport;
        stuple->proto = IPPROTO_TCP;

        /* get old and new tcp state */
        tcp_state_old = BPF_CORE_READ(args, oldstate);
        tcp_state = BPF_CORE_READ(args, newstate);

        /* debug */
        if (debug_proc(comm, NULL)) {
            /* print args socket info */
            bpf_printk("%s:  %s -> %s", func, tcp_state_table[tcp_state_old], tcp_state_table[tcp_state]);
            bpf_printk("  PID: %u  SOCK: %p  KEY: %lx", pid, sock, key);
            bpf_printk("  PROTO: %u  FAMILY: %u ", IPPROTO_TCP, family);
            if (family == AF_INET) {
                bpf_probe_read_kernel(addr, sizeof(args->saddr), BPF_CORE_READ(args, saddr));
                bpf_printk("  LOCAL:  %pI4:%u", addr, lport);
                bpf_probe_read_kernel(addr, sizeof(args->daddr), BPF_CORE_READ(args, daddr));
                bpf_printk("  REMOTE: %pI4:%u", addr, rport);
            } else {
                bpf_probe_read_kernel(addr, sizeof(args->saddr_v6), BPF_CORE_READ(args, saddr_v6));
                bpf_printk("  LOCAL:  %pI6c:%u", addr, lport);
                bpf_probe_read_kernel(addr, sizeof(args->daddr_v6), BPF_CORE_READ(args, daddr_v6));
                bpf_printk("  REMOTE: %pI6c:%u", addr, rport);
            }
        }

        if (tcp_state_old == TCP_SYN_RECV && tcp_state == TCP_ESTABLISHED) {
            sinfo = bpf_map_lookup_elem(&heap_sock, &zero);
            if (!sinfo)
                return 0;
            /* prepare new tcp server socket with unknown pid by remembering socket */
            sinfo->sock = sock;
            sinfo->family = family;
            sinfo->proto = IPPROTO_TCP;
            sinfo->role = ROLE_TCP_SERVER;
            sinfo->state = tcp_state;
            /* add rx syn, ack and tx syn-ack packet since otherwise undetected due to linux syn cookies */
            sinfo->rx_ts = bpf_ktime_get_ns();
            sinfo->rx_ts_first = sinfo->rx_ts;
            sinfo->ts_first = sinfo->rx_ts;
            sinfo->rx_events = 2;
            for (cnt = 0; cnt < SOCK_FLAGS_MAX; cnt++) {
                sinfo->rx_flags_map[cnt] = 0;
                sinfo->rx_event[cnt] = 0;
            }
            sinfo->rx_event[0] = 1;
            sinfo->rx_flags_map[0] = TCP_SYN;
            sinfo->rx_event[1] = 1;
            sinfo->rx_flags_map[1] = TCP_ACK;
            sinfo->rx_flags_map_cnt = 2;
            sinfo->tx_ts = bpf_ktime_get_ns();
            sinfo->tx_ts_first = sinfo->tx_ts;
            sinfo->tx_events = 1;
            for (cnt = 0; cnt < SOCK_FLAGS_MAX; cnt++) {
                sinfo->tx_flags_map[cnt] = 0;
                sinfo->tx_event[cnt] = 0;
            }
            sinfo->tx_event[0] = 1;
            sinfo->tx_flags_map[0] = TCP_SYN | TCP_ACK;
            sinfo->tx_flags_map_cnt = 1;
            sinfo->app_msg.cnt = 0;
            if (!bpf_map_update_elem(&hash_socks, &key, sinfo, BPF_ANY) &&
                !bpf_map_update_elem(&hash_tuples, stuple, &key, BPF_ANY)) {
                if (debug_proc(sinfo->comm, NULL))
                    bpf_printk("Prepared new tcp server socket for pid %u\n", pid);
            } else
                bpf_printk("WARNING: Failed to prepare new tcp server socket for pid %u\n", pid);
        } else if (tcp_state_old == TCP_CLOSE && tcp_state == TCP_SYN_SENT) {
            // TBD: fix key zero
            sinfo = bpf_map_lookup_elem(&heap_sock, &zero);
            if (!sinfo)
                return 0;
            /* prepare new tcp client socket by remembering pid */
            sinfo->sock = sock;
            sinfo->family = family;
            sinfo->proto = IPPROTO_TCP;
            sinfo->role = ROLE_TCP_CLIENT;
            sinfo->state = tcp_state;
            /* add tx syn, ack and rx syn-ack packet since otherwise undetected due to linux syn cookies */
            sinfo->tx_ts = bpf_ktime_get_ns();
            sinfo->tx_ts_first = sinfo->tx_ts;
            sinfo->ts_first = sinfo->tx_ts;
            sinfo->tx_events = 2;
            for (cnt = 0; cnt < SOCK_FLAGS_MAX; cnt++) {
                sinfo->tx_flags_map[cnt] = 0;
                sinfo->tx_event[cnt] = 0;
            }
            sinfo->tx_event[0] = 1;
            sinfo->tx_flags_map[0] = TCP_SYN;
            sinfo->tx_flags_map_cnt = 1;
            sinfo->rx_ts = bpf_ktime_get_ns();
            sinfo->rx_ts_first = sinfo->rx_ts;
            sinfo->rx_events = 1;
            for (cnt = 0; cnt < SOCK_FLAGS_MAX; cnt++) {
                sinfo->rx_flags_map[cnt] = 0;
                sinfo->rx_event[cnt] = 0;
            }
            sinfo->rx_event[0] = 1;
            sinfo->rx_flags_map[0] = TCP_SYN | TCP_ACK;
            sinfo->rx_flags_map_cnt = 1;
            sinfo->pid = pid;
            sinfo->tid = bpf_get_current_pid_tgid();
            sinfo->ppid = BPF_CORE_READ(task, real_parent, tgid);
            sinfo->uid = bpf_get_current_uid_gid();
            sinfo->gid = bpf_get_current_uid_gid() >> 32;
            bpf_get_current_comm(&sinfo->proc, sizeof(sinfo->proc));
            bpf_probe_read_kernel_str(&sinfo->comm, sizeof(sinfo->comm),
                                      BPF_CORE_READ(task, mm, exe_file, f_path.dentry, d_name.name));
            bpf_probe_read_kernel_str(&sinfo->comm_parent, sizeof(sinfo->comm_parent),
                                      BPF_CORE_READ(task, real_parent, mm, exe_file, f_path.dentry, d_name.name));
            sinfo->ts_proc = BPF_CORE_READ(task, start_time);
            /* calculate alternate key for tuple without local port since no kernel socket hash at this point */
            stuple->lport = 0;
            sinfo->app_msg.cnt = 0;
            key_alt = crc64(0, (const u8 *)stuple, sizeof(*stuple));
            if (!bpf_map_update_elem(&hash_socks, &key_alt, sinfo, BPF_ANY)) {
                if (debug_proc(sinfo->comm, NULL))
                    bpf_printk("Prepared new tcp client socket for alt key %lx and pid %u\n", key_alt, pid);
            } else
                bpf_printk("WARNING: Failed to prepare new tcp client socket for alt key %lx and pid %u\n", key_alt,
                           pid);
        } else if (tcp_state_old == TCP_SYN_SENT && tcp_state == TCP_ESTABLISHED) {
            /* get alternate key based on tuple without local port */
            stuple->lport = 0;
            key_alt = crc64(0, (const u8 *)stuple, sizeof(*stuple));
            stuple->lport = lport;
            sinfo = bpf_map_lookup_elem(&hash_socks, &key_alt);
            if (!sinfo || sinfo->sock != sock)
                return 0;
            sinfo->state = tcp_state;
            if (sinfo->family == AF_INET) {
                bpf_probe_read_kernel(sinfo->laddr, sizeof(args->saddr), BPF_CORE_READ(args, saddr));
                bpf_probe_read_kernel(sinfo->raddr, sizeof(args->daddr), BPF_CORE_READ(args, daddr));
            } else {
                bpf_probe_read_kernel(sinfo->laddr, sizeof(args->saddr_v6), BPF_CORE_READ(args, saddr_v6));
                bpf_probe_read_kernel(sinfo->raddr, sizeof(args->daddr_v6), BPF_CORE_READ(args, daddr_v6));
            }
            sinfo->lport = BPF_CORE_READ(args, sport);
            sinfo->rport = BPF_CORE_READ(args, dport);

            /* add new tcp client socket */
            if (!bpf_map_update_elem(&hash_socks, &key, sinfo, BPF_ANY) &&
                !bpf_map_update_elem(&hash_tuples, stuple, &key, BPF_ANY)) {
                if (debug_proc(sinfo->comm, NULL))
                    bpf_printk("Added new tcp client socket for alt key %lx, key %lx and pid %u\n", key_alt, key,
                               sinfo->pid);
            } else
                bpf_printk("WARNING: Failed to add new tcp client socket for alt key %lx and pid %u\n", key_alt,
                           sinfo->pid);
        } else if ((tcp_state_old == TCP_LAST_ACK && tcp_state == TCP_CLOSE) ||
                   (tcp_state_old == TCP_FIN_WAIT2 && tcp_state == TCP_CLOSE)) {
            sinfo = bpf_map_lookup_elem(&hash_socks, &key);
            if (sinfo && sinfo->sock == sock) {
                /* submit final record and delete closed client and server sockets */
                sinfo->state = tcp_state;
                submit_sock_record(sinfo);
                if (bpf_map_delete_elem(&hash_socks, &key))
                    bpf_printk("WARNING: Failed to delete %s socket for key %lx and pid %u\n",
                               GET_ROLE_STR(sinfo->role), key, sinfo->pid);
                else if (debug_proc(sinfo->comm, NULL))
                    bpf_printk("Submitted and deleted %s socket for key %lx and pid %u\n", GET_ROLE_STR(sinfo->role),
                               key, sinfo->pid);
            } else
                bpf_printk("WARNING: Failed tcp socket lookup for key %lx and remote host %x:%u", key,
                           *((__u32 *)raddr), rport);
        } else if (debug_proc(comm, NULL))
            bpf_printk("Pass tcp state change for pid %u\n", pid);
    } else {
        key = KEY_SOCK(BPF_CORE_READ(sock, __sk_common.skc_hash));
        sinfo = bpf_map_lookup_elem(&hash_socks, &key);
        if (!sinfo || sinfo->sock != sock)
            return 0;
        sinfo->sock = sock;
        sinfo->pid = pid;
        sinfo->tid = bpf_get_current_pid_tgid();
        sinfo->ppid = BPF_CORE_READ(task, real_parent, tgid);
        sinfo->uid = bpf_get_current_uid_gid();
        sinfo->gid = bpf_get_current_uid_gid() >> 32;
        bpf_get_current_comm(&sinfo->proc, sizeof(sinfo->proc));
        bpf_probe_read_kernel_str(&sinfo->comm, sizeof(sinfo->comm),
                                  BPF_CORE_READ(task, mm, exe_file, f_path.dentry, d_name.name));
        bpf_probe_read_kernel_str(&sinfo->comm_parent, sizeof(sinfo->comm_parent),
                                  BPF_CORE_READ(task, real_parent, mm, exe_file, f_path.dentry, d_name.name));
        sinfo->ts_proc = BPF_CORE_READ(task, start_time);
        if (sinfo->family == AF_INET) {
            __u32 laddr = BPF_CORE_READ(sock, __sk_common.skc_rcv_saddr);
            __u32 raddr = BPF_CORE_READ(sock, __sk_common.skc_daddr);
            bpf_probe_read_kernel(sinfo->laddr, sizeof(laddr), &laddr);
            bpf_probe_read_kernel(sinfo->raddr, sizeof(raddr), &raddr);
        } else {
            bpf_probe_read_kernel(sinfo->laddr, sizeof(sinfo->laddr),
                                  BPF_CORE_READ(sock, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8));
            bpf_probe_read_kernel(sinfo->raddr, sizeof(sinfo->raddr),
                                  BPF_CORE_READ(sock, __sk_common.skc_v6_daddr.in6_u.u6_addr8));
        }
        sinfo->lport = BPF_CORE_READ(sock, __sk_common.skc_num);
        sinfo->rport = bpf_ntohs(BPF_CORE_READ(sock, __sk_common.skc_dport));

        /* debug */
        if (debug_proc(sinfo->comm, NULL)) {
            /* print socket info */
            bpf_printk("%s:", func);
            bpf_printk("  PID: %u  SOCK=%p  KEY=%lx", pid, sock, key);
            bpf_printk("  PROTO: %u  FAMILY: %u ", sinfo->proto, sinfo->family);
            if (sinfo->family == AF_INET) {
                bpf_printk("  LOCAL:  %pI4:%u", sinfo->laddr, sinfo->lport);
                bpf_printk("  REMOTE: %pI4:%u", sinfo->raddr, sinfo->rport);
            } else {
                bpf_printk("  LOCAL:  %pI6c:%u", sinfo->laddr, sinfo->lport);
                bpf_printk("  REMOTE: %pI6c:%u", sinfo->raddr, sinfo->rport);
            }
        }

        /* update hash tables */
        if (!bpf_map_update_elem(&hash_socks, &key, sinfo, BPF_ANY)) {
            if (debug_proc(sinfo->comm, NULL))
                bpf_printk("Added new tcp server socket for key %lx and pid %u\n", key, pid);
        } else
            bpf_printk("WARNING: Failed to add new tcp server socket for key %lx and pid %u\n", key, pid);
    }

    return 0;
}

/* kprobe for tcp server and tcp client sockets */
SEC("tracepoint/sock/inet_sock_set_state")
int inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *args) {
    KPROBE_SWITCH(MONITOR_SOCK);
    __u16 family;

    /* get pid, family */
    family = BPF_CORE_READ(args, family);
    if (!(family == AF_INET || family == AF_INET6))
        return 0;

    struct SOCK_EVENT_INFO event = {NULL, NULL, family, 0, 0, args, 0, "inet_sock_set_state"};
    handle_tcp_event(NULL, &event);

    return 0;
}

/* kprobe for tcp server sockets */
SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(inet_csk_accept, struct sock *sock) {
    KPROBE_SWITCH(MONITOR_SOCK);
    __u16 family;

    /* get family */
    family = BPF_CORE_READ(sock, __sk_common.skc_family);
    if (!(family == AF_INET || family == AF_INET6))
        return 0;

    struct SOCK_EVENT_INFO event = {sock, NULL, family, 0, 0, NULL, 0, "inet_csk_accept"};
    handle_tcp_event(ctx, &event);

    return 0;
}

/* handle tcp packet */
static __always_inline int handle_tcp_packet(struct sock *sock, struct sk_buff *skb, bool isrx) {
    KPROBE_SWITCH(MONITOR_SOCK);
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct SOCK_INFO   *sinfo;
    struct SOCK_QUEUE   sq = {0};
    struct STATS       *s = NULL;
    __u8                tcp_flags = 0;
    __u64               key;
    __u32               cnt;
    __u32               cntf;
    __u32               zero = 0;

    /* clean expired records */
    expire_sock_records();

    /* try to get sock from buffer if zero */
    if (!sock) {
        sock = BPF_CORE_READ(skb, sk);
        if (!sock)
            return 0;
    }

    /* get key and lookup socket */
    key = KEY_SOCK(BPF_CORE_READ(sock, __sk_common.skc_hash));
    sinfo = bpf_map_lookup_elem(&hash_socks, &key);
    if (sinfo && sinfo->sock == sock) {
        struct skb_shared_info *skbinfo =
            (struct skb_shared_info *)(BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, end));
        struct tcp_sock *tcp_sock = (struct tcp_sock *)sock;
        struct tcphdr   *tcphdr = (struct tcphdr *)(BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, transport_header));
        struct iphdr    *iphdr = NULL;
        struct ipv6hdr  *ipv6hdr = NULL;
        __u8            *dnshdr = NULL;
        __u8            *httphdr = NULL;
        __u32            data_len;

        /* get data len */
        if (sinfo->family == AF_INET) {
            iphdr = (struct iphdr *)(BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, network_header));
            data_len = isrx ? bpf_ntohs(BPF_CORE_READ(iphdr, tot_len)) - BPF_CORE_READ_BITFIELD_PROBED(iphdr, ihl) * 4 -
                                  BPF_CORE_READ_BITFIELD_PROBED(tcphdr, doff) * 4
                            : BPF_CORE_READ(skb, len) -
                                  (BPF_CORE_READ(skb, transport_header) - BPF_CORE_READ(skb, network_header)) -
                                  BPF_CORE_READ_BITFIELD_PROBED(tcphdr, doff) * 4;
        } else {
            ipv6hdr = (struct ipv6hdr *)(BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, network_header));
            data_len =
                isrx ? bpf_ntohs(BPF_CORE_READ(ipv6hdr, payload_len)) - BPF_CORE_READ_BITFIELD_PROBED(tcphdr, doff) * 4
                     : BPF_CORE_READ(skb, len) - BPF_CORE_READ_BITFIELD_PROBED(tcphdr, doff) * 4;
        }

        /* get tcp flags */
        if (BPF_CORE_READ_BITFIELD_PROBED(tcphdr, fin))
            tcp_flags |= TCP_FIN;
        if (BPF_CORE_READ_BITFIELD_PROBED(tcphdr, syn))
            tcp_flags |= TCP_SYN;
        if (BPF_CORE_READ_BITFIELD_PROBED(tcphdr, rst))
            tcp_flags |= TCP_RST;
        if (BPF_CORE_READ_BITFIELD_PROBED(tcphdr, psh))
            tcp_flags |= TCP_PSH;
        if (BPF_CORE_READ_BITFIELD_PROBED(tcphdr, ack))
            tcp_flags |= TCP_ACK;
        if (BPF_CORE_READ_BITFIELD_PROBED(tcphdr, urg))
            tcp_flags |= TCP_URG;

        /* adjust packet count per flag when gso segmented */
        __u16 gso_segs = BPF_CORE_READ(skbinfo, gso_segs);
        __u64 ts_now = bpf_ktime_get_ns();
        if (isrx) {
            sinfo->rx_ts = ts_now;
            if (!sinfo->rx_events++) {
                sinfo->rx_ts_first = sinfo->rx_ts;
                if (!sinfo->ts_first)
                    sinfo->ts_first = sinfo->rx_ts;
                if (!sinfo->rx_ifindex)
                    sinfo->rx_ifindex = BPF_CORE_READ(skb, skb_iif);
            }
            if (gso_segs > 1) {
                if (data_len)
                    sinfo->rx_data_packets += gso_segs;
                sinfo->rx_packets += gso_segs;
            } else {
                if (data_len)
                    sinfo->rx_data_packets++;
                sinfo->rx_packets++;
            }
            /* queued:
               https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/progs/bpf_iter_tcp4.c
                       https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/progs/bpf_iter_tcp6.c
             */
            if (BPF_CORE_READ(sock, __sk_common.skc_state) == TCP_LISTEN)
                sinfo->rx_packets_queued = BPF_CORE_READ(sock, sk_ack_backlog);
            else if (BPF_CORE_READ(tcp_sock, rcv_nxt) > BPF_CORE_READ(tcp_sock, copied_seq))
                sinfo->rx_packets_queued = BPF_CORE_READ(tcp_sock, rcv_nxt) - BPF_CORE_READ(tcp_sock, copied_seq);
            __u32 drop = BPF_CORE_READ(sock, sk_drops.counter);
            if (drop > sinfo->rx_packets_drop[0])
                sinfo->rx_packets_drop[1] = drop - sinfo->rx_packets_drop[0];
            __u32 reorder = BPF_CORE_READ(tcp_sock, reord_seen);
            if (reorder > sinfo->rx_packets_reorder[0])
                sinfo->rx_packets_reorder[1] = reorder - sinfo->rx_packets_reorder[0];
            sinfo->rx_packets_frag += BPF_CORE_READ(skbinfo, nr_frags);
            if (data_len)
                sinfo->rx_bytes += data_len;
            for (cnt = 0; cnt < SOCK_FLAGS_MAX; cnt++)
                if (!sinfo->rx_flags_map[cnt] || sinfo->rx_flags_map[cnt] == tcp_flags)
                    break;
            if (cnt < SOCK_FLAGS_MAX) {
                if (gso_segs > 1)
                    sinfo->rx_event[cnt] += gso_segs;
                else
                    sinfo->rx_event[cnt]++;
                if (cnt == sinfo->rx_flags_map_cnt) {
                    sinfo->rx_flags_map[cnt] = tcp_flags;
                    sinfo->rx_flags_map_cnt++;
                }
            }
            if (sinfo->family == AF_INET)
                sinfo->rx_ttl += BPF_CORE_READ(iphdr, ttl);
            else
                sinfo->rx_ttl += BPF_CORE_READ(ipv6hdr, hop_limit);
        } else {
            sinfo->tx_ts = ts_now;
            if (!sinfo->tx_events++) {
                sinfo->tx_ts_first = sinfo->tx_ts;
                if (!sinfo->ts_first)
                    sinfo->ts_first = sinfo->tx_ts;
                if (!sinfo->tx_ifindex) {
                    struct dst_entry *dst_entry =
                        (struct dst_entry *)(BPF_CORE_READ(skb, _skb_refdst) & SKB_DST_PTRMASK);
                    sinfo->tx_ifindex = BPF_CORE_READ(dst_entry, dev, ifindex);
                }
            }
            if (gso_segs > 1) {
                if (data_len)
                    sinfo->tx_data_packets += gso_segs;
                sinfo->tx_packets += gso_segs;
            } else {
                if (data_len)
                    sinfo->tx_data_packets++;
                sinfo->tx_packets++;
            }
            __u32 retrans = BPF_CORE_READ(tcp_sock, total_retrans);
            if (retrans > sinfo->tx_packets_retrans[0])
                sinfo->tx_packets_retrans[1] = retrans - sinfo->tx_packets_retrans[0];
            __u32 dups = BPF_CORE_READ(tcp_sock, dsack_dups);
            if (dups > sinfo->tx_packets_dups[0])
                sinfo->tx_packets_dups[1] = dups - sinfo->tx_packets_dups[0];
            if (data_len)
                sinfo->tx_bytes += data_len;
            __u64 acked = BPF_CORE_READ(tcp_sock, bytes_acked);
            if (acked > sinfo->tx_bytes_acked[0])
                sinfo->tx_bytes_acked[1] = acked - sinfo->tx_bytes_acked[0];
            __u64 retransb = BPF_CORE_READ(tcp_sock, bytes_retrans);
            if (retransb > sinfo->tx_bytes_retrans[0])
                sinfo->tx_bytes_retrans[1] = retransb - sinfo->tx_bytes_retrans[0];

            for (cnt = 0; cnt < SOCK_FLAGS_MAX; cnt++)
                if (!sinfo->tx_flags_map[cnt] || sinfo->tx_flags_map[cnt] == tcp_flags)
                    break;
            if (cnt < SOCK_FLAGS_MAX) {
                if (gso_segs > 1)
                    sinfo->tx_event[cnt] += gso_segs;
                else
                    sinfo->tx_event[cnt]++;
                if (cnt == sinfo->tx_flags_map_cnt) {
                    sinfo->tx_flags_map[cnt] = tcp_flags;
                    sinfo->tx_flags_map_cnt++;
                }
            }
            sinfo->tx_rto = BPF_CORE_READ(tcp_sock, inet_conn.icsk_rto);
            sinfo->rtt = BPF_CORE_READ(tcp_sock, srtt_us) * 1000 / 8;
        }

        if (!bpf_map_update_elem(&hash_socks, &key, sinfo, BPF_ANY)) {
            if (debug_proc(sinfo->comm, NULL))
                bpf_printk("Updated tcp %s flags of socket %lx for pid %u", isrx ? "rx" : "tx", key, sinfo->pid);
            sq.key = key;
            sq.ts = ts_now;
            if (!bpf_map_push_elem(&queue_socks, &sq, BPF_EXIST)) {
                s = bpf_map_lookup_elem(&stats, &zero);
                if (s) {
                    if (sinfo->rx_events + sinfo->tx_events == 1)
                        s->q_push_added++;
                    else
                        s->q_push_updated++;
                }
                if (debug_proc(sinfo->comm, NULL))
                    bpf_printk("Pushed tcp key %lx with lport %u and rport %u to queue", key, sinfo->lport,
                               sinfo->rport);
                if (s) {
                    __u32 qlen =
                        s->q_push_added + s->q_push_updated - s->q_pop_expired - s->q_pop_ignored - s->q_pop_missed;
                    if (debug_proc(sinfo->comm, NULL))
                        bpf_printk("%lu records in queue", qlen);
                }
            }
        } else
            bpf_printk("WARNING: Failed to update tcp %s flags of socket %lx for pid %u", isrx ? "rx" : "tx", key,
                       sinfo->pid);

        if (debug_proc(sinfo->comm, NULL)) {
            bpf_printk("HANDLE_TCP_PACKET %s", isrx ? "RX" : "TX");
            bpf_printk("  PID: %u  KEY: %lx  STATE: %u", sinfo->pid, key, sinfo->state);
            if (sinfo->family == AF_INET) {
                bpf_printk("  LOCAL:  %pI4:%u", sinfo->laddr, sinfo->lport);
                bpf_printk("  REMOTE: %pI4:%u", sinfo->raddr, sinfo->rport);
            } else {
                bpf_printk("  LOCAL:  %pI6c:%u", sinfo->laddr, sinfo->lport);
                bpf_printk("  REMOTE: %pI6c:%u", sinfo->raddr, sinfo->rport);
            }
            bpf_printk("  %s FLAGS: 0x%x  EVENTS: %u", isrx ? "RX" : "TX", tcp_flags,
                       isrx ? sinfo->rx_events : sinfo->tx_events);
            bpf_printk("  TOTAL: TX %lu   RX %lu\n", sinfo->tx_bytes, sinfo->rx_bytes);
        }
    }

    return 0;
}

/* kprobe for ipv4 and tcp rx packets */
SEC("kprobe/tcp_v4_do_rcv")
int BPF_KPROBE(tcp_v4_do_rcv, struct sock *sock, struct sk_buff *skb) {
    KPROBE_SWITCH(MONITOR_SOCK);
    handle_tcp_packet(sock, skb, true);

    return 0;
}

/* kprobe for ipv6 and tcp rx packets */
SEC("kprobe/tcp_v6_do_rcv")
int BPF_KPROBE(tcp_v6_do_rcv, struct sock *sock, struct sk_buff *skb) {
    KPROBE_SWITCH(MONITOR_SOCK);
    handle_tcp_packet(sock, skb, true);

    return 0;
}

/* kprobe for ipv4 and tcp tx packets */
SEC("kprobe/__ip_local_out")
int BPF_KPROBE(__ip_local_out, struct net *net, struct sock *sock, struct sk_buff *skb) {
    KPROBE_SWITCH(MONITOR_SOCK);
    __u16 proto = BPF_CORE_READ(sock, sk_protocol);
    if (proto != IPPROTO_TCP)
        return 0;
    handle_tcp_packet(sock, skb, false);

    return 0;
}

/* kprobe for ipv6 and tcp tx packets */
SEC("kprobe/ip6_xmit")
int BPF_KPROBE(ip6_xmit, struct sock *sock, struct sk_buff *skb, struct flowi6 *fl6) {
    KPROBE_SWITCH(MONITOR_SOCK);
    __u16 proto = BPF_CORE_READ(sock, sk_protocol);
    if (proto != IPPROTO_TCP)
        return 0;
    handle_tcp_packet(sock, skb, false);

    return 0;
}

/* handle udp socket tx and rx events */
static __always_inline int handle_udp_event(void *ctx, const struct SOCK_EVENT_INFO *event) {
    pid_t                   pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct     *task = (struct task_struct *)bpf_get_current_task();
    struct sk_buff         *skb;
    struct skb_shared_info *skbinfo;
    struct sock            *sock;
    struct iphdr           *iphdr = NULL;
    struct ipv6hdr         *ipv6hdr = NULL;
    struct udphdr          *udphdr;
    struct SOCK_INFO       *sinfo;
    struct SOCK_TUPLE      *stuple;
    struct SOCK_QUEUE       sq = {0};
    struct STATS           *s;
    __u16                   gso_segs;
    char                    comm[TASK_COMM_LEN] = {0};
    __u32                   bindlock;
    __u32                   data_len;
    __u16                   family;
    char                   *func;
    bool                    isrx;
    __u16                   lport;
    __u16                   rport;
    __u8                   *dnshdr = NULL;
    bool                    is_app_port[APP_MAX] = {0};
    __u64                   key;
    __u64                   ts_now;
    __u32                   zero = 0;
    __u16                   num = 0;
    int                     cnt;
    int                     cntp;
    int                     cnts;

    /* ignore network events from self to prevent amplification loops */
    if (pid_self == pid)
        return 0;

    /* get socket event info */
    sock = event->sock;
    skb = event->skb;
    family = event->family;
    isrx = event->isrx;
    func = event->func;

    /* get ip or ipv6 and udp headers from socket buffer */
    if (family == AF_INET)
        iphdr = (struct iphdr *)(BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, network_header));
    else if (family == AF_INET6)
        ipv6hdr = (struct ipv6hdr *)(BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, network_header));
    else
        return 0;
    udphdr = (struct udphdr *)(BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, transport_header));
    data_len = isrx ? bpf_ntohs(BPF_CORE_READ(udphdr, len)) - sizeof(udphdr)
                    : BPF_CORE_READ(skb, len) -
                          (BPF_CORE_READ(skb, transport_header) - BPF_CORE_READ(skb, network_header)) - sizeof(udphdr);

    /* get local and remote port */
    if (isrx) {
        lport = bpf_ntohs(BPF_CORE_READ(udphdr, dest));
        rport = bpf_ntohs(BPF_CORE_READ(udphdr, source));
    } else {
        lport = event->lport;
        rport = event->rport;
    }

    /* get gso kernel segments to adjust packet counters */
    skbinfo = (struct skb_shared_info *)(BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, end));
    gso_segs = BPF_CORE_READ(skbinfo, gso_segs);

    /* ignore network events of other process caused from self to prevent amplification loops */
    bpf_probe_read_kernel_str(comm, sizeof(comm), BPF_CORE_READ(task, mm, exe_file, f_path.dentry, d_name.name));
    for (cntp = 0; cntp < UDP_SERVER_MAX; cntp++) {
        if (!output_udp_port[cntp])
            break;
        if (lport == output_udp_port[cntp]) {
            char monitor_str[UDP_MONITOR_STR_LEN] = {0};
            char socket_str[] = "socket";
            /* check if message has InfoMonitor set to socket */
            bpf_probe_read_kernel(monitor_str, UDP_MONITOR_STR_LEN - 1,
                                  (char *)udphdr + sizeof(*udphdr) + UDP_MONITOR_OFS);
            for (cnt = 0; cnt < sizeof(monitor_str) - sizeof(socket_str); cnt++) { /* strcmp not available */
                for (cnts = 0; cnts < sizeof(socket_str) - 1; cnts++)
                    if (socket_str[cnts] != monitor_str[cnt + cnts])
                        break;
                if (cnts == sizeof(socket_str) - 1) {
                    /* ignore record */
                    if (debug_proc(comm, NULL))
                        bpf_printk("Ignore socket record from self to local port %u", lport);
                    return 0;
                }
            }
        }
    }

    /* check for dns port */
    for (cnt = 0; cnt < APP_PORT_MAX; cnt++) {
        // verifier issue
        // if (!dns_proto[cnt])
        //    break;
        if (IPPROTO_UDP == app_proto[APP_DNS][cnt] &&
            (lport == app_port[APP_DNS][cnt] || rport == app_port[APP_DNS][cnt])) {
            is_app_port[APP_DNS] = true;
            dnshdr = BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, transport_header) + sizeof(*udphdr);
            break;
        }
    }

    /* clean expired records */
    expire_sock_records();

    /* lookup and update socket */
    key = KEY_SOCK(BPF_CORE_READ(sock, __sk_common.skc_hash));
    sinfo = bpf_map_lookup_elem(&hash_socks, &key);
    s = bpf_map_lookup_elem(&stats, &zero);
    ts_now = bpf_ktime_get_ns();
    if (sinfo && sinfo->sock == sock) {
        /* update existing udp socket */
        if (isrx) {
            sinfo->rx_ts = ts_now;
            if (!sinfo->rx_ts_first) {
                sinfo->rx_ts_first = sinfo->rx_ts;
                sinfo->rx_packets_drop[0] = BPF_CORE_READ(sock, sk_drops.counter);
            } else
                sinfo->rx_packets_drop[1] = BPF_CORE_READ(sock, sk_drops.counter) - sinfo->rx_packets_drop[0];
            if (gso_segs > 1)
                sinfo->rx_packets += gso_segs;
            else
                sinfo->rx_packets++;
            sinfo->rx_bytes += data_len;
            sinfo->rx_packets_queued = BPF_CORE_READ(sock, sk_backlog.rmem_alloc.counter) -
                                       BPF_CORE_READ((struct udp_sock *)sock, forward_deficit);
            sinfo->rx_packets_frag += BPF_CORE_READ(skbinfo, nr_frags);
            if (!sinfo->rx_ifindex)
                sinfo->rx_ifindex = BPF_CORE_READ(skb, skb_iif);
            if (sinfo->family == AF_INET)
                sinfo->rx_ttl += BPF_CORE_READ(iphdr, ttl);
            else
                sinfo->rx_ttl += BPF_CORE_READ(ipv6hdr, hop_limit);
        } else {
            sinfo->tx_ts = ts_now;
            if (!sinfo->tx_ts_first)
                sinfo->tx_ts_first = sinfo->tx_ts;
            if (gso_segs > 1)
                sinfo->tx_packets += gso_segs;
            else
                sinfo->tx_packets++;
            sinfo->tx_bytes += data_len;
            if (!sinfo->tx_ifindex) {
                struct dst_entry *dst_entry = (struct dst_entry *)(BPF_CORE_READ(skb, _skb_refdst) & SKB_DST_PTRMASK);
                sinfo->tx_ifindex = BPF_CORE_READ(dst_entry, dev, ifindex);
            }
        }
        sinfo->state = BPF_CORE_READ(sock, __sk_common.skc_state);

        /* add application data (dns) */
        if (is_app_port[APP_DNS]) {
            if (sinfo->app_msg.cnt < APP_MSG_MAX) {
                num = sinfo->app_msg.cnt++;
                sinfo->app_msg.type = APP_DNS;
                sinfo->app_msg.ts[num] = bpf_ktime_get_ns();
                sinfo->app_msg.len[num] = data_len;
                sinfo->app_msg.isrx[num] = isrx;
                bpf_probe_read_kernel(sinfo->app_msg.data[num], MIN((__u16)data_len, sizeof(sinfo->app_msg.data[num])),
                                      dnshdr);
                /* export record on max application messages */
                if (sinfo->app_msg.cnt == APP_MSG_MAX) {
                    submit_sock_record(sinfo);
                    if (bpf_map_delete_elem(&hash_socks, &key))
                        bpf_printk("WARNING: Failed to delete %s socket for key %lx and pid %u\n",
                                   GET_ROLE_STR(sinfo->role), key, sinfo->pid);
                    else if (debug_proc(sinfo->comm, NULL))
                        bpf_printk("Submitted and deleted %s socket for key %lx and pid %u\n",
                                   GET_ROLE_STR(sinfo->role), key, sinfo->pid);
                    return 0;
                }
            } else
                bpf_printk("WARNING: Failed to capture dns application message #%u\n", sinfo->app_msg.cnt);
        }
        if (!bpf_map_update_elem(&hash_socks, &key, sinfo, BPF_ANY)) {
            if (debug_proc(sinfo->comm, NULL))
                bpf_printk("Updated %s socket %lx for pid %u", GET_ROLE_STR(sinfo->role), key, pid);
            sq.key = key;
            sq.ts = ts_now;
            if (!bpf_map_push_elem(&queue_socks, &sq, BPF_EXIST)) {
                if (s)
                    s->q_push_updated++;
                if (debug_proc(sinfo->comm, NULL))
                    bpf_printk("Pushed udp socket %lx with lport %u and rport %u to queue\n", key, lport, rport);
            }
        } else
            bpf_printk("WARNING: Failed to update %s socket %lx for pid %u\n", GET_ROLE_STR(sinfo->role), key, pid);
    } else {
        /* populate new socket and pid data */
        sinfo = bpf_map_lookup_elem(&heap_sock, &zero);
        stuple = bpf_map_lookup_elem(&heap_tuple, &zero);
        if (!sinfo || !stuple)
            return 0;
        sinfo->sock = sock;
        sinfo->pid = pid;
        sinfo->tid = bpf_get_current_pid_tgid();
        sinfo->ppid = BPF_CORE_READ(task, real_parent, tgid);
        sinfo->uid = bpf_get_current_uid_gid();
        sinfo->gid = bpf_get_current_uid_gid() >> 32;
        bpf_get_current_comm(&sinfo->proc, sizeof(sinfo->proc));
        bpf_probe_read_kernel_str(&sinfo->comm, sizeof(sinfo->comm),
                                  BPF_CORE_READ(task, mm, exe_file, f_path.dentry, d_name.name));
        bpf_probe_read_kernel_str(&sinfo->comm_parent, sizeof(sinfo->comm_parent),
                                  BPF_CORE_READ(task, real_parent, mm, exe_file, f_path.dentry, d_name.name));
        sinfo->ts_proc = BPF_CORE_READ(task, start_time);
        sinfo->family = family;
        sinfo->proto = IPPROTO_UDP;
        sinfo->state = BPF_CORE_READ(sock, __sk_common.skc_state);
        if (family == AF_INET) {
            __u32 laddr = isrx ? BPF_CORE_READ(iphdr, daddr) : BPF_CORE_READ(iphdr, saddr);
            __u32 raddr = isrx ? BPF_CORE_READ(iphdr, saddr) : BPF_CORE_READ(iphdr, daddr);
            bpf_probe_read_kernel(sinfo->laddr, sizeof(laddr), &laddr);
            bpf_probe_read_kernel(sinfo->raddr, sizeof(raddr), &raddr);
        } else {
            bpf_probe_read_kernel(sinfo->laddr, sizeof(sinfo->laddr), BPF_CORE_READ(ipv6hdr, saddr.in6_u.u6_addr8));
            bpf_probe_read_kernel(sinfo->raddr, sizeof(sinfo->raddr), BPF_CORE_READ(ipv6hdr, daddr.in6_u.u6_addr8));
        }
        sinfo->lport = lport;
        sinfo->rport = rport;
        sinfo->ts_first = ts_now;
        if (isrx) {
            struct skb_shared_info *skbinfo =
                (struct skb_shared_info *)(BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, end));
            sinfo->rx_ifindex = BPF_CORE_READ(skb, skb_iif);
            sinfo->rx_ts = sinfo->rx_ts_first = sinfo->ts_first;
            if (gso_segs > 1)
                sinfo->rx_packets = gso_segs;
            else
                sinfo->rx_packets = 1;
            sinfo->rx_bytes = data_len;
            /* queued/drop: github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/progs/bpf_iter_udp.c
             */
            sinfo->rx_packets_queued = BPF_CORE_READ(sock, sk_backlog.rmem_alloc.counter) -
                                       BPF_CORE_READ((struct udp_sock *)sock, forward_deficit);
            sinfo->rx_packets_drop[0] = BPF_CORE_READ(sock, sk_drops.counter);
            sinfo->rx_packets_frag = BPF_CORE_READ(skbinfo, nr_frags);
            if (sinfo->family == AF_INET)
                sinfo->rx_ttl = BPF_CORE_READ(iphdr, ttl);
            else
                sinfo->rx_ttl = BPF_CORE_READ(ipv6hdr, hop_limit);
            sinfo->tx_packets = 0;
            sinfo->tx_bytes = 0;
        } else {
            struct dst_entry *dst_entry = (struct dst_entry *)(BPF_CORE_READ(skb, _skb_refdst) & SKB_DST_PTRMASK);
            sinfo->tx_ifindex = BPF_CORE_READ(dst_entry, dev, ifindex);
            sinfo->tx_ts = sinfo->tx_ts_first = sinfo->ts_first;
            if (gso_segs > 1)
                sinfo->tx_packets = gso_segs;
            else
                sinfo->tx_packets = 1;
            sinfo->tx_bytes = data_len;
            sinfo->rx_packets = 0;
            sinfo->rx_bytes = 0;
            sinfo->rx_packets_frag = 0;
            sinfo->rx_ttl = 0;
        }

        /* nullify flags unused for UDP */
        sinfo->tx_events = 0;
        sinfo->rx_events = 0;
        for (cnt = 0; cnt < SOCK_FLAGS_MAX; cnt++) {
            sinfo->tx_flags_map[cnt] = 0;
            sinfo->rx_flags_map[cnt] = 0;
            sinfo->tx_event[cnt] = 0;
            sinfo->rx_event[cnt] = 0;
        }

        /* populate application data (dns) */
        sinfo->app_msg.cnt = 0;
        if (is_app_port[APP_DNS]) {
            if (sinfo->app_msg.cnt < APP_MSG_MAX) {
                num = sinfo->app_msg.cnt++;
                sinfo->app_msg.type = APP_DNS;
                sinfo->app_msg.ts[num] = bpf_ktime_get_ns();
                sinfo->app_msg.len[num] = data_len;
                sinfo->app_msg.isrx[num] = isrx;
                bpf_probe_read_kernel(sinfo->app_msg.data[num], MIN((__u16)data_len, sizeof(sinfo->app_msg.data[num])),
                                      dnshdr);
            } else
                bpf_printk("WARNING: Failed to capture dns application message #%u\n", sinfo->app_msg.cnt);
        }

        /* get role */
        sinfo->role = ROLE_UDP_CLIENT;
        if (isrx) {
            bindlock = BPF_CORE_READ_BITFIELD_PROBED(sock, sk_userlocks) & SOCK_BINDPORT_LOCK;
            if (bindlock || (family == AF_INET && !BPF_CORE_READ(sock, __sk_common.skc_rcv_saddr)))
                sinfo->role = ROLE_UDP_SERVER;
        }

        // TBD: consolidate
        bpf_probe_read_kernel(stuple->laddr, sizeof(stuple->laddr), sinfo->laddr);
        bpf_probe_read_kernel(stuple->raddr, sizeof(stuple->raddr), sinfo->raddr);
        stuple->lport = sinfo->lport;
        stuple->rport = sinfo->rport;
        stuple->proto = IPPROTO_UDP;
        if (!bpf_map_update_elem(&hash_socks, &key, sinfo, BPF_ANY) &&
            !bpf_map_update_elem(&hash_tuples, stuple, &key, BPF_ANY)) {
            if (debug_proc(sinfo->comm, NULL))
                bpf_printk("Added new %s socket %lx for pid %u", GET_ROLE_STR(sinfo->role), key, pid);
            sq.key = key;
            sq.ts = ts_now;
            if (!bpf_map_push_elem(&queue_socks, &sq, BPF_EXIST)) {
                if (s)
                    s->q_push_added++;
                if (debug_proc(sinfo->comm, NULL))
                    bpf_printk("Pushed first udp socket %lx with lport %u and rport %u to queue", key, lport, rport);
            }
        } else
            bpf_printk("WARNING: Failed to add new %s socket for pid %u\n", GET_ROLE_STR(sinfo->role), pid);
    }

    /* debug for socket info */
    if (!debug_proc(sinfo->comm, NULL))
        return 0;
    bpf_printk("HANDLE_UDP_EVENT: %s", func);
    bpf_printk("  PID: %u  KEY: %lx  STATE: %u", pid, key, sinfo->state);
    bpf_printk("  BINDLOCK: %u  TX: %u  RX: %u", bindlock, isrx ? 0 : data_len, isrx ? data_len : 0);
    if (sinfo->family == AF_INET) {
        bpf_printk("  LOCAL:  %pI4:%u", sinfo->laddr, sinfo->lport);
        bpf_printk("  REMOTE: %pI4:%u", sinfo->raddr, sinfo->rport);
    } else {
        bpf_printk("  LOCAL:  %pI6c:%u", sinfo->laddr, sinfo->lport);
        bpf_printk("  REMOTE: %pI6c:%u", sinfo->raddr, sinfo->rport);
    }
    if (is_app_port[APP_DNS])
        bpf_printk("  DNS MESSAGE: %u  TRANSACTION ID: %u  LEN: %u", num, bpf_ntohs(*(__u16 *)sinfo->app_msg.data[num]),
                   sinfo->app_msg.len[num]);
    bpf_printk("  TOTAL: TX %lu   RX %lu\n", sinfo->tx_bytes, sinfo->rx_bytes);

    return 0;
}

/* kprobe for new udp sockets */
SEC("kprobe/udp_init_sock")
int BPF_KPROBE(udp_init_sock, struct sock *sock) {
    KPROBE_SWITCH(MONITOR_SOCK);
    return 0;
}

/* kprobe for udp socket rx events */
SEC("kprobe/skb_consume_udp")
int BPF_KPROBE(skb_consume_udp, struct sock *sock, struct sk_buff *skb, int len) {
    KPROBE_SWITCH(MONITOR_SOCK);
    u16 family;
    if (BPF_CORE_READ(skb, protocol) == bpf_htons(ETH_P_IP))
        family = AF_INET;
    else if (BPF_CORE_READ(skb, protocol) == bpf_htons(ETH_P_IPV6))
        family = AF_INET6;
    if (!sock)
        sock = BPF_CORE_READ(skb, sk);

    if (len < 0 || !(family == AF_INET || family == AF_INET6))
        return 0;

    struct SOCK_EVENT_INFO event = {sock, skb, family, 0, 0, NULL, true, "skb_consume_udp"};
    handle_udp_event(ctx, &event);

    return 0;
}

/* kprobe for udp v4 socket tx events */
SEC("kprobe/udp_send_skb")
int BPF_KPROBE(udp_send_skb, struct sk_buff *skb, struct flowi4 *fl4, struct inet_cork *cork) {
    KPROBE_SWITCH(MONITOR_SOCK);
    __u16        family = BPF_CORE_READ(skb, sk, __sk_common.skc_family);
    struct sock *sock = BPF_CORE_READ(skb, sk);
    __u16        sport = bpf_ntohs(BPF_CORE_READ(fl4, uli.ports.sport));
    __u16        dport = bpf_ntohs(BPF_CORE_READ(fl4, uli.ports.dport));

    if (!sock || family != AF_INET)
        return 0;

    struct SOCK_EVENT_INFO event = {sock, skb, family, sport, dport, NULL, false, "udp_send_skb"};
    handle_udp_event(ctx, &event);

    return 0;
}

/* kprobe for udp v6 socket tx events */
SEC("kprobe/udp_v6_send_skb")
int BPF_KPROBE(udp_v6_send_skb, struct sk_buff *skb, struct flowi6 *fl6, struct inet_cork *cork) {
    KPROBE_SWITCH(MONITOR_SOCK);
    __u16        family = BPF_CORE_READ(skb, sk, __sk_common.skc_family);
    struct sock *sock = BPF_CORE_READ(skb, sk);
    __u16        sport = bpf_ntohs(BPF_CORE_READ(fl6, uli.ports.sport));
    __u16        dport = bpf_ntohs(BPF_CORE_READ(fl6, uli.ports.dport));

    if (!sock || family != AF_INET6)
        return 0;

    struct SOCK_EVENT_INFO event = {sock, skb, family, sport, dport, NULL, false, "udp_v6_send_skb"};
    handle_udp_event(ctx, &event);

    return 0;
}

/* socket filter used to capture large tcp data packets */
SEC("socket")
int handle_skb(struct __sk_buff *skb) {
    __u16              eth_proto;
    __u16              family;
    __u32              proto = 0;
    __u16              ip_len;
    __u8               iphdr_len;
    __u16              frag_ofs;
    __u32              tcphdr_ofs;
    __u8               tcphdr_len;
    __u32              udphdr_ofs;
    __u8               udphdr_len;
    __u32              data_ofs;
    __u32              data_len = 0;
    __u8               laddr[IP_ADDR_LEN_MAX] = {0};
    __u8               raddr[IP_ADDR_LEN_MAX] = {0};
    __u16              lport;
    __u16              rport;
    __u16              sport;
    __u16              dport;
    bool               is_app_port[APP_MAX] = {0};
    struct SOCK_INFO  *sinfo;
    struct SOCK_TUPLE *stuple;
    __u32              zero = 0;
    __u64              key = 0;
    __u64             *pkey = NULL;
    __u32              cnt;
    __u32              cntp;
    __u32              cnta;
    __u8               num;
    bool               found = false;

    /* get ethernet protocol */
    bpf_skb_load_bytes(skb, 12, &eth_proto, 2);
    eth_proto = __bpf_ntohs(eth_proto);
    if (eth_proto != ETH_P_IP)
        return skb->len;
    // tbd: AF_INET6
    family = AF_INET;

    /* check fragmentation */
    bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, frag_off), &frag_ofs, 2);
    frag_ofs = __bpf_ntohs(frag_ofs);
    if (frag_ofs & (IP_MF | IP_OFFMASK))
        return skb->len;

    /* get ip protocol */
    bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, protocol), &proto, 1);
    if (proto != IPPROTO_TCP)
        return skb->len;

    /* get ip header len */
    bpf_skb_load_bytes(skb, ETH_HLEN, &iphdr_len, sizeof(iphdr_len));
    iphdr_len &= 0x0f;
    iphdr_len *= 4;
    if (iphdr_len < sizeof(struct iphdr))
        return skb->len;

    /* get ip source and dest addresses */
    bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, tot_len), &ip_len, sizeof(ip_len));
    ip_len = __bpf_ntohs(ip_len);
    bool isrx = (skb->ingress_ifindex == skb->ifindex);
    bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, saddr), isrx ? raddr : laddr, 4);
    bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, daddr), isrx ? laddr : raddr, 4);

    /* get tcp source and dest ports */
    tcphdr_ofs = ETH_HLEN + iphdr_len;
    bpf_skb_load_bytes(skb, tcphdr_ofs + offsetof(struct tcphdr, ack_seq) + 4, &tcphdr_len, sizeof(tcphdr_len));
    tcphdr_len &= 0xf0;
    tcphdr_len >>= 4;
    tcphdr_len *= 4;
    bpf_skb_load_bytes(skb, tcphdr_ofs + offsetof(struct tcphdr, source), &sport, 2);
    bpf_skb_load_bytes(skb, tcphdr_ofs + offsetof(struct tcphdr, dest), &dport, 2);
    data_ofs = ETH_HLEN + iphdr_len + tcphdr_len;
    if (ip_len > iphdr_len + tcphdr_len)
        data_len = ip_len - (iphdr_len + tcphdr_len);
    else
        return skb->len;
    if (data_len < APP_MSG_LEN_MIN || data_len > APP_MSG_LEN_MAX)
        return skb->len;

    /* check data length and dns port */
    lport = bpf_ntohs(isrx ? dport : sport);
    rport = bpf_ntohs(isrx ? sport : dport);
    for (cnta = 0; cnta < APP_MAX; cnta++) {
        for (cntp = 0; cntp < APP_PORT_MAX; cntp++) {
            if (proto == app_proto[cnta][cntp] && (lport == app_port[cnta][cntp] || rport == app_port[cnta][cntp])) {
                is_app_port[cnta] = true;
                found = true;
                break;
            }
        }
        if (found)
            break;
    }
    if (!found)
        return skb->len;

    /* lookup socket via stuple */
    stuple = bpf_map_lookup_elem(&heap_tuple, &zero);
    if (!stuple)
        return skb->len;
    bpf_probe_read_kernel(stuple->laddr, sizeof(stuple->laddr), laddr);
    bpf_probe_read_kernel(stuple->raddr, sizeof(stuple->raddr), raddr);
    stuple->lport = lport;
    stuple->rport = rport;
    stuple->proto = proto;
    pkey = bpf_map_lookup_elem(&hash_tuples, stuple);
    if (!pkey) {
        bpf_printk("WARNING: Failed to lookup tcp socket for tuple\n");
        return skb->len;
    }
    bpf_probe_read_kernel(&key, sizeof(key), pkey);
    sinfo = bpf_map_lookup_elem(&hash_socks, &key);
    if (!sinfo) {
        bpf_printk("WARNING: Failed to lookup tcp socket %lx\n", key);
        return skb->len;
    }

    /* capture payloads */
    num = sinfo->app_msg.cnt++;
    if (num >= APP_MSG_MAX) {
        bpf_printk("WARNING: Failed to capture %u application messages\n", num);
        return skb->len;
    } else if (!num)
        sinfo->app_msg.type = cnta;

    sinfo->app_msg.ts[num] = bpf_ktime_get_ns();
    sinfo->app_msg.len[num] = data_len;
    sinfo->app_msg.isrx[num] = isrx;
    bpf_skb_load_bytes(skb, data_ofs, sinfo->app_msg.data[num], MIN(data_len, sizeof(sinfo->app_msg.data[num]) - 1));
    if (!bpf_map_update_elem(&hash_socks, &key, sinfo, BPF_ANY)) {
        if (debug_proc(sinfo->comm, NULL))
            bpf_printk("Captured payload for %s socket %lx and pid %u", GET_ROLE_STR(sinfo->role), key, sinfo->pid);
    } else
        bpf_printk("WARNING: Failed to capture payload for %s socket %lx and pid %u\n", GET_ROLE_STR(sinfo->role), key,
                   sinfo->pid);

    /* debug for socket filter */
    if (debug_proc(sinfo->comm, NULL)) {
        bpf_printk("HANDLE_SKB %s:", isrx ? "RX" : "TX");
        bpf_printk("  PID: %u  KEY: %lx", sinfo->pid, key);
        bpf_printk("  PROTO: %u  FAMILY: %u ", sinfo->proto, sinfo->family);
        if (family == AF_INET) {
            bpf_printk("  LOCAL:  %pI4:%u", laddr, lport);
            bpf_printk("  REMOTE: %pI4:%u", raddr, rport);
        } else {
            bpf_printk("  LOCAL:  %pI6c:%u", laddr, lport);
            bpf_printk("  REMOTE: %pI6c:%u", raddr, rport);
        }
        bpf_printk("  APP:  MESSAGE %u  LEN %u", num, sinfo->app_msg.len[num]);
    }

    return skb->len;
}

/* DEBUG */
/* debug helper function to dump kernel stack */
static long                 debug_stack[MAX_STACK_TRACE_DEPTH] = {0};
static __always_inline void debug_dump_stack(void *ctx, const char *func) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    long                kstacklen;
    __u32               cnt;

    kstacklen = bpf_get_stack(ctx, debug_stack, MAX_STACK_TRACE_DEPTH * sizeof(long), 0);
    if (kstacklen > 0) {
        bpf_printk("KERNEL STACK (%u): %s  ", (kstacklen / sizeof(long)), func);
        for (cnt = 0; cnt < MAX_STACK_TRACE_DEPTH; cnt++) {
            if (kstacklen > cnt * sizeof(long)) /* check needed for bpf verifier */
                bpf_printk("  %pB", (void *)debug_stack[cnt]);
        }
    }
}

/* debug helper function to detect trace pipe */
bool debug_file_is_tp(char *filename) {
    char tp[] = "trace_pipe";
    int  cnt;

    /* check file for trace_pipe */
    if (filename) {
        for (cnt = 0; cnt < DBG_LEN_MAX; cnt++) /* strcmp not available */
            if (filename[cnt] != tp[cnt])
                break;
            else if (cnt == sizeof(tp) - 1)
                return true;
    }

    return false;
}

/* debug helper function to print debug messages based on process */
bool debug_proc(char *comm, char *filename) {
    int cnt;

    /* filter debug prints on queue when comm is null */
    if (!comm) {
        if (debug[0] == 'q' && !debug[1])
            return true;
        else
            return false;
    }

    /* filter debug prints on process name */
    if (debug[0] != '*')
        for (cnt = 0; cnt < DBG_LEN_MAX; cnt++) /* strcmp not available */
            if (!comm[0] || comm[cnt] != debug[cnt])
                return false;

    /* always omit debug for trace_pipe file itself */
    if (debug_file_is_tp(filename))
        return false;

    return true;
}

#if 0
/* debug kprobe to detect file events using fsnotify userspace api */
SEC("kprobe/fsnotify")
int BPF_KPROBE(fsnotify, __u32 mask, void *data, int data_type, struct inode *inoded, const struct qstr *file_name) {
    struct inode       *inode;
    struct task_struct *task;
    struct event       *e;
    __u8                comm[TASK_COMM_LEN];
    pid_t               pid;
    __u32               uid;
    __u32               gid;
    __u32               ino;
    umode_t             imode;
    __u64               key;
    __u32               zero = 0;
    int                 index = -1;
    __u32               cnt;

    if (!(file_name && (data_type == FSNOTIFY_EVENT_INODE || data_type == FSNOTIFY_EVENT_PATH)))
        return 0;
    for (cnt = 0; cnt < FS_EVENT_MAX; ++cnt)
        if (mask & fsevt[cnt].value)
            index = cnt;
    if (index < 0)
        return 0;

    /* get comm, pid, uid and gid */
    bpf_get_current_comm(comm, sizeof(comm));
    pid = bpf_get_current_pid_tgid() >> 32;
    uid = bpf_get_current_uid_gid() >> 32;
    gid = bpf_get_current_uid_gid();

    /* get inode from data */
    if (data_type == FSNOTIFY_EVENT_INODE) {
        inode = (struct inode *)data;
    } else if (data_type == FSNOTIFY_EVENT_PATH) {
        struct path *path = (struct path *)data;
        inode = BPF_CORE_READ(path, dentry, d_inode);
    }
    ino = BPF_CORE_READ(inode, i_ino);

    /* validate inode mode (file or link)) */
    imode = BPF_CORE_READ(inode, i_mode);
    if (!(S_ISREG(imode) || S_ISLNK(imode)))
        return 0;

    bpf_printk("FS_NOTIFY: %s (ino=%u)", BPF_CORE_READ(file_name, name), ino);
    debug_dump_stack(ctx, "FS_NOTIFY");

    return 0;
}
#endif

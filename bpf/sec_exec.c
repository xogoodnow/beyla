#include "vmlinux.h"
#include "common.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_dbg.h"
#include "sec.h"
#include "ringbuf.h"
#include "sec_sock_info.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_CONCURRENT_REQUESTS 10000

// Force emitting struct sec_event_t into the ELF for automatic creation of Golang struct
const sec_event_t *unused __attribute__((unused));

#if defined(__TARGET_ARCH_arm64)
// Copied from Linux include/uapi/asm/ptrace.h to make ARM64 happy
struct user_pt_regs {
	u64		regs[31];
	u64		sp;
	u64		pc;
	u64		pstate;
};
#endif

// Track PID to executable on exec, so we can report the command on exit
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __type(key, u32);
    __type(value, char[MAX_STR_LEN]);
} active_pids SEC(".maps");

// Temporary tracking of accept arguments
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __type(key, u64);
    __type(value, sock_args_t);
} active_accept_args SEC(".maps");

// Temporary tracking of connect arguments
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __type(key, u64);
    __type(value, sock_args_t);
} active_connect_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, connection_info_t);
    __type(value, sec_event_meta_t); 
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} filtered_connections SEC(".maps");

static __always_inline void execve_event(const char *filename, const char *const *argv, u8 op) {
    sec_event_t *event = bpf_ringbuf_reserve(&events, sizeof(sec_event_t), 0);
    if (event) {
        make_sec_meta(&event->meta);
        print_sec_meta(&event->meta);
        event->meta.op = op;
        unsigned char *b = &(event->buf[0]);
        unsigned char *end = &(event->buf[EVENT_BUF_LEN]);

        int len = bpf_probe_read_str(event->filename, MAX_STR_LEN, filename);
        if (len > 0) {
            char executable[MAX_STR_LEN];
            bpf_probe_read_str(executable, MAX_STR_LEN, filename);
            u32 pid = event->meta.pid;
            bpf_map_update_elem(&active_pids, &pid, &executable, BPF_ANY); // On purpose BPF_ANY, we want to overwrite stal
        }                

        #pragma unroll
        // skip first argument
        for (int i = 1; i < MAX_ARR_CNT; i++) {
            const char *argp = NULL;
            bpf_probe_read(&argp, sizeof(argp), &argv[i]);

            if (!argp) {
                bpf_dbg_printk("Stopped reading at argv index %d", i);
                goto out;
            }

            if (b >= end) {
                goto out;
            }

            if (b != event->buf) {
                *(b++) = ' ';
            }

            if ((b + MAX_STR_LEN) > end) {
                goto out;
            }

            int len = bpf_probe_read_str(b, MAX_STR_LEN, argp);
            if (len > 0) {
                b += (u16)(len-1); // ignore the null terminator
            }
        }

        if (b < end) {
            *b = '\0';
        }
out:
        bpf_dbg_printk("Command [%s]", event->buf);
        bpf_ringbuf_submit(event, get_flags());
    }
}


SEC("tracepoint/syscalls/sys_enter_execve")
int syscall_enter_execve(struct execve_args *ctx) {
    bpf_dbg_printk("=== tracepoint/syscalls/sys_enter_execve ===");
    execve_event(ctx->filename, ctx->argv, OP_EXECVE);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int syscall_enter_execveat(struct execveat_args *ctx) {
    bpf_dbg_printk("=== tracepoint/syscalls/sys_enter_execveat ===");
    execve_event(ctx->filename, ctx->argv, OP_EXECVEAT);
    return 0;
}

SEC("kprobe/sys_execve")
int kprobe_sys_execve(struct pt_regs *ctx) {
    struct pt_regs * __ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);
    void *filename;
    bpf_probe_read(&filename, sizeof(void *), (void *)&PT_REGS_PARM1(__ctx));
    void *argv;
    bpf_probe_read(&argv, sizeof(void *), (void *)&PT_REGS_PARM2(__ctx));
    execve_event((char *)filename, (const char *const *)argv, OP_EXECVE);

    return 0;
}

SEC("kprobe/sys_execveat")
int kprobe_sys_execveat(struct pt_regs *ctx) {
    struct pt_regs * __ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);
    void *filename;
    bpf_probe_read(&filename, sizeof(void *), (void *)&PT_REGS_PARM2(__ctx));
    void *argv;
    bpf_probe_read(&argv, sizeof(void *), (void *)&PT_REGS_PARM3(__ctx));
    execve_event((char *)filename, (const char *const *)argv, OP_EXECVEAT);

    return 0;
}

SEC("kprobe/do_task_dead")
int BPF_KPROBE(kprobe_do_task_dead) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct signal_struct *signal = BPF_CORE_READ(task, signal);
    atomic_t live = BPF_CORE_READ(signal, live);

    if (live.counter == 0) {
        bpf_dbg_printk("=== sys_exit ===");

        sec_event_t *event = bpf_ringbuf_reserve(&events, sizeof(sec_event_t), 0);
        if (event) {
            make_sec_meta(&event->meta);
            print_sec_meta(&event->meta);
            event->meta.op = OP_EXIT;

            u32 pid = event->meta.pid;
            char *executable = bpf_map_lookup_elem(&active_pids, &pid);
            if (executable) {
                bpf_probe_read_str(event->buf, MAX_STR_LEN, executable);
            }

            bpf_ringbuf_submit(event, get_flags());
        }
    }

    return 0;
}


SEC("kprobe/wake_up_new_task")
int BPF_KPROBE(kprobe_wake_up_new_task) {
    bpf_dbg_printk("=== sys_fork ===");

    sec_event_t *event = bpf_ringbuf_reserve(&events, sizeof(sec_event_t), 0);
    if (event) {
        make_sec_meta(&event->meta);
        print_sec_meta(&event->meta);
        event->meta.op = OP_FORK;

        u32 pid = event->meta.pid;
        char *executable = bpf_map_lookup_elem(&active_pids, &pid);
        if (executable) {
            bpf_probe_read_str(event->buf, MAX_STR_LEN, executable);
        }

        bpf_ringbuf_submit(event, get_flags());
    }

    return 0;
}

#if defined(bpf_target_x86)
#define KERN_REGS_PARM4(x) ((x)->r10)
#else
#define KERN_REGS_PARM4(x) (PT_REGS_PARM4(x))
#endif

SEC("kprobe/sys_rename")
int kprobe_sys_rename(struct pt_regs *ctx) {
    bpf_dbg_printk("=== sys_rename ===");

    struct pt_regs * __ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);
    void *oldpath;
    void *newpath;
    bpf_probe_read(&oldpath, sizeof(void *), (void *)&PT_REGS_PARM1(__ctx));
    bpf_probe_read(&newpath, sizeof(void *), (void *)&PT_REGS_PARM2(__ctx));

    sec_event_t *event = bpf_ringbuf_reserve(&events, sizeof(sec_event_t), 0);
    if (event) {
        make_sec_meta(&event->meta);
        print_sec_meta(&event->meta);
        event->meta.op = OP_RENAME;

        bpf_probe_read_str(event->filename, MAX_STR_LEN, oldpath);
        bpf_probe_read_str(event->buf, MAX_STR_LEN, newpath);

        bpf_dbg_printk("oldpath = %s, newpath = %s", event->filename, event->buf);

        bpf_ringbuf_submit(event, get_flags());
    }

    return 0;
}



SEC("kprobe/sys_renameat")
int kprobe_sys_renameat(struct pt_regs *ctx) {
    bpf_dbg_printk("=== sys_renameat ===");

    struct pt_regs * __ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);
    void *oldpath;
    void *newpath;
    bpf_probe_read(&oldpath, sizeof(void *), (void *)&PT_REGS_PARM2(__ctx));
    bpf_probe_read(&newpath, sizeof(void *), (void *)&KERN_REGS_PARM4(__ctx));

    sec_event_t *event = bpf_ringbuf_reserve(&events, sizeof(sec_event_t), 0);
    if (event) {
        make_sec_meta(&event->meta);
        print_sec_meta(&event->meta);
        event->meta.op = OP_RENAMEAT;

        bpf_probe_read_str(event->filename, MAX_STR_LEN, oldpath);
        bpf_probe_read_str(event->buf, MAX_STR_LEN, newpath);

        bpf_dbg_printk("oldpath = %s, newpath = %s", event->filename, event->buf);

        bpf_ringbuf_submit(event, get_flags());
    }

    return 0;
}

SEC("kprobe/sys_unlink")
int kprobe_sys_unlink(struct pt_regs *ctx) {
    bpf_dbg_printk("=== sys_unlink ===");

    struct pt_regs * __ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);
    void *path;
    bpf_probe_read(&path, sizeof(void *), (void *)&PT_REGS_PARM1(__ctx));

    sec_event_t *event = bpf_ringbuf_reserve(&events, sizeof(sec_event_t), 0);
    if (event) {
        make_sec_meta(&event->meta);
        print_sec_meta(&event->meta);
        event->meta.op = OP_UNLINK;

        bpf_probe_read_str(event->filename, MAX_STR_LEN, path);

        bpf_ringbuf_submit(event, get_flags());
    }

    return 0;
}

SEC("kprobe/sys_unlinkat")
int kprobe_sys_unlinkat(struct pt_regs *ctx) {
    bpf_dbg_printk("=== sys_unlinkat ===");

    struct pt_regs * __ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);
    void *path;
    bpf_probe_read(&path, sizeof(void *), (void *)&PT_REGS_PARM2(__ctx));

    sec_event_t *event = bpf_ringbuf_reserve(&events, sizeof(sec_event_t), 0);
    if (event) {
        make_sec_meta(&event->meta);
        print_sec_meta(&event->meta);
        event->meta.op = OP_UNLINKAT;

        bpf_probe_read_str(event->filename, MAX_STR_LEN, path);

        bpf_ringbuf_submit(event, get_flags());
    }

    return 0;
}

SEC("kprobe/sys_creat")
int kprobe_sys_creat(struct pt_regs *ctx) {
    bpf_dbg_printk("=== sys_creat ===");

    struct pt_regs * __ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);
    void *path;
    bpf_probe_read(&path, sizeof(void *), (void *)&PT_REGS_PARM1(__ctx));

    sec_event_t *event = bpf_ringbuf_reserve(&events, sizeof(sec_event_t), 0);
    if (event) {
        make_sec_meta(&event->meta);
        print_sec_meta(&event->meta);
        event->meta.op = OP_CREAT;

        bpf_probe_read_str(event->filename, MAX_STR_LEN, path);

        bpf_ringbuf_submit(event, get_flags());
    }

    return 0;
}

SEC("kprobe/sys_open")
int kprobe_sys_open(struct pt_regs *ctx) {
    bpf_dbg_printk("=== sys_open ===");

    struct pt_regs * __ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);
    void *path;
    bpf_probe_read(&path, sizeof(void *), (void *)&PT_REGS_PARM1(__ctx));

    sec_event_t *event = bpf_ringbuf_reserve(&events, sizeof(sec_event_t), 0);
    if (event) {
        make_sec_meta(&event->meta);
        print_sec_meta(&event->meta);
        event->meta.op = OP_OPEN;

        bpf_probe_read_str(event->filename, MAX_STR_LEN, path);

        bpf_ringbuf_submit(event, get_flags());
    }

    return 0;
}

SEC("kprobe/sys_openat")
int kprobe_sys_openat(struct pt_regs *ctx) {
    bpf_dbg_printk("=== sys_openat ===");

    struct pt_regs * __ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);
    void *path;
    bpf_probe_read(&path, sizeof(void *), (void *)&PT_REGS_PARM2(__ctx));

    sec_event_t *event = bpf_ringbuf_reserve(&events, sizeof(sec_event_t), 0);
    if (event) {
        make_sec_meta(&event->meta);
        print_sec_meta(&event->meta);
        event->meta.op = OP_OPENAT;

        bpf_probe_read_str(event->filename, MAX_STR_LEN, path);

        bpf_ringbuf_submit(event, get_flags());
    }

    return 0;
}

SEC("socket/http_filter")
int socket__http_filter(struct __sk_buff *skb) {
    protocol_info_t proto = {};
    connection_info_t conn = {};

    if (!read_sk_buff(skb, &proto, &conn)) {
        //bpf_printk("Can't read sk_buff, this is a bug");
        return 0;
    }

    sort_connection_info(&conn);
    sec_event_meta_t *meta = bpf_map_lookup_elem(&filtered_connections, &conn);

    if (meta) {
        sec_event_t *event = bpf_ringbuf_reserve(&events, sizeof(sec_event_t), 0);
        if (event) {
            event->meta = *meta;
            event->conn = conn;
            event->type = proto.type;

            bpf_dbg_printk("SENDING NET EVENT");
            dbg_print_http_connection_info(&event->conn);
            print_sec_meta(&event->meta);

            bpf_ringbuf_submit(event, get_flags());
        }
    } else {
        bpf_printk("Cannot find filtered connection, this is a bug, type = %d!", proto.type);
        dbg_print_http_connection_info(&conn);
    }

    return 0;
}


// Used by accept to grab the sock details
SEC("kretprobe/sock_alloc")
int BPF_KRETPROBE(kretprobe_sock_alloc, struct socket *sock) {
    u64 id = bpf_get_current_pid_tgid();

    u64 addr = (u64)sock;

    sock_args_t args = {};

    args.addr = addr;

    // The socket->sock is not valid until accept finishes, therefore
    // we don't extract ->sock here, we remember the address of socket
    // and parse in sys_accept
    bpf_map_update_elem(&active_accept_args, &id, &args, BPF_ANY);

    return 0;
}

// We tap into accept and connect to figure out if a request is inbound or
// outbound. However, in some cases servers can optimise the accept path if
// the same request is sent over and over. For that reason, in case we miss the
// initial accept, we establish an active filtered connection here. By default
// sets the type to be server HTTP, in client mode we'll overwrite the 
// data in the map, since those cannot be optimised.
SEC("kprobe/tcp_rcv_established")
int BPF_KPROBE(kprobe_tcp_rcv_established, struct sock *sk, struct sk_buff *skb) {
    connection_info_t info = {};

    if (parse_sock_info(sk, &info)) {
        sort_connection_info(&info);
        //dbg_print_http_connection_info(&info);

        sec_event_meta_t meta = {};
        make_sec_meta(&meta);
        meta.op = OP_NET_SRV;

        bpf_map_update_elem(&filtered_connections, &info, &meta, BPF_NOEXIST); // On purpose BPF_NOEXIST
    }

    return 0;
}

// We tap into both sys_accept and sys_accept4.
// We don't care about the accept entry arguments, since we get only peer information
// we don't have the full picture for the socket.
// 
// Note: A current limitation is that likely we won't capture the first accept request. The
// process may have already reached accept, before the instrumenter has launched.
SEC("kretprobe/sys_accept4")
int BPF_KRETPROBE(kretprobe_sys_accept4, uint fd)
{
    u64 id = bpf_get_current_pid_tgid();

    bpf_dbg_printk("=== accept 4 ret id=%d ===", id);

    // The file descriptor is the value returned from the accept4 syscall.
    // If we got a negative file descriptor we don't have a connection
    if ((int)fd < 0) {
        goto cleanup;
    }

    sock_args_t *args = bpf_map_lookup_elem(&active_accept_args, &id);
    if (!args) {
        //bpf_dbg_printk("No sock info %d", id);
        goto cleanup;
    }

    connection_info_t info = {};

    if (parse_accept_socket_info(args, &info)) {
        sort_connection_info(&info);
        dbg_print_http_connection_info(&info);

        sec_event_meta_t meta = {};
        make_sec_meta(&meta);
        meta.op = OP_NET_SRV;

        bpf_map_update_elem(&filtered_connections, &info, &meta, BPF_ANY); // On purpose BPF_ANY, we want to overwrite stale
    }

cleanup:
    bpf_map_delete_elem(&active_accept_args, &id);
    return 0;
}

// Used by connect so that we can grab the sock details
SEC("kprobe/tcp_connect")
int BPF_KPROBE(kprobe_tcp_connect, struct sock *sk) {
    u64 id = bpf_get_current_pid_tgid();

    u64 addr = (u64)sk;

    sock_args_t args = {};

    args.addr = addr;

    bpf_map_update_elem(&active_connect_args, &id, &args, BPF_ANY);

    connection_info_t info = {};

    if (parse_connect_sock_info(&args, &info)) {
        sort_connection_info(&info);
        dbg_print_http_connection_info(&info);

        sec_event_meta_t meta = {};
        make_sec_meta(&meta);
        meta.op = OP_NET_CLIENT;

        bpf_map_update_elem(&filtered_connections, &info, &meta, BPF_ANY); // On purpose BPF_ANY, we want to overwrite stale
    }


    return 0;
}

// We tap into sys_connect so we can track properly the processes doing
// HTTP client calls
SEC("kretprobe/sys_connect")
int BPF_KRETPROBE(kretprobe_sys_connect, int fd)
{
    u64 id = bpf_get_current_pid_tgid();

    // The file descriptor is the value returned from the connect syscall.
    // If we got a negative file descriptor we don't have a connection, unless we are in progress
    if (fd < 0 && (fd != -EINPROGRESS)) {
        goto cleanup;
    }

    sock_args_t *args = bpf_map_lookup_elem(&active_connect_args, &id);
    if (!args) {
        bpf_dbg_printk("No sock info %d", id);
        goto cleanup;
    }

    connection_info_t info = {};

    if (parse_connect_sock_info(args, &info)) {
        sort_connection_info(&info);
        dbg_print_http_connection_info(&info);

        sec_event_meta_t meta = {};
        make_sec_meta(&meta);
        meta.op = OP_NET_CLIENT;

        bpf_map_update_elem(&filtered_connections, &info, &meta, BPF_ANY); // On purpose BPF_ANY, we want to overwrite stale
    }

cleanup:
    bpf_map_delete_elem(&active_connect_args, &id);
    return 0;
}

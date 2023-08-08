#include "vmlinux.h"
#include "common.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_dbg.h"
#include "sec.h"
#include "ringbuf.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_ARR_CNT 30

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


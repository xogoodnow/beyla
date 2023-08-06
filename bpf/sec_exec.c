#include "vmlinux.h"
#include "common.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_dbg.h"
#include "sec.h"
#include "ringbuf.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_STR_LEN 256
#define MAX_ARR_CNT 30

#if defined(__TARGET_ARCH_arm64)
// Copied from Linux include/uapi/asm/ptrace.h to make ARM64 happy
struct user_pt_regs {
	u64		regs[31];
	u64		sp;
	u64		pc;
	u64		pstate;
};
#endif

static __always_inline void execve_event(const char *filename, const char *const *argv) {
    sec_event_t *event = bpf_ringbuf_reserve(&events, sizeof(sec_event_t), 0);
    if (event) {
        make_sec_meta(&event->meta);
        print_sec_meta(&event->meta);
        char *b = &(event->buf[0]);
        char *end = &(event->buf[EVENT_BUF_LEN]);

        int len = bpf_probe_read_str(b, MAX_STR_LEN, filename);
        if (len > 0) {
            b += (u16)(len-1); // ignore the null terminator
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

            *(b++) = ' ';

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
    execve_event(ctx->filename, ctx->argv);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int syscall_enter_execveat(struct execveat_args *ctx) {
    bpf_dbg_printk("=== tracepoint/syscalls/sys_enter_execveat ===");
    execve_event(ctx->filename, ctx->argv);
    return 0;
}

SEC("kprobe/do_task_dead")
int BPF_KPROBE(kprobe_do_task_dead) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct signal_struct *signal = BPF_CORE_READ(task, signal);
    atomic_t live = BPF_CORE_READ(signal, live);

    if (live.counter == 0) {
        sec_event_meta_t meta = {};

        bpf_dbg_printk("=== sys_exit ===");

        make_sec_meta(&meta);
        print_sec_meta(&meta);
    }

    return 0;
}


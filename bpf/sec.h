#ifndef SEC_H
#define SEC_H

#include "common.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "pid.h"
#include "http_defs.h"

#define OP_EXECVE 1
#define OP_EXECVEAT 2
#define OP_EXIT 3
#define OP_NET_SRV 4
#define OP_NET_CLIENT 5
#define OP_FORK 6
#define OP_RENAME 7
#define OP_RENAMEAT 8
#define OP_UNLINK 9
#define OP_UNLINKAT 10

#define CGRP_NAME_LEN 128
#define EVENT_BUF_LEN 2048
#define MAX_STR_LEN 256

typedef struct connection_info {
    u8 s_addr[IP_V6_ADDR_LEN];
    u8 d_addr[IP_V6_ADDR_LEN];
    u16 s_port;
    u16 d_port;
} connection_info_t;

typedef struct sec_event_meta {
    u8  op;       // Event type
    u32 pid;      // Process TGID
    u32 tid;      // Process thread id
    u32 ppid;     // Parent process TGID
    u32 uid;      // Current UID
    u32 auid;     // Current Audit UID
    u32 ns_pid;   // Namespaced PID for containers
    u32 ns_ppid;  // Namespaced parent TGID
    u32 pid_ns_id;// PID namespace id
    u64 time_ns;  // Kernel time when this happened in nanos
    u64 cap_eff;  // Subjective task effective capabilities
    u64 cap_inh;  // Subjective task inherited capabilities
    u64 cap_perm; // Subjective task permitted capabilities
    u32 cgrp_id;  // The cgroup_id 
    u32 net_ns;   // The network namespace 
    unsigned char cgrp_name[CGRP_NAME_LEN]; // Cgroup name
    unsigned char comm[16];// Current command
} sec_event_meta_t; 

typedef struct sec_event {
    sec_event_meta_t meta;
    unsigned char filename[MAX_STR_LEN]; // the execve filename
    unsigned char buf[EVENT_BUF_LEN]; // Whatever we capture as data
    u8 type;
    connection_info_t conn;
} sec_event_t;


static __always_inline u64 auid(struct task_struct *task) {
	if (!task) {
		return 0;
    }

	if (bpf_core_field_exists(struct task_struct, loginuid)) {
        kuid_t luid = BPF_CORE_READ(task, loginuid);
        return luid.val;
	} 

	return 0;
}

static __always_inline void capabilities(struct task_struct *task, u64 *permitted, u64 *effective, u64 *inheritable) {
	const struct cred *cred = BPF_CORE_READ(task, cred);
    bpf_probe_read(permitted, sizeof(u64), (void *)&cred->cap_permitted);
    bpf_probe_read(effective, sizeof(u64), (void *)&cred->cap_effective);
    bpf_probe_read(inheritable, sizeof(u64), (void *)&cred->cap_inheritable);
}

static __always_inline struct cgroup *get_task_cgroup(struct task_struct *task) {
	struct cgroup *cgrp = NULL;

    struct css_set *cgroups = BPF_CORE_READ(task, cgroups);
	if (!cgroups) {		
		return cgrp;
	}
	
    struct cgroup_subsys_state *subsys;
    bpf_probe_read(&subsys, sizeof(subsys), &cgroups->subsys[0]);
	if (!subsys) {
		return cgrp;
	}

	bpf_probe_read(&cgrp, sizeof(cgrp), &subsys->cgroup);

	return cgrp;
}

static __always_inline char *get_cgroup_name(struct task_struct *task) {
    struct cgroup *cgrp = get_task_cgroup(task);
    if (!cgrp) {
        return NULL;
    }

	char *name;

	if (BPF_CORE_READ_INTO(&name, cgrp, kn, name) != 0) {
	    return NULL;
    }

    return name;
}

static __always_inline u32 get_net_ns(struct task_struct *task) {
    u32 net_ns;

    BPF_CORE_READ_INTO(&net_ns, task, nsproxy, net_ns, ns.inum);

    return net_ns;
}

static __always_inline void make_sec_meta(sec_event_meta_t *m) {
    u64 pid = bpf_get_current_pid_tgid();
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    int ns_pid = 0;
    int ns_ppid = 0;
    u32 pid_ns_id = 0;

    ns_pid_ppid(task, &ns_pid, &ns_ppid, &pid_ns_id);

    m->pid = pid >> 32;
	m->tid = (u32)pid;
	m->ns_pid = ns_pid;
    m->ns_ppid = ns_ppid;
    m->pid_ns_id = pid_ns_id;
	m->time_ns = bpf_ktime_get_ns();	
	m->auid = auid(task);
	m->uid = bpf_get_current_uid_gid();

    capabilities(task, &m->cap_perm, &m->cap_eff, &m->cap_inh);
    m->cgrp_id = bpf_get_current_cgroup_id();
    char *cgroup_name = get_cgroup_name(task);
    if (cgroup_name) {
        bpf_probe_read_str(m->cgrp_name, CGRP_NAME_LEN, cgroup_name);
    }
    m->net_ns = get_net_ns(task);
    bpf_get_current_comm(&m->comm, sizeof(m->comm));
}

static __always_inline void print_sec_meta(sec_event_meta_t *m) {
    bpf_printk("comm=[%s] pid=[%d] tid=[%d] ns_pid=[%d] ns_ppid=[%d] pid_ns_id=[%u] time_ns=[%lld] uid=[%d] auid=[%d] cap_perm=[%llx] cap_eff=[%llx] cap_inh=[%llx]",
        m->comm, m->pid, m->tid, m->ns_pid, m->ns_ppid, m->pid_ns_id, m->time_ns, m->uid, m->auid, m->cap_perm, m->cap_eff, m->cap_inh
    );
    bpf_printk("cgrp_id=[%d] cgrp_name=[%s] net_ns=[%u]", m->cgrp_id, m->cgrp_name, m->net_ns);
}

// syscall structs

// Based on /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format
struct execve_args {
    short common_type;
    char common_flags;
    char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    char *filename;
    const char *const *argv;
    const char *const *envp;
};

// Based on /sys/kernel/debug/tracing/events/syscalls/sys_enter_execveat/format
struct execveat_args {
    short common_type;
    char common_flags;
    char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    int fd;
    char *filename;
    const char *const *argv;
    const char *const *envp;
    int flags;
};

#endif
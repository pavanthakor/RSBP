#include "headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "headers/rsbp.h"

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

#ifndef __NR_execve
#define __NR_execve 59
#endif

#ifndef __NR_socket
#define __NR_socket 41
#endif

#ifndef __NR_connect
#define __NR_connect 42
#endif

#ifndef __NR_dup2
#define __NR_dup2 33
#endif

#ifndef __NR_dup3
#define __NR_dup3 292
#endif

#ifndef __NR_fork
#define __NR_fork 57
#endif

#ifndef __NR_clone3
#define __NR_clone3 435
#endif

#ifndef __NR_pipe
#define __NR_pipe 22
#endif

#ifndef __NR_pipe2
#define __NR_pipe2 293
#endif

struct pid_fd_key {
    __u32 pid;
    __s32 fd;
};

struct socket_info {
    __u16 family;
    __u16 port;
    __u32 ip4;
    __u8 ip6[16];
};

struct socket_enter_state {
    __u16 family;
    __u16 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct socket_enter_state);
} socket_enter_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 131072);
    __type(key, struct pid_fd_key);
    __type(value, struct socket_info);
} socket_fd_map SEC(".maps");

static __always_inline __u64 read_enter_arg(struct trace_event_raw_sys_enter *ctx, __u32 idx)
{
    __u64 arg = 0;

    if (idx >= 6)
        return 0;

    bpf_probe_read_kernel(&arg, sizeof(arg), &ctx->args[idx]);
    return arg;
}

static __always_inline void fill_common(struct syscall_event *evt, __u32 syscall_nr, __s32 fd)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

    evt->pid = (__u32)(pid_tgid >> 32);
    evt->uid = (__u32)(uid_gid & 0xffffffffULL);
    evt->gid = (__u32)(uid_gid >> 32);
    evt->ppid = BPF_CORE_READ(task, real_parent, tgid);
    evt->syscall_nr = syscall_nr;
    evt->fd = fd;
    evt->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(evt->comm, sizeof(evt->comm));
}

static __always_inline void submit_basic(__u32 syscall_nr, __s32 fd)
{
    struct syscall_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);

    if (!evt)
        return;

    __builtin_memset(evt, 0, sizeof(*evt));
    fill_common(evt, syscall_nr, fd);
    bpf_ringbuf_submit(evt, 0);
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *evt;
    const char *filename = (const char *)read_enter_arg(ctx, 0);
    const char *const *argv = (const char *const *)read_enter_arg(ctx, 1);
    const char *arg0 = 0;

    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    fill_common(evt, __NR_execve, -1);
    evt->has_execve = 1;

    if (filename)
        bpf_probe_read_user_str(evt->exec_path, sizeof(evt->exec_path), filename);

    if (argv) {
        bpf_probe_read_user(&arg0, sizeof(arg0), &argv[0]);
        if (arg0)
            bpf_probe_read_user_str(evt->args, sizeof(evt->args), arg0);
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int trace_exit_execve(struct trace_event_raw_sys_exit *ctx)
{
    submit_basic(__NR_execve, -1);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_socket")
int trace_enter_socket(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    struct socket_enter_state st = {};

    st.family = (__u16)read_enter_arg(ctx, 0);
    bpf_map_update_elem(&socket_enter_map, &pid, &st, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_socket")
int trace_exit_socket(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    struct socket_enter_state *st;
    struct pid_fd_key key = {};
    struct socket_info si = {};
    long ret_fd = -1;

    bpf_probe_read_kernel(&ret_fd, sizeof(ret_fd), &ctx->ret);
    if (ret_fd < 0)
        return 0;

    st = bpf_map_lookup_elem(&socket_enter_map, &pid);
    if (st)
        si.family = st->family;

    key.pid = pid;
    key.fd = (__s32)ret_fd;
    bpf_map_update_elem(&socket_fd_map, &key, &si, BPF_ANY);
    bpf_map_delete_elem(&socket_enter_map, &pid);

    {
        struct syscall_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
        if (!evt)
            return 0;

        __builtin_memset(evt, 0, sizeof(*evt));
        fill_common(evt, __NR_socket, (__s32)ret_fd);
        evt->has_socket = 1;
        evt->family = si.family;
        bpf_ringbuf_submit(evt, 0);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_enter_connect(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __s32 fd = (__s32)read_enter_arg(ctx, 0);
    struct sockaddr *addr = (struct sockaddr *)read_enter_arg(ctx, 1);
    struct pid_fd_key key = {};
    struct socket_info si = {};
    struct syscall_event *evt;

    key.pid = pid;
    key.fd = fd;

    if (addr) {
        __u16 family = 0;
        bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);
        si.family = family;

        if (family == AF_INET) {
            struct sockaddr_in sa4 = {};
            bpf_probe_read_user(&sa4, sizeof(sa4), addr);
            si.port = bpf_ntohs(sa4.sin_port);
            si.ip4 = sa4.sin_addr.s_addr;
        } else if (family == AF_INET6) {
            struct sockaddr_in6 sa6 = {};
            bpf_probe_read_user(&sa6, sizeof(sa6), addr);
            si.port = bpf_ntohs(sa6.sin6_port);
            __builtin_memcpy(si.ip6, sa6.sin6_addr.in6_u.u6_addr8, sizeof(si.ip6));
        }

        bpf_map_update_elem(&socket_fd_map, &key, &si, BPF_ANY);
    }

    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    fill_common(evt, __NR_connect, fd);
    evt->has_connect = 1;
    evt->family = si.family;
    evt->remote_port = si.port;
    evt->remote_ip4 = si.ip4;
    __builtin_memcpy(evt->remote_ip6, si.ip6, sizeof(evt->remote_ip6));
    bpf_ringbuf_submit(evt, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup2")
int trace_enter_dup2(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __s32 oldfd = (__s32)read_enter_arg(ctx, 0);
    __s32 newfd = (__s32)read_enter_arg(ctx, 1);
    struct pid_fd_key key = {.pid = pid, .fd = oldfd};
    struct socket_info *si;
    struct syscall_event *evt;

    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    fill_common(evt, __NR_dup2, oldfd);

    if (newfd == 0 || newfd == 1 || newfd == 2) {
        si = bpf_map_lookup_elem(&socket_fd_map, &key);
        if (si) {
            evt->has_dup2_stdio = 1;
            evt->family = si->family;
            evt->remote_port = si->port;
            evt->remote_ip4 = si->ip4;
            __builtin_memcpy(evt->remote_ip6, si->ip6, sizeof(evt->remote_ip6));
        }
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup3")
int trace_enter_dup3(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __s32 oldfd = (__s32)read_enter_arg(ctx, 0);
    __s32 newfd = (__s32)read_enter_arg(ctx, 1);
    struct pid_fd_key key = {.pid = pid, .fd = oldfd};
    struct socket_info *si;
    struct syscall_event *evt;

    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    fill_common(evt, __NR_dup3, oldfd);

    if (newfd == 0 || newfd == 1 || newfd == 2) {
        si = bpf_map_lookup_elem(&socket_fd_map, &key);
        if (si) {
            evt->has_dup2_stdio = 1;
            evt->family = si->family;
            evt->remote_port = si->port;
            evt->remote_ip4 = si->ip4;
            __builtin_memcpy(evt->remote_ip6, si->ip6, sizeof(evt->remote_ip6));
        }
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fork")
int trace_enter_fork(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *evt;

    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    fill_common(evt, __NR_fork, -1);
    evt->fork_parent_pid = evt->pid;
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_clone3")
int trace_enter_clone3(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *evt;

    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    fill_common(evt, __NR_clone3, -1);
    evt->fork_parent_pid = evt->pid;
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pipe")
int trace_enter_pipe(struct trace_event_raw_sys_enter *ctx)
{
    submit_basic(__NR_pipe, -1);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pipe2")
int trace_enter_pipe2(struct trace_event_raw_sys_enter *ctx)
{
    submit_basic(__NR_pipe2, -1);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

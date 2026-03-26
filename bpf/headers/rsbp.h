#pragma once
struct syscall_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u32 syscall_nr;
    __s32 fd;
    __u32 remote_ip4;
    __u8  remote_ip6[16];
    __u16 remote_port;
    __u16 family;
    __u64 timestamp_ns;
    __u8  comm[16];
    __u8  exec_path[256];
    __u8  args[512];
    __u8  has_execve;
    __u8  has_socket;
    __u8  has_connect;
    __u8  has_dup2_stdio;
    __u32 fork_parent_pid;
    __u32 suspicious_mask;
};

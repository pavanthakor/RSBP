package ebpf

// bpf2go is used so the project can ship architecture-specific object bindings
// while still allowing direct object loading in production deployments.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-15 -cflags "-O2 -g -target bpf -D__TARGET_ARCH_x86 -I../../bpf/headers/" bpf ../../bpf/rsbp.bpf.c

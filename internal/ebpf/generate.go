package ebpf

// bpf2go compiles bpf/rsbp.bpf.c and ships architecture-specific object bindings
// (bpf_bpfel.* / bpf_bpfeb.*) that the loader embeds, so the daemon builds without
// a BPF toolchain. Regeneration needs clang + libbpf development headers
// (Debian/Ubuntu: `apt install clang libbpf-dev`; Fedora: `dnf install clang libbpf-devel`);
// <bpf/bpf_helpers.h> resolves from the system libbpf include path. Override the
// compiler with BPF2GO_CC (e.g. BPF2GO_CC=clang-18). Regenerate only when the C changes.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-O2 -g -target bpf -D__TARGET_ARCH_x86 -I../../bpf/headers/" bpf ../../bpf/rsbp.bpf.c

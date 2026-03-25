#!/usr/bin/env bash

set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Please run as root (sudo)."
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y --no-install-recommends \
  clang-15 \
  libbpf-dev \
  "linux-headers-$(uname -r)" \
  bpftool \
  golang-go \
  ca-certificates \
  make

if [[ ! -f /sys/kernel/btf/vmlinux ]]; then
  echo "ERROR: /sys/kernel/btf/vmlinux not found."
  echo "Your kernel must be built with CONFIG_DEBUG_INFO_BTF=y to generate bpf/headers/vmlinux.h."
  exit 1
fi

mkdir -p bpf/headers
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/headers/vmlinux.h

echo "Dependencies installed for Ubuntu 22.04."

#!/usr/bin/env bash
# RSBP demo setup — idempotent, non-destructive. Prepares a fresh Linux VM so
# `rsbpd run --config config/demo.yaml` starts first time. Safe to re-run.
set -euo pipefail

echo "[setup-demo] RSBP demo environment setup"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "[setup-demo] please run with sudo (needs mount + /var dirs + setcap)" >&2
  exit 1
fi

# 1) tracefs / debugfs — eBPF tracepoint attach needs one of these mounted.
if [[ ! -d /sys/kernel/tracing/events/syscalls && ! -d /sys/kernel/debug/tracing/events/syscalls ]]; then
  echo "[setup-demo] mounting tracefs at /sys/kernel/tracing"
  mount -t tracefs none /sys/kernel/tracing 2>/dev/null || \
    mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
fi
if [[ -d /sys/kernel/tracing/events/syscalls || -d /sys/kernel/debug/tracing/events/syscalls ]]; then
  echo "[setup-demo]   tracepoints: OK"
else
  echo "[setup-demo]   WARNING: tracepoints path still unavailable — eBPF attach may fail" >&2
fi

# 2) runtime directories
install -d -m 0755 /var/log/rsbp /var/lib/rsbp
echo "[setup-demo]   dirs: /var/log/rsbp /var/lib/rsbp OK"

# 3) BTF (informational — required for CO-RE)
if [[ -r /sys/kernel/btf/vmlinux ]]; then
  echo "[setup-demo]   BTF: OK"
else
  echo "[setup-demo]   WARNING: /sys/kernel/btf/vmlinux missing — kernel lacks BTF; use a mainline Ubuntu kernel" >&2
fi

# 4) capabilities on the built binary (so you need not run the daemon as root)
BIN="${1:-bin/rsbpd}"
if [[ -x "$BIN" ]]; then
  if command -v setcap >/dev/null 2>&1; then
    setcap 'cap_bpf,cap_sys_admin,cap_perfmon+ep' "$BIN" 2>/dev/null \
      && echo "[setup-demo]   caps set on $BIN" \
      || echo "[setup-demo]   note: setcap failed; run the daemon with sudo instead"
  fi
else
  echo "[setup-demo]   note: $BIN not built yet — run: CGO_ENABLED=0 go build -o bin/rsbpd ./cmd/rsbpd"
fi

echo "[setup-demo] done. Next:"
echo "  sudo ./bin/rsbpd run --config config/demo.yaml"

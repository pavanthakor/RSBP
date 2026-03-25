# RSBP Project Context For Claude

## What this project is
- Project: RSBP (Reverse Shell Behavior Profiler)
- Language: Go userspace daemon + eBPF C program
- Goal: Detect reverse shell behavior by correlating syscall events (execve, socket, connect, dup2/dup3, etc.) and emitting alerts.

## High-level architecture
- eBPF program in `bpf/rsbp.bpf.c` captures syscall activity and writes `syscall_event` records to a ring buffer.
- Go loader in `internal/ebpf/loader.go` reads ring buffer records and forwards `types.SyscallEvent` into an event channel.
- Correlation logic in `internal/correlation/engine.go` and `internal/correlation/session.go` builds per-process session state.
- Detection logic in `internal/detection/engine.go` evaluates complete sessions and writes alerts.
- Daemon wiring is in `cmd/rsbpd/main.go`.

## What we are building
- A reliable syscall-correlation pipeline that can detect simulated reverse-shell behavior from `test/simulate/attack_sim.sh`.
- Target outcome: non-zero alert generation on simulation while controlling false positives.

## Confirmed recent problem
- Previously observed: many loader events, zero correlation receive logs, zero alerts.
- Root cause for that stage: tracker used a no-op logger path in active wiring, which made correlation receive visibility misleading.
- Pipeline visibility is now fixed: send and receive counts are both present and equal.

## Current state (latest verified)
- Loader to correlation transport is working.
- Latest run showed:
  - `DEBUG_SENDING=429`
  - `DEBUG_CORR_RECEIVED=429`
  - `ALERTS=0`
- This means transport is healthy; problem is now in correlation completion / detection criteria, not channel delivery.

## Key technical findings from logs
- Connect events are now visible for python3 in BPF debug output with `syscall_nr=42` and `has_connect=1`.
- Socket events are visible with `syscall_nr=41` and `has_socket=1`.
- Many shell processes (`sh`, `bash`, `nc`) still show sparse per-PID flag combinations, so parent/child propagation remains critical.

## Important files touched during debugging
- `bpf/rsbp.bpf.c`
  - Updated socket/connect emission behavior.
- `internal/ebpf/loader.go`
  - Added debug marker: `DEBUG SENDING TO CORRELATION`.
- `internal/correlation/engine.go`
  - Added debug marker: `DEBUG CORRELATION RECEIVED`.
  - Added parent-session connect propagation when child emits connect.
- `internal/correlation/session.go`
  - Updated completion logic for reverse-shell tool/connect scenarios.
- `cmd/rsbpd/main.go`
  - Active runtime wiring now uses event buffer 10000.
  - Tracker now uses logger-enabled constructor.

## Reproduction commands used
```bash
make generate && make build

echo 'kali' | sudo -S truncate -s 0 /var/log/rsbp/alerts.jsonl
echo 'kali' | sudo -S ./bin/rsbpd run --config config/rsbp.yaml >/tmp/rsbp.postfix.log 2>&1 &
sleep 3
echo 'kali' | sudo -S ./test/simulate/attack_sim.sh
sleep 5
echo 'kali' | sudo -S pkill rsbpd
sleep 1

wc -l /var/log/rsbp/alerts.jsonl
grep -c 'DEBUG SENDING TO CORRELATION' /tmp/rsbp.postfix.log
grep -c 'DEBUG CORRELATION RECEIVED' /tmp/rsbp.postfix.log
```

## What Claude should focus on next
1. Correlation completeness conditions:
   - Verify `SessionState.IsComplete()` logic against real simulation event shapes.
   - Confirm child-connect propagation is correctly attached to parent sessions in all relevant paths.
2. Detection gating:
   - Inspect score thresholds and whitelist suppression in `internal/detection/engine.go` and whitelist helpers.
   - Determine why complete sessions (if any) still do not emit alerts.
3. Session identity and process-tree linking:
   - Validate PID/PPID stitching from BPF to correlation.
   - Confirm suspicious shell parent session gets connector child network context.
4. Add short-lived focused debug logs:
   - Log complete reason path in `IsComplete()` (which condition failed).
   - Log detection suppression reason (whitelist vs score vs baseline).

## One-line summary for handoff
- We have fixed event transport (loader -> correlation), but simulation still produces zero alerts; next debugging must target correlation completion and detection suppression logic, not channel wiring.

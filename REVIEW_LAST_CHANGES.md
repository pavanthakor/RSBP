# Review: Last Changes

## Findings

1. High: Whitelist suppression moved into correlation completion path can silently drop sessions before detection.
- In `internal/correlation/session.go` around the `IsComplete()` logic, whitelist/path/IP/port checks can return `false` before detection runs.
- Detection already performs whitelist suppression, so this duplication in correlation can hide valid candidates and reduce observability.

2. Medium: Socket syscall now emits ring buffer events on both enter and exit.
- `bpf/rsbp.bpf.c` emits `has_socket=1` in both `trace_enter_socket` and `trace_exit_socket`.
- This can increase event volume and cause early/partial session state transitions.

3. Medium: Parent connect propagation is broad and may taint parent sessions.
- In `internal/correlation/engine.go` sysConnect path, parent session gets `HasConnect=true` and child remote endpoint copied.
- Useful for parent-child correlation, but can increase false positives without tighter guardrails.

4. Medium: Significant behavior changes with limited visible matching test expansion.
- Correlation completion and BPF emission behavior changed materially.
- Additional targeted tests for parent-child connect and loopback/tool exceptions are recommended.

## Open Questions / Assumptions
- Source reviewed is assumed to be the active runtime path.
- Goal assumed: keep suppression primarily in detection layer, not in correlation completeness gating.

## Last Change Snapshot
- Socket enter/exit ringbuf emission updated in `bpf/rsbp.bpf.c`.
- Connect event emission remains explicit with endpoint fields in `bpf/rsbp.bpf.c`.
- Parent-session connect propagation added in `internal/correlation/engine.go`.
- Completion logic updated for RS-tool/connect flows in `internal/correlation/session.go`.
- Main wiring currently shows event buffer 10000 and logger-enabled tracker in `cmd/rsbpd/main.go`.

## Suggested Next Step
- Move whitelist/safe-port suppression out of `IsComplete()` and keep suppression only in detection.
- Re-run simulation to verify whether alert generation recovers while preserving FP controls.

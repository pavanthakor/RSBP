# Reverse Shell Behaviour Profiler (RSBP)

RSBP is a production-oriented Linux security daemon that combines eBPF syscall telemetry with process correlation, reverse-shell detection logic, enrichment, and multi-sink alert delivery.

## Architecture

1. Kernel-space eBPF tracepoints observe syscall activity: `execve`, `socket`, `connect`, `dup2`, `fork`/`clone`, and `pipe`.
2. Userspace collector reads events from a perf ring buffer and keeps per-PID state.
3. Detection engine scores behavior chains consistent with reverse shell tradecraft.
4. Enrichment adds network context, reputation, and command-line risk profiling.
5. Forensics collects `/proc` artifacts for high-confidence alerts.
6. Output fan-out sends structured alerts to JSON/HTTP, Syslog RFC5424, Elasticsearch, Splunk, and Kafka REST.

## Quick Start

```bash
cd /path/to/rsbp

# 1) Install dependencies (clang-15, bpftool, libbpf-dev, headers, Go, make)
chmod +x scripts/install_deps.sh
sudo ./scripts/install_deps.sh

# 2) Generate BPF bindings and object files
make generate

# 3) Build daemon binary
make build

# 4) Run daemon (minimum required runtime flag is --config)
sudo ./bin/rsbpd run --config config/rsbp.yaml

# 5) Verify detections are flowing (in another terminal)
sudo tail -f /var/log/rsbp/alerts.jsonl

# 6) Run test suite
go test ./...
```

## Configuration

Default runtime configuration lives in `config/rsbp.yaml`.

Config discovery order:

1. `./config/rsbp.yaml`
2. `./rsbp.yaml`
3. `/etc/rsbp/rsbp.yaml`

## Design Decisions

- eBPF does only low-level capture and emits compact structs to reduce kernel overhead.
- Correlation and detection remain in userspace for faster iteration and safer rule updates.
- Enrichment and sink delivery are decoupled from kernel collection to isolate external-system latency.
- Forensics runs only for qualifying alerts to control system impact.

## Notes

- Run on Linux with CAP_BPF/CAP_SYS_ADMIN (or root) for tracepoint and BPF map access.
- If tracepoint attachment fails, verify matching kernel headers and `bpftool` availability.

## Production Deployment

### Quick Start
```bash
make build
make install-caps
./scripts/start-rsbp.sh
./scripts/status-rsbp.sh
```

### Monitoring Stack
```bash
cd deployments/monitoring
docker compose up -d
open http://localhost:3000  # Grafana (admin/rsbp123)
open http://localhost:5601  # Kibana
```

### Key Files
| Path | Purpose |
|------|---------|
| /var/log/rsbp/alerts.jsonl | Alert output |
| /var/log/rsbp/daemon.log | Daemon logs |
| /var/lib/rsbp/baseline.json | Behavioral baseline |
| /var/lib/rsbp/forensics/ | Evidence bundles |

### Verify Detection
```bash
sudo ./test/simulate/attack_sim.sh
tail -f /var/log/rsbp/alerts.jsonl | python3 -m json.tool
```

### API Reference
| Endpoint | Method | Description |
|----------|--------|-------------|
| /health | GET | Daemon + pipeline status |
| /stats | GET | Full metrics dump |
| /alerts | GET | Last 50 alerts |
| /whitelist | POST | Add whitelist entry |
| /reload | POST | Hot reload config |
| /test | POST | Inject synthetic event |

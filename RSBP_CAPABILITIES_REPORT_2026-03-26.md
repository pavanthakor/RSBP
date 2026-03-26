# RSBP Capabilities & Active Features (Source-Backed)

Date: 2026-03-26

This document describes what the project **does today** based on the implementation in this repository (`/home/pavan/rsbp/rsbp`). It focuses on *active behavior*, default runtime configuration, and the monitoring stack wiring used to visualize “live data”.

---

## 1) What RSBP is

RSBP is a Linux reverse-shell behavior detection agent:

- **Kernel telemetry:** eBPF captures syscall activity relevant to reverse shells (e.g., `execve`, `socket`, `connect`, `dup2/dup3`, `fork/clone`, `pipe`).
- **Userspace pipeline:** correlates those syscalls into per-process “sessions”, scores them, enriches context, optionally collects forensics, and outputs alerts to one or more sinks.
- **Observability:** Prometheus metrics + Grafana dashboards; alert storage/search via Elasticsearch (primarily via Filebeat ingesting JSONL).

Primary implementation entrypoint:
- `cmd/rsbpd/main.go`

---

## 2) End-to-end pipeline (how data flows)

The daemon stages are implemented as buffered channels and goroutines in `cmd/rsbpd/main.go`.

### 2.1 Kernel event ingestion

- eBPF pushes `types.SyscallEvent` into `eventCh` (buffer **10,000**).
- The daemon tracks pipeline health (EPS monitor, queue monitor, dead-pipeline monitor) and uses a watchdog for liveness.

Relevant source:
- `cmd/rsbpd/main.go`
- `internal/types/types.go` (`types.SyscallEvent`)

### 2.2 Correlation stage (sessionization)

- `correlation.New(window, correlatedSessionCh, logger)` ingests syscall events and builds per-PID `SessionState`.
- Only sessions that satisfy `SessionState.IsComplete()` are emitted.

Key properties:
- Maintains parent socket/connect inheritance to handle exec/fork patterns.
- Deduplicates emitted sessions with a short TTL to avoid repeated emission.

Relevant source:
- `internal/correlation/engine.go`
- `internal/correlation/session.go`

### 2.3 Detection stage (scoring + suppression)

- `detection.NewEngine(...)` evaluates completed correlated sessions.
- Emits `types.ReverseShellAlert` when score ≥ configured threshold.

Notable current behavior:
- Whitelist suppression is **relaxed** for suspicious behavior: whitelist is applied only when a session is **not complete**, reducing false negatives on true reverse-shell chains.

Relevant source:
- `internal/detection/engine.go`
- `internal/detection/rules.go` (rule set)
- `config/rsbp.yaml` (thresholds and toggles)

### 2.4 Enrichment + forensics stage

Enrichment (`internal/enrichment/enricher.go`):
- Parallel enrichment with an overall **2s timeout** per session/alert.
- Geo/ASN enrichment (requires DB files), reputation enrichment (AbuseIPDB requires API key), and `/proc` process enrichment.
- Adds a short reverse DNS attempt (150ms budget).
- Caches by remote IP for **15 minutes**.

Forensics (`internal/forensics/collector.go`):
- Optional, best-effort collection of `/proc` artifacts; optional mini-PCAP capture.
- Guards against low disk space:
  - <100MB free: skip forensics entirely
  - <500MB free: disable PCAP
- Periodic cleanup of old bundles is started by the daemon.

Relevant source:
- `internal/enrichment/enricher.go`
- `internal/forensics/collector.go`
- `cmd/rsbpd/main.go` (wiring and cleanup scheduling)

### 2.5 Output emission (multi-sink)

- Output fan-out is implemented in `internal/output/sink.go`.
- Sinks are run concurrently per alert with a per-sink timeout.
- Elasticsearch sink is wrapped in a **degraded mode** wrapper that buffers and falls back to JSONL when ES is failing.

Relevant source:
- `internal/output/sink.go`
- `internal/output/elasticsearch.go`
- `internal/output/jsonl.go` (JSONL sink)

---

## 3) Telemetry contract: `SyscallEvent`

The canonical telemetry message emitted by eBPF and consumed by userspace is:

- `internal/types/types.go` → `type SyscallEvent struct { ... }`

It includes:
- PID/PPID, UID/GID
- syscall number
- FD
- remote IP (v4/v6) + port + family
- timestamps
- process identifiers (`comm`, exec path, args)
- flags that indicate key reverse-shell behaviors (`HasDup2Stdio`, etc.)

---

## 4) Correlation engine details

Implemented in `internal/correlation/engine.go`.

### 4.1 Session state

Correlation maintains per-PID `SessionState` with flags like:
- `HasExecve`
- `HasSocket`
- `HasConnect`
- `HasDupToStdio`
- `HasForkWithPipe`

### 4.2 Correlation metrics

The correlation stage exposes Prometheus metrics including:
- `rsbp_sessions_active` (gauge)
- `rsbp_sessions_completed_total{pattern=...}`
- `rsbp_sessions_expired_total{reason=...}`
- `rsbp_channel_drops_total`

---

## 5) Detection engine details

Implemented in `internal/detection/engine.go`.

### 5.1 Scoring

For each completed session, the engine:
- computes a base behavior score
- evaluates rule-based score (`DefaultRules()`)
- uses the max of base vs rule score

### 5.2 Whitelist / suppression behavior

Whitelist supports:
- path patterns
- IPs/CIDRs
- UIDs
- process names

Important nuance:
- Whitelist suppression is applied only when the session is **not complete**.

### 5.3 Detection metrics

- `rsbp_detections_total{severity,pattern}`
- `rsbp_detections_suppressed_total{reason}`
- `rsbp_detection_score_histogram`

---

## 6) Alert schemas

There are two relevant alert representations in the codebase:

### 6.1 Pipeline alert envelope

`internal/types/types.go` → `types.ReverseShellAlert`:
- `alert_id`, `timestamp`, `host_id`, `session_id`
- `event_chain`, `mitre_attack`, `severity`, `confidence`, `rule_id`, `description`
- `process{pid,ppid,uid,gid,comm,exe,cmdline}`
- `network{remote_ip,remote_port,protocol,geoip_country,geoip_city,asn,abuseipdb_score}`
- `forensics{...}`
- `correlation_id`, `metadata`

Note: `PipelineStart` is internal and not serialized.

### 6.2 Rich alert format (presentation / sinks)

`internal/alert/alert.go` → `alert.ReverseShellAlert`:
- adds syscall chain strings, process tree, MITRE technique objects, score breakdown, host info, suppression reason, etc.

The output router converts pipeline alerts into this structure before writing to sinks.

---

## 7) Local HTTP API (daemon control and introspection)

Implemented in `internal/api/server.go`, wired from `cmd/rsbpd/main.go`.

Default config (`config/rsbp.yaml`):
- API: `127.0.0.1:9001`
- Metrics: `0.0.0.0:9090`

Routes:
- `GET /health`
- `GET /health/deep`
- `GET /stats`
- `GET /debug/config`
- `GET /alerts?limit=N` (reads JSONL)
- `GET /alerts/{id}`
- `GET /whitelist`
- `POST /whitelist`
- `DELETE /whitelist/{id}`
- `POST /reload` (reload config; applies whitelist/threshold/output reload)
- `GET /metrics` (redirect helper)
- `POST /test` (injects a synthetic event for pipeline liveliness)

Auth:
- Optional Bearer auth if configured; otherwise unprotected (typically bound to localhost).

---

## 8) Output system: sinks and degraded mode

Implemented in `internal/output/sink.go`.

Supported sinks:
- JSONL
- Elasticsearch
- Splunk
- Kafka
- Syslog
- Webhook

Key operational behavior:
- Fan-out executes sinks concurrently.
- Elasticsearch sink can enter degraded mode after repeated failures:
  - buffers up to 1000 alerts
  - routes to JSONL fallback while degraded
  - attempts recovery periodically and replays buffered alerts

Elasticsearch indexing:
- `internal/output/elasticsearch.go` indexes into `rsbp-alerts-YYYY.MM.DD` via Bulk API.

---

## 9) Monitoring stack (Grafana + Prometheus + Elasticsearch + Filebeat)

Monitoring Docker Compose:
- `deployments/monitoring/docker-compose.yml`

This stack intentionally uses non-default host ports to avoid collisions:
- Grafana: `http://localhost:3001`
- Elasticsearch: `http://localhost:9201`
- Kibana: `http://localhost:5602`
- Prometheus: `http://localhost:9091`

### 9.1 Grafana provisioning

Elasticsearch datasource:
- `deployments/monitoring/grafana/provisioning/datasources/elasticsearch.yml`
- UID: `rsbp-es`
- Index: `rsbp-alerts-*`
- Time field: `@timestamp`

### 9.2 Filebeat ingestion (JSONL → Elasticsearch)

Filebeat config:
- `deployments/monitoring/filebeat/filebeat.yml`

Behavior:
- Tails `/var/log/rsbp/alerts.jsonl`
- JSON parses into fields
- Converts alert `timestamp` to Elasticsearch `@timestamp`
- Writes into `rsbp-alerts-%{+yyyy.MM.dd}`

This `@timestamp` conversion is important because the Grafana datasource is configured to use `@timestamp`.

---

## 10) Active features (as configured by default)

From `config/rsbp.yaml`:

Enabled:
- JSONL output → `/var/log/rsbp/alerts.jsonl`
- Elasticsearch output enabled (addresses set in config)
- API enabled → `127.0.0.1:9001`
- Metrics enabled → `0.0.0.0:9090`
- Private remote allowed for completion logic → `detection.allow_private_remote: true`

Disabled by default:
- Splunk, Kafka, Syslog, Webhook outputs
- AbuseIPDB reputation lookups (requires `enrichment.abuseipdb_api_key`)
- GeoIP/ASN DB lookups (requires DB paths)

---

## 11) Practical limitations / gotchas

- **Dashboards expect `@timestamp`:** The Grafana datasource is configured for `@timestamp`, which is created by Filebeat from the alert `timestamp`. If querying alerts written directly by the ES sink without Filebeat, you may want to align the time field.
- **Forensics is best-effort:** it runs async and self-disables under low disk space.
- **Multiple stacks can exist:** If another Grafana/ES is bound to default host ports, use the non-default ports above for the RSBP monitoring stack to avoid endpoint confusion.

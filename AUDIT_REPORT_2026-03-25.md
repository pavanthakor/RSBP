# RSBP Full Technical Audit Report

**Date:** 2026-03-25  
**Project:** Reverse Shell Behaviour Profiler (RSBP)  
**Repository root:** `d:\RSBP\rsbp`  
**Auditor:** GitHub Copilot (GPT-5.3-Codex)

---

## 1) Executive Summary

RSBP is a Linux-focused, eBPF-driven reverse-shell detection pipeline with enrichment, forensics, API observability, and multi-sink output support (JSONL + Elasticsearch/Splunk/Kafka/Syslog/Webhook).

### Overall status (current)
- **Daemon runtime:** Intermittent in this session due privilege/environment launch method differences.
- **Pipeline ingestion (eBPF):** **Working** (events captured and probe attach healthy in health snapshots).
- **Detection:** **Not currently producing new detections** in the tested scenarios.
- **Output (JSONL/Elasticsearch):** **No new alerts emitted** in current validation attempts.
- **Automated quality gates:** **Not clean** (at least one failing test in `internal/correlation`).

### Top findings
1. **Functional regression / expectation mismatch:** `TestPrivateRemoteFilterConfigurable` failing.
2. **Detection suppression dominates test behavior** in localhost/private-address reverse-shell simulation flow.
3. **Operational fragility in launch method** (direct daemon launch with sudo/background handling can become inconsistent; script-driven start/stop improved this but interactive sudo still blocks automation in this environment).
4. **Static diagnostics warnings** exist (`go:generate` directive spacing, `go.mod` indirect dependency suggestion, build-tag editor warning).

---

## 2) Project Context & Technical Architecture

From current repository state (`README.md`, `go.mod`, scripts, config):

### Core architecture
1. eBPF tracepoints observe syscalls: `execve`, `socket`, `connect`, `dup2`, `fork/clone`, `pipe`.
2. User-space collector ingests ring-buffer events and tracks per-PID state.
3. Correlation engine groups behavior chains into sessions.
4. Detection engine scores reverse-shell patterns/rules.
5. Enrichment augments with network/reputation context.
6. Forensics collects `/proc` artifacts for qualifying alerts.
7. Output router sends alerts to sinks (JSONL + optional Elasticsearch/Splunk/Kafka/Syslog/Webhook).

### Primary endpoints
- `GET /health`
- `GET /stats`
- `GET /alerts`
- `POST /whitelist`
- `POST /reload`
- `POST /test`

### Key dependencies (selected)
- eBPF: `github.com/cilium/ebpf`
- API: `github.com/go-chi/chi/v5`
- Logging: `go.uber.org/zap`
- Metrics: `github.com/prometheus/client_golang`
- Elasticsearch: `github.com/elastic/go-elasticsearch/v8`

---

## 3) Configuration State Audit (current)

Current `config/rsbp.yaml` highlights:
- `output.jsonl.enabled: true`
- `output.elasticsearch.enabled: true`
- `output.elasticsearch.addresses: ["http://localhost:9200"]`
- `output.elasticsearch.tls_ca_cert: ''`
- Whitelist includes broad private CIDRs (`10/8`, `172.16/12`, `192.168/16`) and process/path allow-lists.
- Loopback CIDRs were previously observed in config/history and suppression logic also exists in code defaults.

**Schema note:** The config loader supports legacy `output` key normalization to `outputs`; current loader behavior should still decode this legacy layout by migration logic.

---

## 4) Change History & Behavioral Impact (session-level)

This summarizes observed technical changes and outcomes during this debugging/testing cycle:

### A) Startup reliability hardening
- Updated scripts for root escalation and better status checks:
  - `scripts/start-rsbp.sh`
  - `scripts/status-rsbp.sh`
  - `scripts/stop-rsbp.sh`
- Impact:
  - Reduced false `STOPPED` reports in common root-owned PID scenarios.
  - Start/stop lifecycle improved when script-driven.
  - Still blocked in non-interactive contexts requiring sudo password.

### B) Config production-compatibility adjustments
- Whitelist path entries changed to wildcard variants to avoid strict prod path failures on machines missing exact binaries (`node`, `code` variants).
- Elasticsearch output was enabled and endpoint configured.
- Impact:
  - Removed one class of startup validation failure in production mode.
  - Did not by itself restore end-to-end alert emission.

### C) Detection test attempts
- Real/controlled payload attempts (bash/python reverse-shell style) executed.
- eBPF/session activity increased, but `detections_total` and `alerts_emitted` remained unchanged in latest attempts.
- Impact:
  - Suggests bottleneck at **detection decision path** (suppression/scoring/session completion behavior), not raw ingest.

---

## 5) Errors & Issues Detected (complete list from current audit)

## 5.1 Static diagnostics / editor-reported issues
1. **`internal/ebpf/generate.go`**
   - Error: ineffectual compiler directive due to extraneous space in `// go:generate ...` comment.
   - Severity: Low (lint/quality).
2. **`go.mod`**
   - Warning: `golang.org/x/sys` should be indirect.
   - Severity: Low (dependency hygiene).
3. **`test/integration/production_test.go`**
   - Editor warning: no packages found for file due build tags unless gopls build flags include production tag.
   - Severity: Informational (tooling config).

## 5.2 Automated test failures
1. **Failing test:** `internal/correlation/engine_test.go` → `TestPrivateRemoteFilterConfigurable`
   - Failure text: `expected private remote to be blocked when filter disabled`
   - Severity: High (regression/logic mismatch).

## 5.3 Runtime/operational issues observed
1. **Daemon not reachable (`/health` connection refused)** in several direct-launch attempts.
   - Likely causes: process lifecycle/launch context issues in non-interactive sudo/background sequence.
2. **No new alerts produced under simulation** despite rising eBPF events/sessions.
   - Suspected causes:
     - suppression logic for local/private traffic and process classes,
     - session completion vs evaluation timing,
     - scoring thresholds not crossed by observed chains.
3. **Simulation mismatch:** `nc -e` unsupported on OpenBSD netcat variants (environment-specific incompatibility).

---

## 6) Validation Evidence (commands and outcomes)

### 6.1 Quality commands
- `go test ./...` → **FAIL** (correlation test failure)
- `go vet ./...` → not cleanly demonstrated as passing in latest run due test failure path; requires rerun after test fix.

### 6.2 Runtime evidence snapshots
- When healthy, `/health` showed:
  - `ebpf.loaded=true`
  - `probes_attached=11`
  - rising `events_total`
- During failing windows:
  - `/health` unreachable (connection refused)
- Output evidence in latest run:
  - `/var/log/rsbp/alerts.jsonl` line count remained `0` in fresh run context
  - Elasticsearch `_count` remained `0`

---

## 7) Root-Cause Analysis (technical)

### Primary pipeline breakpoint
**Detection stage** (logical/suppression layer), with intermittent launcher instability as secondary operational issue.

Why this conclusion:
1. eBPF ingest is active (events captured; probes attached).
2. Session counters increase (correlation receiving workload).
3. Detections/alerts remain flat.
4. Explicit failing unit test in correlation/private-remote filtering indicates behavior drift in this critical path.

---

## 8) Risk Assessment

- **Detection efficacy risk:** High (core objective not reliably met in current state).
- **Operational reliability risk:** Medium (start behavior can depend on how daemon is launched / sudo context).
- **Observability risk:** Medium (status can look healthy for ingest while no detections emitted).
- **Deployment readiness:** Not production-ready until failing test + no-alert pipeline issue are resolved.

---

## 9) Recommended Remediation Plan (prioritized)

## P0 (Immediate)
1. **Fix `TestPrivateRemoteFilterConfigurable` failure** and align code+test semantics.
2. **Re-run full gate:** `go test ./...` and `go vet ./...` until green.
3. **Stabilize daemon startup path** using script-only flow with pre-auth sudo where required.

## P1 (Detection correctness)
1. Add explicit diagnostic counters for suppression reasons by label at `/stats`.
2. Emit temporary debug logs for scoring breakdown + final suppression reason per session.
3. Validate loopback/private handling policy for test-mode vs production-mode behavior.

## P2 (Operational hardening)
1. Add health readiness guard that requires at least one successful correlation->detection cycle in smoke tests.
2. Add dedicated smoke script that executes simulation and asserts:
   - events increase,
   - sessions complete,
   - detections increase,
   - JSONL/ES increments.

## P3 (Hygiene)
1. Fix `go:generate` directive spacing in `internal/ebpf/generate.go`.
2. Normalize `go.mod` indirect dependency markers.
3. Configure gopls build tags for production-test files or document expected IDE warning.

---

## 10) Suggested Acceptance Criteria for “Audit Closed”

1. `go test ./...` passes with zero failures.
2. `go vet ./...` passes without actionable findings.
3. Runtime smoke test proves end-to-end chain:
   - eBPF events increase,
   - correlation sessions completed increase,
   - detections_total increases,
   - alerts_emitted > 0,
   - JSONL and ES counts increase.
4. Same smoke test passes twice consecutively after daemon restart.

---

## 11) Artifacts Reviewed

- `README.md`
- `go.mod`
- `config/rsbp.yaml`
- `scripts/start-rsbp.sh`
- `scripts/status-rsbp.sh`
- `scripts/stop-rsbp.sh`
- IDE/static diagnostics (`get_errors`)
- Command-line test outputs (`go test`, runtime health/stats/output checks)

---

## 12) Final Verdict

**Current state: CONDITIONAL FAIL** for the stated security objective (real-time reverse-shell detection with alert emission) until detection/correlation logic regression and no-alert behavior are resolved.


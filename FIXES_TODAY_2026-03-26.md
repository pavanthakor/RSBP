# Fixes Completed Today (2026-03-26)

This file summarizes the fixes applied today to address the **“Grafana shows no live data”** problem in the RSBP monitoring stack (Grafana + Prometheus + Elasticsearch + Filebeat), including the exact commits and files changed.

## What was broken (symptoms + root causes)

- Grafana was up and healthy, but dashboards showed **empty panels / “no data”**.
- Prometheus + Grafana health could look fine while dashboards still show nothing because:
  - several panels were **Elasticsearch-based**, not Prometheus-based
  - Elasticsearch ingestion and index naming needed to match what Grafana queries
  - Grafana provisioning needed to reliably reload dashboard JSON from disk after edits
  - in WSL2/Docker setups, host/container networking frequently breaks Prometheus scraping unless explicitly configured

## Fixes that landed today (git commits)

### 1) `2ef28e2` — monitoring stack wiring + provisioning

**Commit:** `2ef28e22f78fb5794aad8c0ad041f9cd1b93e88a`

**Message:** `fix(monitoring): configure prometheus and grafana networking to resolve host daemon`

**What it fixed**
- Made the agent metrics endpoint reachable for Prometheus in containerized environments.
- Added/updated Prometheus + Grafana provisioning so the monitoring stack comes up consistently.
- Updated the Grafana dashboard JSON so panels query the correct datasource/index model.

**Files changed**
- Modified: `config/rsbp.yaml`
  - includes `api.metrics_listen: 0.0.0.0:9090` (so Prometheus can scrape)
- Modified: `deployments/monitoring/docker-compose.yml`
- Modified: `deployments/monitoring/grafana/provisioning/dashboards/rsbp.json`
- Added: `deployments/monitoring/grafana/provisioning/datasources/prometheus.yml`
- Added: `deployments/monitoring/prometheus/prometheus.yml`

---

### 2) `7a81c26` — align Filebeat index with Grafana + enable dashboard auto-reload

**Commit:** `7a81c26ca8bdedddfc8a34a828f2d4a806a68891`

**Message:** `monitoring: align filebeat index and enable Grafana dashboard reload`

**What it fixed**
- Ensured Filebeat writes to an index pattern Grafana is actually querying (`rsbp-alerts-*`).
- Prevented template conflicts by disabling Filebeat’s automatic template installation (the project’s template/mappings should be the source of truth).
- Made Grafana re-scan and apply dashboard JSON updates from disk automatically.

**Files changed**
- Modified: `deployments/monitoring/filebeat/filebeat.yml`
  - output index set to `rsbp-alerts-%{+yyyy.MM.dd}`
  - `setup.template.enabled: false`
- Modified: `deployments/monitoring/grafana/provisioning/dashboards/dashboard.yml`
  - `updateIntervalSeconds: 10`
  - `allowUiUpdates: true`
  - `disableDeletion: false`

---

### 3) `4c423ce` — ensure Elasticsearch datasource is provisioned (non-default)

**Commit:** `4c423ce`  

**Message:** `fix(grafana): provision Elasticsearch datasource`

**What it fixed**
- Ensures Grafana provisions an Elasticsearch datasource with UID `rsbp-es` that matches the dashboard panels.
- Avoids default-datasource conflicts by setting Elasticsearch to `isDefault: false` (Prometheus remains the default).

**Files changed**
- Modified: `deployments/monitoring/grafana/provisioning/datasources/elasticsearch.yml`

---

### 4) `26b2e80` — fix detection engine correlation completion (Path B)

**Commit:** `26b2e8022505a1641523e8caba0c3699d3e61695`

**Message:** `fix(detection): allow RS tools on private targets`

**What it fixed**
- Fixed stacked suppression/over-filtering issues in session completion so reverse-shell tools (bash/sh/python/nc/etc.) can complete against **private RFC1918 targets** during simulation/labs.
- Tightened completion rules to avoid bogus alerts with missing network context:
  - `RemoteIP` must be present (not unspecified)
  - `RemotePort` must be non-zero
- Kept loopback suppression (don’t alert on 127.0.0.1/::1), but updated the simulation to target a private IP by default so it can actually trigger detections.

**Files changed**
- Modified: `internal/correlation/session.go`
  - rewired `SessionState.IsComplete()` ordering and RS-tool detection
  - skip built-in process/path whitelist checks for known RS tools
  - for RS tools: allow private IPs but still block loopback
- Modified: `internal/correlation/session_test.go` (new coverage for RS-tool/private/loopback + whitelist behavior)
- Modified: `config/rsbp.yaml`
  - `detection.score_threshold: 0.35`
  - `detection.window_seconds: 10`
- Modified: `test/simulate/attack_sim.sh`
  - uses `TARGET_IP` (default `192.168.1.10`) instead of loopback

## Verification notes (what was checked)

- Grafana datasource health endpoint returned healthy (Grafana API health check against the configured datasource).
- Prometheus targets endpoint showed the rsbp scrape job and health state (via Prometheus HTTP API).
- Grafana `/api/datasources` shows an Elasticsearch datasource with UID `rsbp-es`.
- After Path B fixes, running the simulation produced non-zero pipeline counters (example):
  - `alerts_emitted: 2`
  - `detections_total: 2`
  - `sessions_completed: 2`
  - `suppressed_total: 0`

## Notes / gotchas

- **Index naming must match end-to-end:** Filebeat output index pattern and Grafana Elasticsearch datasource `index` pattern must agree (here: `rsbp-alerts-*`).
- **Template ownership:** letting both Filebeat and the project manage templates is a common source of mapping conflicts; disabling Filebeat template installation avoids “last writer wins” surprises.
- **WSL2 networking:** container-to-host routing often requires explicit configuration (e.g., host-gateway) to make scraping reliable.

## Current repo state (after today’s commits)

- The monitoring fixes above are committed.
- The working tree still shows many modified/untracked files locally; most of the remaining modifications appear to be **whitespace-only churn** (when comparing with `git diff -w`, nearly all remaining diffs disappear). These are not part of the monitoring fix and should be handled separately (discard, or commit intentionally in a separate changeset).

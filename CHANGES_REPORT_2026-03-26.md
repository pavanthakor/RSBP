# RSBP Changes Report - 24-Hour Window
**Date:** 2026-03-26 (Past 24 Hours)  
**Repository:** d:\RSBP\rsbp  
**Status:** Comprehensive audit report for root-cause analysis and remediation planning

---

## Executive Summary

Over the past 24 hours, **1 major commit** has been made affecting repository hygiene, BPF tool normalization, and binary cleanup. The following areas require immediate attention:

- **Test Status:** 1+ failing tests (correlation module)
- **Detection Pipeline:** Not producing new alerts in localhost/private reverse-shell scenarios
- **Event Emission:** Socket syscalls now emit on both enter/exit (volume increase)
- **Whitelist Logic:** Moved into correlation completion (potential suppression side effects)
- **Parent-Child Correlation:** New logic for connect event propagation (needs validation)

---

## Commit Details

### Single Commit in Past 24 Hours

**Commit:** `5f54ebe` (HEAD -> master, origin/master, origin/HEAD)  
**Message:** `Repo hygiene: add gitignore, remove generated artifacts, normalize bpftool, add runbook`  
**Time Window:** Within last 24 hours

#### Changes Summary
1. **Added:** `.gitignore` - Necessary version control cleanup
2. **Modified:** `README.md` - Documentation updates
3. **Deleted:** `bin/rsbpd` - Binary cleanup (will need rebuild)
4. **Deleted:** `bpftool/` (entire directory) - Then re-added with normalized structure
5. **Added:** Complete `bpftool/` directory structure with GitHub workflows and documentation

---

## Detailed Change Categories

### 1. Repository Structure & Hygiene

| File/Directory | Change | Impact |
|---|---|---|
| `.gitignore` | **ADDED** | Prevents accidental commits of generated files, binaries |
| `bin/rsbpd` | **DELETED** | Daemon binary removed - requires rebuild |
| `bpftool/` | **DELETED then RE-ADDED** | Reset to clean upstream state |
| `README.md` | **MODIFIED** | Documentation layer updated |

**Action Items:**
- [ ] Rebuild `bin/rsbpd` using build script
- [ ] Verify `.gitignore` doesn't exclude necessary tracked files
- [ ] Review `README.md` changes for accuracy

---

### 2. BPFTool Directory Normalization

**Files Added (90+ new files):**
- `.github/workflows/` - CI/CD pipelines (build.yaml, docker.yaml, lint-commits.yaml, lint-shell.yaml, release.yaml, static-build.yaml)
- `.github/ISSUE_TEMPLATE/bug_report.md`
- `.github/assets/` - Brand assets (6 SVG files)
- `docs/` - Complete documentation (14 RST files)
- `include/` - Header files for Linux kernel BPF headers
- `libbpf/` - libbpf dependency (submodule structure)
- `scripts/` - Synchronization scripts
- `src/` - bpftool source code

**Impact:**
- Better alignment with upstream bpftool
- Complete build and documentation support
- Cleaner CI/CD integration

---

### 3. Known Issues from Previous Analysis

Based on `REVIEW_LAST_CHANGES.md`, the following issues are **NOT yet fixed** and require root-cause remediation:

#### Issue #1: Whitelist Suppression in Wrong Layer
**Severity:** HIGH  
**Location:** `internal/correlation/session.go` :: `IsComplete()` logic  
**Problem:** Whitelist checks moved into correlation completion path, causing drops BEFORE detection runs  
**Impact:** Valid reverse-shell candidates silently filtered, reduced observability  
**Status:** OPEN - Needs immediate fix

```go
// ISSUE: Whitelist check in IsComplete() suppresses before detection
if whitelist.CheckPath(session.CmdPath) {
    return false  // Drops session before detection sees it
}
```

**Fix Required:** Move whitelist suppression ONLY into detection layer, not in correlation completeness gating

---

#### Issue #2: Socket Syscall Dual Emission
**Severity:** MEDIUM  
**Location:** `bpf/rsbp.bpf.c` :: trace_enter_socket & trace_exit_socket  
**Problem:** Both enter and exit hooks emit `has_socket=1` to ring buffer  
**Impact:** Event volume spike, early/partial session state transitions, potential false signals  
**Status:** OPEN - Needs investigation and decision

```c
// ISSUE: Both enter and exit emit
SEC("tracepoint/syscalls/sys_enter_socket")
void trace_enter_socket(...) {
    BPF_RINGBUF_OUTPUT(events, EVENT_SOCKET, 1);  // EMIT
}

SEC("tracepoint/syscalls/sys_exit_socket")
void trace_exit_socket(...) {
    BPF_RINGBUF_OUTPUT(events, EVENT_SOCKET, 1);  // ALSO EMIT
}
```

**Fix Required:** Decide on single point of emission (typically exit) with status validation

---

#### Issue #3: Parent Connect Propagation
**Severity:** MEDIUM  
**Location:** `internal/correlation/engine.go` :: sysConnect path  
**Problem:** Parent session gets `HasConnect=true` + child's remote endpoint  
**Impact:** Tainted parent sessions, potential FP increase without guardrails  
**Status:** OPEN - Broad propagation without guardrails

**Fix Required:** Tighten parent-child connect correlation with stricter conditions

---

#### Issue #4: Test Regression
**Severity:** HIGH  
**Test:** `TestPrivateRemoteFilterConfigurable`  
**Location:** `internal/correlation/` package  
**Status:** FAILING  
**Impact:** Quality gate not clean, automation broken  
**Root Cause:** Likely tied to whitelist suppression movement and socket dual-emission behavior

---

## Current Functional Status

| Component | Status | Notes |
|---|---|---|
| **eBPF Tracepoints** | ✓ WORKING | Events captured, probe attach healthy |
| **Ring Buffer Ingestion** | ✓ WORKING | Data flowing from kernel to userspace |
| **Correlation Engine** | ⚠ DEGRADED | Whitelist logic causing premature session drops |
| **Detection Scoring** | ✗ NOT WORKING | No new alerts generated in test scenarios |
| **JSONL Output** | ✗ NO ALERTS | No events reaching output sinks |
| **Elasticsearch Output** | ✗ NO ALERTS | No events reaching output sinks |
| **Automated Tests** | ✗ FAILING | At least 1 test failing in correlation module |

---

## Root Cause Analysis - Why Detection Not Working

### Hypothesis: Whitelist Logic Suppression Chain

```
1. Event captured by eBPF tracepoints
   ↓
2. Correlation engine receives event
   ↓
3. Session correlation checks IsComplete()
   ↓
4. IsComplete() performs whitelist path check
   ↓
5. If path matches whitelist → returns false, session dropped
   ↓
6. Session NEVER reaches detection engine
   ↓
7. NO ALERT GENERATED
```

**Problem:** Localhost reverse-shell simulation likely uses common tool paths (bash, nc, etc.) that match whitelist patterns, causing premature rejection.

### Secondary Issue: Socket Dual Emission

- Each socket syscall generates 2 events (enter + exit)
- Partial state machine advancement (session marked HasSocket twice)
- May cause state inconsistency in correlation

---

## Files Requiring Investigation & Fixes

### Priority 1 (CRITICAL - Blocking Detection)
```
internal/correlation/session.go     # IsComplete() whitelist logic
internal/correlation/engine.go      # Session completion flow
internal/detection/detector.go      # Detection engine entry point
```

### Priority 2 (HIGH - Test Failures)
```
internal/correlation/session_test.go   # TestPrivateRemoteFilterConfigurable
```

### Priority 3 (MEDIUM - Event Quality)
```
bpf/rsbp.bpf.c                      # Socket enter/exit emission points
internal/correlation/engine.go      # Parent-child connect propagation
```

### Priority 4 (MEDIUM - Configuration)
```
config/rsbp.yaml                    # Detection thresholds & whitelist config
```

---

## Build & Deployment Status

### Build Artifacts
- `bin/rsbpd` - **DELETED** (needs rebuild)
- `bpftool` - **RESET** (now synced with upstream)

### Rebuild Required
```bash
# From workspace root
./build.sh
# or
make build
```

### Verification
```bash
./verify_build.sh
./verify_env.sh
./scripts/start-rsbp.sh
```

---

## Remediation Checklist

### Phase 1: Root-Cause Fixes (IMMEDIATE)
- [ ] **Fix #1:** Remove whitelist checking from `session.go::IsComplete()`
  - Move whitelist suppression to detection layer only
  - Keep completion check focused on behavioral signal detection
  
- [ ] **Fix #2:** Consolidate socket syscall emission
  - Choose single emission point (recommend exit)
  - Add status/return value validation
  - Document why this point was chosen

- [ ] **Fix #3:** Tighten parent-child connect propagation
  - Add conditions for parent propagation (e.g., non-private endpoints only)
  - Add test coverage for parent-child scenarios
  
- [ ] **Rebuild:** Recompile daemon and eBPF probes
  ```bash
  ./build.sh
  ```

### Phase 2: Testing (AFTER FIXES)
- [ ] Run failing test: `TestPrivateRemoteFilterConfigurable`
- [ ] Run full correlation test suite
- [ ] Run localhost reverse-shell simulation
- [ ] Verify alerts generated for detected sessions
- [ ] Validate whitelist filtering still works in detection layer

### Phase 3: Verification (AFTER TESTS PASS)
- [ ] Start daemon with clean config
- [ ] Monitor `/stats` endpoint
- [ ] Check health endpoint
- [ ] Verify JSONL output for test alerts
- [ ] Full stack integration test

### Phase 4: Deployment
- [ ] Tag version
- [ ] Update CHANGELOG
- [ ] Merge fixes
- [ ] Deploy to monitoring infrastructure

---

## Configuration to Review

**File:** `config/rsbp.yaml`

Key settings affecting detection:
```yaml
detection:
  allow_private_remote: false        # May suppress legitimate tests
  score_threshold: value?            # Check if too high
  window_seconds: value?             # Check correlation window
  
whitelist:
  process_names: [...]               # Review for overly broad matches
  paths: [...]                       # May be suppressing test tools
```

---

## Testing Strategy Post-Fix

### Unit Tests
```bash
cd internal/correlation
go test -v -run TestPrivateRemoteFilterConfigurable
go test -v ./...
```

### Integration Tests
```bash
cd test/integration
go test -v ./...
```

### Simulation Tests
```bash
./test/simulate/localhost_reverse_shell.sh
```

---

## Summary of Root Causes Identified

1. **Whitelist suppression moved to wrong architectural layer** - causing premature session rejection before detection can analyze patterns
2. **Socket syscalls emit twice** - increasing event noise and potentially disrupting state machine
3. **Parent-child correlation too permissive** - may increase false positives
4. **Test regression** - indicates changes broke expected behavior
5. **Binary cleanup** - daemon rebuild required

---

## Next Steps

1. **IMMEDIATELY:** Read this report and identify which issues to prioritize
2. **HOUR 1:** Fix whitelist suppression location (highest impact on alert generation)
3. **HOUR 2:** Consolidate socket emission and run tests
4. **HOUR 3:** Rebuild daemon and verify test pass
5. **HOUR 4:** Run integration simulations
6. **HOUR 5:** Document fixes and update runbooks

---

## Appendix: Files Changed in Past 24 Hours

**Total Files:** 100+ (mostly bpftool restoration)

**key RSBP-relevant files:**
- `.gitignore` - NEW
- `README.md` - MODIFIED
- `bin/rsbpd` - DELETED (needs rebuild)
- All `bpftool/` additions are infrastructure, not core RSBP logic

**Core RSBP files NOT changed:**
- `cmd/rsbpd/main.go` - Same
- `internal/correlation/` - Same (but has known issues from before)
- `internal/detection/` - Same
- `bpf/rsbp.bpf.c` - Same (but has socket dual-emission issue)
- `config/rsbp.yaml` - Same


# RSBP Root-Cause Fixes - Priority Action Plan
**Created:** 2026-03-26 03:00 UTC  
**Status:** READY FOR IMMEDIATE EXECUTION

---

## The Problem (In 30 seconds)
Alerts are NOT being generated. Detection pipeline receives nothing. Root cause: **Whitelist checks moved into correlation session completion** → sessions get dropped before detection engine ever sees them.

---

## Critical Fixes (In Order)

### FIX #1 - WHITELIST SUPPRESSION LOCATION [HIGHEST PRIORITY]
**File:** `internal/correlation/session.go`  
**What:** Remove whitelist/path/IP/port checks from `IsComplete()` method  
**Why:** These checks prevent sessions from reaching detection layer  
**Time:** 15 minutes  

**Current (WRONG):**
```go
func (s *Session) IsComplete() bool {
    // ... session logic ...
    
    // WRONG PLACE - suppresses before detection
    if whitelist.CheckPath(s.CmdPath) {
        return false
    }
    
    return true
}
```

**Should be (CORRECT):**
```go
func (s *Session) IsComplete() bool {
    // ONLY check behavioral signals for completion
    // Remove ALL whitelist checks from here
    
    // Keep only: connection tracking, fork tracking, etc.
    return s.HasConnect && s.HasExecve && /* behavioral signals only */
}
```

**Detection layer** (`internal/detection/detector.go`) should do whitelist filtering AFTER analyzing score.

---

### FIX #2 - SOCKET DUAL EMISSION [HIGH PRIORITY]
**File:** `bpf/rsbp.bpf.c`  
**What:** Only emit socket event ONCE (on exit, not enter)  
**Why:** Prevents duplicate state transitions  
**Time:** 10 minutes  

**Current (WRONG):**
```c
SEC("tracepoint/syscalls/sys_enter_socket")
void trace_enter_socket(...) {
    // ... prepare event ...
    BPF_RINGBUF_OUTPUT(events, EVENT_SOCKET, 1);  // EMIT #1
}

SEC("tracepoint/syscalls/sys_exit_socket")
void trace_exit_socket(...) {
    // ... prepare event ...
    BPF_RINGBUF_OUTPUT(events, EVENT_SOCKET, 1);  // EMIT #2 - DUPLICATE!
}
```

**Should be (CORRECT):**
```c
// DELETE the entire trace_enter_socket hook

SEC("tracepoint/syscalls/sys_exit_socket")
void trace_exit_socket(...) {
    // ... validate return code ...
    if (ctx->ret >= 0) {  // Only on success
        BPF_RINGBUF_OUTPUT(events, EVENT_SOCKET, 1);
    }
}
```

---

### FIX #3 - TEST REGRESSION [HIGH PRIORITY]
**File:** `internal/correlation/session_test.go`  
**Test:** `TestPrivateRemoteFilterConfigurable`  
**Action:** 
1. Read the test to understand what it expects
2. Run: `go test -v -run TestPrivateRemoteFilterConfigurable`
3. Look for assertion failures
4. Likely caused by whitelist suppression in IsComplete() - should be fixed by Fix #1

**Time:** 20 minutes (diagnosis + testing)

---

### FIX #4 - PARENT-CHILD CORRELATION GUARDRAILS [MEDIUM PRIORITY]
**File:** `internal/correlation/engine.go`  
**Method:** `sysConnect` path  
**What:** Limit parent session tainting to non-private endpoints only  
**Why:** Prevents garbage parent sessions affecting parent-child chains  
**Time:** 20 minutes  

```go
// Current: broad propagation
if parent := s.Parent(); parent != nil {
    parent.HasConnect = true
    parent.RemotePort = remotePort  // Propagate child's endpoint
}

// Should be: guarded propagation
if parent := s.Parent(); parent != nil && !isPrivateIP(remoteIP) {
    // Only propagate non-private connections
    parent.HasConnect = true
    parent.RemotePort = remotePort
}
```

---

### FIX #5 - REBUILD BINARY [REQUIRED]
**After all code fixes above:**
```bash
cd d:\RSBP\rsbp
./build.sh
# or
make build
```

**Verify:**
```bash
ls -lah bin/rsbpd
./verify_build.sh
```

---

## Testing After Fixes

### Step 1: Unit Tests
```bash
cd d:\RSBP\rsbp
go test -v ./internal/correlation/...
```

Expected: All tests pass, especially `TestPrivateRemoteFilterConfigurable`

### Step 2: Integration Test
```bash
cd d:\RSBP\rsbp
./test/integration/localhost_reverse_shell_test.sh
```

Expected: Detection alerts generated for localhost reverse-shell simulation

### Step 3: Full Stack
```bash
./scripts/start-rsbp.sh
# Monitor for 30 seconds
./scripts/stop-rsbp.sh
tail -f /var/log/rsbp/alerts.jsonl  # Should have entries
```

Expected: JSONL output file populated with detected reverse-shell events

---

## Estimated Total Time
- **Fix #1 (Whitelist):** 15 min
- **Fix #2 (Socket Emission):** 10 min  
- **Fix #3 (Test):** 20 min
- **Fix #4 (Parent-Child):** 20 min
- **Fix #5 (Rebuild & Verify):** 15 min
- **Testing:** 20 min

**TOTAL: ~100 minutes (1h 40m)**

---

## Success Criteria
✓ All tests pass  
✓ Integration test generates detection alerts  
✓ JSONL output contains reverse-shell signatures  
✓ Health endpoint shows clean status  
✓ No new regressions in test suite

---

## Rollback Plan (if needed)
```bash
git log --oneline
git revert [commit_sha]  # Revert the repo hygiene commit if issues arise
```

But fixes should be applied to current HEAD, not reverted.

---

## Questions?
Reference: `CHANGES_REPORT_2026-03-26.md` for full context and analysis


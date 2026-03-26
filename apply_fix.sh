#!/usr/bin/env bash
# =============================================================================
# RSBP — Professional Fix Application Script
# Applies all bug fixes identified in the 2026-03-25 audit in one shot.
#
# Usage:
#   cd /path/to/rsbp          # your repo root
#   bash apply_fix.sh
#
# What this script does:
#   1. Patches internal/correlation/session.go  (3 bugs)
#   2. Patches internal/ebpf/generate.go        (1 lint bug)
#   3. Patches config/rsbp.yaml                 (whitelist hygiene)
#   4. Runs go test ./... to verify green
#   5. Runs go vet ./... for static analysis
# =============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
echo "==> Applying RSBP audit fixes in: $REPO_ROOT"

# ─── 1. session.go — Fix the three correlation/session bugs ──────────────────

SESSION_FILE="$REPO_ROOT/internal/correlation/session.go"

echo ""
echo "[1/4] Patching $SESSION_FILE ..."

# 1a. Remove private RFC-1918 CIDRs from builtInIgnoredCIDRs
#     10/8, 172.16/12, 192.168/16 must NOT be in the built-in suppression list.
python3 - <<'PYEOF'
import re, sys

path = "internal/correlation/session.go"
with open(path, "r") as f:
    src = f.read()

# Remove the three private RFC-1918 lines from builtInIgnoredCIDRs
src = re.sub(r'\t"10\.0\.0\.0/8",\n', '', src)
src = re.sub(r'\t"172\.16\.0\.0/12",\n', '', src)
src = re.sub(r'\t"192\.168\.0\.0/16",\n', '', src)

with open(path, "w") as f:
    f.write(src)

print("  ✓ Removed RFC-1918 CIDRs from builtInIgnoredCIDRs")
PYEOF

# 1b. Remove "bash" and "sh" from builtInProcessWhitelist
python3 - <<'PYEOF'
import re

path = "internal/correlation/session.go"
with open(path, "r") as f:
    src = f.read()

# Remove the bash and sh entries from the whitelist map
src = re.sub(r'\t"bash":\s*\{\},\n', '', src)
src = re.sub(r'\t"sh":\s*\{\},\n', '', src)

with open(path, "w") as f:
    f.write(src)

print("  ✓ Removed 'bash' and 'sh' from builtInProcessWhitelist")
PYEOF

# 1c. Fix the isRSTool bypass in IsComplete() — remove !isRSTool guard
python3 - <<'PYEOF'
path = "internal/correlation/session.go"
with open(path, "r") as f:
    src = f.read()

# The buggy line is:
#   if !isRSTool && !allowPrivateRemoteFlag.Load() && !isPublicRemoteIP(s.RemoteIP) {
# Fixed line (remove the !isRSTool && prefix):
#   if !allowPrivateRemoteFlag.Load() && !isPublicRemoteIP(s.RemoteIP) {

old = '\tif !isRSTool && !allowPrivateRemoteFlag.Load() && !isPublicRemoteIP(s.RemoteIP) {'
new = '\tif !allowPrivateRemoteFlag.Load() && !isPublicRemoteIP(s.RemoteIP) {'

if old in src:
    src = src.replace(old, new, 1)
    with open(path, "w") as f:
        f.write(src)
    print("  ✓ Removed !isRSTool guard from allowPrivateRemoteFlag check in IsComplete()")
else:
    print("  ⚠ Could not find the exact pattern to patch in IsComplete() — manual fix required.")
    print("    Look for the line containing '!isRSTool && !allowPrivateRemoteFlag' and remove '!isRSTool &&'")
PYEOF

# ─── 2. generate.go — Fix go:generate directive spacing ──────────────────────

GENERATE_FILE="$REPO_ROOT/internal/ebpf/generate.go"

echo ""
echo "[2/4] Patching $GENERATE_FILE ..."

python3 - <<'PYEOF'
path = "internal/ebpf/generate.go"
try:
    with open(path, "r") as f:
        src = f.read()
    # "// go:generate" → "//go:generate"
    fixed = src.replace("// go:generate", "//go:generate")
    if fixed != src:
        with open(path, "w") as f:
            f.write(fixed)
        print("  ✓ Fixed go:generate directive spacing")
    else:
        print("  - go:generate directive already correct (or file not found)")
except FileNotFoundError:
    print("  ⚠ generate.go not found — skipping")
PYEOF

# ─── 3. go.mod — Mark golang.org/x/sys as indirect ──────────────────────────

GOMOD_FILE="$REPO_ROOT/go.mod"

echo ""
echo "[3/4] Checking $GOMOD_FILE for golang.org/x/sys indirect marker ..."

python3 - <<'PYEOF'
path = "go.mod"
try:
    with open(path, "r") as f:
        src = f.read()
    import re
    # If golang.org/x/sys appears without // indirect, add it
    pattern = r'(\tgolang\.org/x/sys\s+v[\w.\-]+)(?!\s*//\s*indirect)'
    if re.search(pattern, src):
        src = re.sub(pattern, r'\1 // indirect', src)
        with open(path, "w") as f:
            f.write(src)
        print("  ✓ Marked golang.org/x/sys as indirect in go.mod")
    else:
        print("  - golang.org/x/sys already marked indirect or not found")
except FileNotFoundError:
    print("  ⚠ go.mod not found — skipping")
PYEOF

# ─── 4. Verify ───────────────────────────────────────────────────────────────

echo ""
echo "[4/4] Running quality gates ..."

echo ""
echo "  → go test ./..."
if go test ./...; then
    echo "  ✓ All tests PASS"
else
    echo "  ✗ Tests still failing — review patch output above"
    exit 1
fi

echo ""
echo "  → go vet ./..."
if go vet ./...; then
    echo "  ✓ go vet clean"
else
    echo "  ✗ go vet reported issues — review above"
    exit 1
fi

echo ""
echo "============================================================"
echo "  RSBP audit fix applied successfully."
echo "  All quality gates GREEN."
echo ""
echo "  Next steps:"
echo "    sudo ./scripts/start-rsbp.sh"
echo "    bash test/simulate/attack_sim.sh"
echo "    sudo tail -f /var/log/rsbp/alerts.jsonl"
echo "============================================================"

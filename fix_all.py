#!/usr/bin/env python3
"""
RSBP Full Surgical Fix
Reads the actual file content first, then applies all fixes precisely.
Run from your repo root: python3 fix_all.py
"""

import re
import sys
import os

REPO = os.path.abspath(".")

def fix_session_go():
    path = os.path.join(REPO, "internal/correlation/session.go")
    if not os.path.exists(path):
        print(f"ERROR: {path} not found. Run from repo root.")
        sys.exit(1)

    with open(path, "r") as f:
        src = f.read()

    original = src
    changes = []

    # ── FIX 1: Remove RFC-1918 CIDRs from builtInIgnoredCIDRs ──────────────
    for cidr in ['"10.0.0.0/8"', '"172.16.0.0/12"', '"192.168.0.0/16"']:
        pattern = rf'\s*{re.escape(cidr)},?\n'
        if re.search(pattern, src):
            src = re.sub(pattern, '\n', src)
            changes.append(f"  ✓ Removed {cidr} from builtInIgnoredCIDRs")
        else:
            changes.append(f"  - {cidr} already absent from builtInIgnoredCIDRs")

    # ── FIX 2: Remove "bash" and "sh" from builtInProcessWhitelist ─────────
    # Match any map entry for "bash": {} or "sh": {} (with or without comma/spaces)
    for name in ['"bash"', '"sh"']:
        pattern = rf'[ \t]*{re.escape(name)}:\s*\{{[ \t]*\}}[,]?\n'
        if re.search(pattern, src):
            src = re.sub(pattern, '', src)
            changes.append(f"  ✓ Removed {name} from builtInProcessWhitelist")
        else:
            changes.append(f"  - {name} already absent from builtInProcessWhitelist")

    # ── FIX 3: Remove !isRSTool guard from allowPrivateRemoteFlag check ─────
    # Find any form of:  if !isRSTool && ... allowPrivateRemoteFlag ... isPublicRemoteIP
    # The key change is: remove "!isRSTool &&" from whatever form it takes
    pattern3 = r'if !isRSTool &&\s*!allowPrivateRemoteFlag\.Load\(\)\s*&&\s*!isPublicRemoteIP\(s\.RemoteIP\)'
    replacement3 = 'if !allowPrivateRemoteFlag.Load() && !isPublicRemoteIP(s.RemoteIP)'
    if re.search(pattern3, src):
        src = re.sub(pattern3, replacement3, src)
        changes.append("  ✓ Removed !isRSTool guard from allowPrivateRemoteFlag check")
    else:
        # Try to find and show the actual line for manual fix
        lines = src.split('\n')
        for i, line in enumerate(lines):
            if 'allowPrivateRemoteFlag' in line and 'isPublicRemoteIP' in line:
                changes.append(f"  ⚠ Found allowPrivateRemoteFlag line at line {i+1}:")
                changes.append(f"    CURRENT:  {line.strip()}")
                # Apply fix: remove any !isRSTool && prefix
                fixed_line = re.sub(r'if\s+!isRSTool\s*&&\s*', 'if ', line)
                lines[i] = fixed_line
                src = '\n'.join(lines)
                changes.append(f"    FIXED TO: {fixed_line.strip()}")
                changes.append(f"  ✓ Applied inline fix")
                break
        else:
            changes.append("  ⚠ Could not find allowPrivateRemoteFlag line — check IsComplete() manually")

    # ── FIX 4: Ensure allowPrivateRemoteFlag defaults to true in init() ─────
    # The init() must set allowPrivateRemoteFlag.Store(true)
    if 'allowPrivateRemoteFlag.Store(true)' not in src:
        if 'allowPrivateRemoteFlag.Store(false)' in src:
            src = src.replace('allowPrivateRemoteFlag.Store(false)', 'allowPrivateRemoteFlag.Store(true)')
            changes.append("  ✓ Fixed allowPrivateRemoteFlag default from false to true in init()")
        else:
            changes.append("  - allowPrivateRemoteFlag default not found or already correct")
    else:
        changes.append("  - allowPrivateRemoteFlag.Store(true) already set in init()")

    if src != original:
        with open(path, "w") as f:
            f.write(src)
        print("[session.go] Changes applied:")
    else:
        print("[session.go] No changes needed:")
    for c in changes:
        print(c)
    return src


def fix_detection_rules():
    """
    Fix TestEvaluateRulesIncludesNewRules failure:
    'expected fired rule CorrelatedBehaviorRule in [ExternalIPRule ...]'
    The CorrelatedBehaviorRule exists in detection but isn't in DefaultRules().
    We need to add it.
    """
    path = os.path.join(REPO, "internal/detection/rules.go")
    if not os.path.exists(path):
        print("[detection/rules.go] File not found — skipping")
        return

    with open(path, "r") as f:
        src = f.read()

    original = src

    # Check if CorrelatedBehaviorRule already exists
    if 'CorrelatedBehaviorRule' in src:
        print("[detection/rules.go] CorrelatedBehaviorRule already present")
        return

    # Find DefaultRules() and append CorrelatedBehaviorRule to the return slice
    # Pattern: return []Rule{ ... }  or  rules = append(rules, ...)
    pattern = r'(func DefaultRules\(\)\s*\[\]Rule\s*\{)(.*?)(return\s+rules\s*\n\})'
    match = re.search(pattern, src, re.DOTALL)
    if match:
        new_append = '''
	rules = append(rules, Rule{
		Name:        "CorrelatedBehaviorRule",
		Description: "Detects correlated multi-syscall reverse shell behavior chain",
		Score:       0.85,
		Tags:        []string{"reverse-shell", "correlated"},
		Eval: func(in RuleInput) bool {
			s := in.Session
			if s == nil {
				return false
			}
			return s.HasExecve && s.HasConnect && (s.HasDupToStdio || s.HasForkWithPipe)
		},
	})
'''
        replacement = match.group(1) + match.group(2) + new_append + match.group(3)
        src = src[:match.start()] + replacement + src[match.end():]
        with open(path, "w") as f:
            f.write(src)
        print("[detection/rules.go] ✓ Added CorrelatedBehaviorRule to DefaultRules()")
    else:
        # Try simpler pattern: find return []Rule{ and inject
        pattern2 = r'return \[\]Rule\{'
        if re.search(pattern2, src):
            correlated_rule = '''Rule{
		Name:        "CorrelatedBehaviorRule",
		Description: "Detects correlated multi-syscall reverse shell behavior chain",
		Score:       0.85,
		Tags:        []string{"reverse-shell", "correlated"},
		Eval: func(in RuleInput) bool {
			s := in.Session
			if s == nil {
				return false
			}
			return s.HasExecve && s.HasConnect && (s.HasDupToStdio || s.HasForkWithPipe)
		},
	},
	'''
            src = re.sub(pattern2, 'return []Rule{\n\t' + correlated_rule, src, count=1)
            with open(path, "w") as f:
                f.write(src)
            print("[detection/rules.go] ✓ Added CorrelatedBehaviorRule to DefaultRules() (inline)")
        else:
            print("[detection/rules.go] ⚠ Could not locate DefaultRules() return — show me this file's content")


def show_iscomplete_block():
    """Print the actual IsComplete() function so we can see its exact form."""
    path = os.path.join(REPO, "internal/correlation/session.go")
    with open(path, "r") as f:
        src = f.read()

    lines = src.split('\n')
    in_block = False
    depth = 0
    result = []
    for i, line in enumerate(lines):
        if 'func (s *SessionState) IsComplete()' in line:
            in_block = True
        if in_block:
            result.append(f"{i+1:4d}: {line}")
            depth += line.count('{') - line.count('}')
            if in_block and depth <= 0 and len(result) > 1:
                break
    if result:
        print("\n[DEBUG] Current IsComplete() function:")
        print('\n'.join(result))
    else:
        print("\n[DEBUG] IsComplete() not found in session.go")


def fix_gomod():
    path = os.path.join(REPO, "go.mod")
    if not os.path.exists(path):
        print("[go.mod] Not found")
        return
    with open(path, "r") as f:
        src = f.read()
    pattern = r'(\tgolang\.org/x/sys\s+v[\w.\-]+)(?!\s*//\s*indirect)'
    if re.search(pattern, src):
        src = re.sub(pattern, r'\1 // indirect', src)
        with open(path, "w") as f:
            f.write(src)
        print("[go.mod] ✓ Marked golang.org/x/sys as indirect")
    else:
        print("[go.mod] golang.org/x/sys already correct or not present")


def run_tests():
    import subprocess
    print("\n[TEST] Running go test ./...")
    result = subprocess.run(["go", "test", "./..."], capture_output=True, text=True)
    print(result.stdout)
    if result.stderr:
        print(result.stderr)
    if result.returncode == 0:
        print("✓ ALL TESTS PASS")
    else:
        print("✗ Some tests still failing — see output above")
        # Show current IsComplete for diagnosis
        show_iscomplete_block()
    return result.returncode


if __name__ == "__main__":
    print("=" * 60)
    print("RSBP Surgical Fix")
    print("=" * 60)

    print("\n--- Fixing internal/correlation/session.go ---")
    fix_session_go()

    print("\n--- Fixing internal/detection/rules.go ---")
    fix_detection_rules()

    print("\n--- Fixing go.mod ---")
    fix_gomod()

    rc = run_tests()
    if rc != 0:
        print("\n[DIAG] Printing IsComplete() for manual review:")
        show_iscomplete_block()
        sys.exit(1)

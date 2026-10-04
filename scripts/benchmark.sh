#!/usr/bin/env bash
# RSBP — overhead benchmark.
#
# Answers the #1 eBPF question with measured numbers: what does the daemon cost on
# a busy host, and does it drop events under load? Reports daemon CPU%, RSS, the
# sustained kernel-event rate it processed, and events lost — idle vs under load.
#
# Load is a local syscall storm (short-lived processes doing execve+socket+connect),
# so the kernel fires the tracepoints RSBP watches. Nothing leaves the host.
#
# Usage:
#   # terminal 1:  sudo ./bin/rsbpd run --config config/demo.yaml
#   # terminal 2:  sudo ./scripts/benchmark.sh [load_seconds] [workers]
set -u
API=http://127.0.0.1:9001
DUR="${1:-30}"      # load window, seconds
WORKERS="${2:-4}"   # parallel load generators
CLK=$(getconf CLK_TCK 2>/dev/null || echo 100)

pid=$(pgrep -x rsbpd | head -1)
[ -n "$pid" ] || { echo "rsbpd not running — start it first"; exit 1; }
command -v curl >/dev/null || { echo "need curl"; exit 1; }

health(){ curl -s --noproxy '*' "$API/health" 2>/dev/null; }
jq_get(){ python3 -c "import json,sys;d=json.load(sys.stdin);print(eval('d'+'$1'))" 2>/dev/null; }
cpu_ticks(){ awk '{print $14+$15}' "/proc/$pid/stat" 2>/dev/null; }   # utime+stime
rss_mb(){ awk '/VmRSS/{printf "%.0f", $2/1024}' "/proc/$pid/status" 2>/dev/null; }

measure(){ # <label> <seconds>  -> prints "cpu_pct rss_mb eps lost_delta"
  local secs="$2"
  local t0 c0 e0 l0 t1 c1 e1 l1 h
  h=$(health); e0=$(echo "$h" | jq_get "['ebpf']['events_total']"); l0=$(echo "$h" | jq_get "['ebpf']['lost_events']")
  c0=$(cpu_ticks); t0=$(date +%s.%N)
  sleep "$secs"
  h=$(health); e1=$(echo "$h" | jq_get "['ebpf']['events_total']"); l1=$(echo "$h" | jq_get "['ebpf']['lost_events']")
  c1=$(cpu_ticks); t1=$(date +%s.%N)
  python3 - "$c0" "$c1" "$t0" "$t1" "$e0" "$e1" "$l0" "$l1" "$CLK" <<'PY'
import sys
c0,c1,t0,t1,e0,e1,l0,l1,clk=sys.argv[1:]
c0,c1=float(c0),float(c1); t0,t1=float(t0),float(t1)
e0,e1,l0,l1,clk=int(e0),int(e1),int(l0),int(l1),float(clk)
dt=max(t1-t0,1e-6)
cpu=(c1-c0)/clk/dt*100
eps=(e1-e0)/dt
print(f"{cpu:.1f} {eps:.0f} {l1-l0}")
PY
}

echo "RSBP overhead benchmark — pid=$pid, $(nproc) vCPU, load=${DUR}s x ${WORKERS} workers"
echo "-----------------------------------------------------------------------------"

# 1) idle baseline (5s)
read bcpu beps blost < <(measure idle 5)
brss=$(rss_mb)
printf "idle (5s):      CPU %5s%%   RSS %4s MB   events %6s/s   lost %s\n" "$bcpu" "$brss" "$beps" "$blost"

# 2) under load
echo "generating syscall load for ${DUR}s ..."
stop=$((SECONDS+DUR))
pids=()
for _ in $(seq 1 "$WORKERS"); do
  ( while [ "$SECONDS" -lt "$stop" ]; do
      python3 -c "import socket
for _ in range(200):
 s=socket.socket();s.settimeout(0.05)
 try:s.connect_ex(('127.0.0.1',9))
 except Exception:pass
 s.close()" 2>/dev/null
    done ) & pids+=($!)
done
sleep 2                     # let load ramp
read lcpu leps llost < <(measure load $((DUR-4)))
lrss=$(rss_mb)
for p in "${pids[@]}"; do wait "$p" 2>/dev/null; done
printf "under load:     CPU %5s%%   RSS %4s MB   events %6s/s   lost %s\n" "$lcpu" "$lrss" "$leps" "$llost"

echo "-----------------------------------------------------------------------------"
echo "Reading: CPU% is of one core (so ${lcpu}% ≈ $(python3 -c "print(round(${lcpu}/$(nproc),1))")% of this ${nproc:-?}-vCPU host)."
echo "events/s is the sustained kernel-event rate RSBP decoded; 'lost' > 0 means the"
echo "ring buffer overflowed under load. Report these exact numbers — do not round to zero."

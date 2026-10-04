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
NCPU=$(nproc)

pid=$(pgrep -x rsbpd | head -1)
[ -n "$pid" ] || { echo "rsbpd not running — start it first"; exit 1; }
command -v curl >/dev/null || { echo "need curl"; exit 1; }

# hv <k1> <k2> : read nested value d[k1][k2] from a /health JSON on stdin
hv(){ python3 -c "import json,sys
try:
 d=json.load(sys.stdin); print(d['$1']['$2'])
except Exception: print('')"; }
cpu_ticks(){ awk '{print $14+$15}' "/proc/$pid/stat" 2>/dev/null; }   # utime+stime
rss_mb(){ awk '/VmRSS/{printf "%.0f", $2/1024}' "/proc/$pid/status" 2>/dev/null; }

measure(){ # <seconds> -> prints "cpu_pct eps lost_delta"
  local secs="$1" h e0 l0 e1 l1 c0 c1 t0 t1
  h=$(curl -s --noproxy '*' "$API/health"); e0=$(printf '%s' "$h" | hv ebpf events_total); l0=$(printf '%s' "$h" | hv ebpf lost_events)
  c0=$(cpu_ticks); t0=$(date +%s.%N)
  sleep "$secs"
  h=$(curl -s --noproxy '*' "$API/health"); e1=$(printf '%s' "$h" | hv ebpf events_total); l1=$(printf '%s' "$h" | hv ebpf lost_events)
  c1=$(cpu_ticks); t1=$(date +%s.%N)
  python3 - "$c0" "$c1" "$t0" "$t1" "${e0:-0}" "${e1:-0}" "${l0:-0}" "${l1:-0}" "$CLK" <<'PY'
import sys
a=sys.argv
try:
 c0,c1=float(a[1]),float(a[2]); t0,t1=float(a[3]),float(a[4])
 e0,e1=int(float(a[5])),int(float(a[6])); l0,l1=int(float(a[7])),int(float(a[8])); clk=float(a[9])
 dt=max(t1-t0,1e-6)
 print(f"{(c1-c0)/clk/dt*100:.1f} {int((e1-e0)/dt)} {l1-l0}")
except Exception:
 print("n/a n/a n/a")
PY
}

echo "RSBP overhead benchmark — pid=$pid, ${NCPU} vCPU, load=${DUR}s x ${WORKERS} workers"
echo "-----------------------------------------------------------------------------"

read bcpu beps blost < <(measure 5); brss=$(rss_mb)
printf "idle (5s):      CPU %6s%%   RSS %4s MB   events %7s/s   lost %s\n" "$bcpu" "$brss" "$beps" "$blost"

echo "generating syscall load for ${DUR}s ..."
stop=$((SECONDS+DUR)); pids=()
for _ in $(seq 1 "$WORKERS"); do
  ( while [ "$SECONDS" -lt "$stop" ]; do
      python3 -c "import socket
for _ in range(200):
 s=socket.socket();s.settimeout(0.05)
 try: s.connect_ex(('127.0.0.1',9))
 except Exception: pass
 s.close()" 2>/dev/null
    done ) & pids+=($!)
done
sleep 2
read lcpu leps llost < <(measure $((DUR>6?DUR-4:2))); lrss=$(rss_mb)
for p in "${pids[@]}"; do wait "$p" 2>/dev/null; done
printf "under load:     CPU %6s%%   RSS %4s MB   events %7s/s   lost %s\n" "$lcpu" "$lrss" "$leps" "$llost"

echo "-----------------------------------------------------------------------------"
if [ "$lcpu" != "n/a" ]; then
  frac=$(python3 -c "print(round($lcpu/$NCPU,1))" 2>/dev/null || echo "?")
  echo "Reading: CPU% is of ONE core, so ${lcpu}% ≈ ${frac}% of this ${NCPU}-vCPU host."
fi
echo "events/s is the sustained kernel-event rate RSBP decoded; 'lost' > 0 means the ring"
echo "buffer overflowed under load (tunable via ebpf.ring_buffer_size). Report these exact"
echo "numbers — do not round to zero."

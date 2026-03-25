#!/usr/bin/env bash
set -euo pipefail

PID_FILE="/var/run/rsbp.pid"
BASELINE_FILE="/var/lib/rsbp/baseline.json"

if [[ "$(id -u)" -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    exec sudo -E bash "$0" "$@"
  fi
  echo "STOPPED: stop-rsbp.sh requires root (sudo not found)"
  exit 1
fi

if [[ ! -f "${PID_FILE}" ]]; then
  echo "STOPPED: pid file not found (${PID_FILE})"
  if [[ -f "${BASELINE_FILE}" ]]; then
    echo "baseline: present (${BASELINE_FILE})"
  else
    echo "baseline: missing (${BASELINE_FILE})"
  fi
  exit 0
fi

pid="$(cat "${PID_FILE}" 2>/dev/null || true)"
if [[ -z "${pid}" ]]; then
  echo "STOPPED: pid file was empty"
  rm -f "${PID_FILE}"
  exit 0
fi

if kill -0 "${pid}" >/dev/null 2>&1; then
  kill -INT "${pid}" >/dev/null 2>&1 || true
  for _ in $(seq 1 10); do
    if ! kill -0 "${pid}" >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done

  if kill -0 "${pid}" >/dev/null 2>&1; then
    kill -KILL "${pid}" >/dev/null 2>&1 || true
    echo "STOPPED: force-killed pid=${pid} after 10s timeout"
  else
    echo "STOPPED: graceful shutdown complete pid=${pid}"
  fi
else
  echo "STOPPED: process already not running pid=${pid}"
fi

rm -f "${PID_FILE}"

if [[ -f "${BASELINE_FILE}" ]]; then
  echo "baseline: present (${BASELINE_FILE})"
else
  echo "baseline: missing (${BASELINE_FILE})"
fi
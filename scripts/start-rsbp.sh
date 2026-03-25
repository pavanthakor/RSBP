#!/usr/bin/env bash
set -euo pipefail

BIN="./bin/rsbpd"
CONFIG="config/rsbp.yaml"
PID_FILE="/var/run/rsbp.pid"
DAEMON_LOG="/var/log/rsbp/daemon.log"
HEALTH_URL="http://127.0.0.1:9001/health"

if [[ "$(id -u)" -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    exec sudo -E bash "$0" "$@"
  fi
  echo "FAILED: start-rsbp.sh requires root (sudo not found)"
  exit 1
fi

if [[ "${PWD}" == /mnt/* ]] && [[ -z "${RSBP_ENV:-}" ]]; then
  export RSBP_ENV="prod"
fi

reason() {
  echo "FAILED: $1"
  exit 1
}

if pgrep -f "${BIN} run --config ${CONFIG}" >/dev/null 2>&1; then
  running_pid="$(pgrep -f "${BIN} run --config ${CONFIG}" | head -n1)"
  echo "STARTED: already running (pid=${running_pid})"
  exit 0
fi

mkdir -p /var/log/rsbp /var/lib/rsbp

touch "${DAEMON_LOG}" || reason "cannot write daemon log at ${DAEMON_LOG}"

nohup "${BIN}" run --config "${CONFIG}" >>"${DAEMON_LOG}" 2>&1 &
new_pid=$!
echo "${new_pid}" > "${PID_FILE}"

for _ in $(seq 1 10); do
  if curl -fsS "${HEALTH_URL}" >/dev/null 2>&1; then
    echo "STARTED: rsbpd is healthy (pid=${new_pid})"
    exit 0
  fi

  if ! kill -0 "${new_pid}" >/dev/null 2>&1; then
    tail -n 50 "${DAEMON_LOG}" || true
    reason "process exited before health check passed"
  fi

  sleep 1
done

tail -n 50 "${DAEMON_LOG}" || true
reason "health endpoint did not become ready within 10 seconds"
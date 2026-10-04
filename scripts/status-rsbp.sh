#!/usr/bin/env bash
set -euo pipefail

PID_FILE="/var/run/rsbp.pid"
ALERTS_FILE="/var/log/rsbp/alerts.jsonl"
HEALTH_URL="http://127.0.0.1:9001/health"
STATS_URL="http://127.0.0.1:9001/stats"
ES_COUNT_URL="http://localhost:9200/_count"

daemon_state="STOPPED"
daemon_pid=""
if [[ -f "${PID_FILE}" ]]; then
  pid="$(cat "${PID_FILE}" 2>/dev/null || true)"
  if [[ -n "${pid}" ]]; then
    if kill -0 "${pid}" >/dev/null 2>&1; then
      daemon_state="RUNNING"
      daemon_pid="${pid}"
    elif [[ -d "/proc/${pid}" ]]; then
      daemon_state="RUNNING"
      daemon_pid="${pid}"
    fi
  fi
fi

if [[ "${daemon_state}" == "RUNNING" ]]; then
  echo "daemon: RUNNING (pid=${daemon_pid})"
else
  echo "daemon: STOPPED"
fi

health_json="$(curl -fsS "${HEALTH_URL}" 2>/dev/null || true)"
stats_json="$(curl -fsS "${STATS_URL}" 2>/dev/null || true)"

if [[ -n "${health_json}" ]]; then
  uptime="$(echo "${health_json}" | sed -n 's/.*"uptime"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
  echo "uptime: ${uptime:-unknown}"
else
  echo "uptime: unavailable"
fi

if [[ -n "${stats_json}" ]]; then
  events_processed="$(echo "${stats_json}" | sed -n 's/.*"events_processed"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -n1)"
  echo "events_processed: ${events_processed:-unknown}"
else
  echo "events_processed: unavailable"
fi

today="$(date -u +%Y-%m-%d)"
alerts_today=0
if [[ -f "${ALERTS_FILE}" ]]; then
  alerts_today="$(grep -c "${today}" "${ALERTS_FILE}" || true)"
fi
echo "alerts today: ${alerts_today}"

es_count="$(curl -fsS "${ES_COUNT_URL}" 2>/dev/null | sed -n 's/.*"count"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -n1 || true)"
if [[ -n "${es_count}" ]]; then
  echo "ES documents: ${es_count}"
else
  echo "ES documents: unavailable"
fi

if [[ -f "${ALERTS_FILE}" ]]; then
  last_line="$(tail -n 1 "${ALERTS_FILE}" 2>/dev/null || true)"
  if [[ -n "${last_line}" ]]; then
    last_ts="$(echo "${last_line}" | sed -n 's/.*"timestamp"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
    last_sev="$(echo "${last_line}" | sed -n 's/.*"severity"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
    echo "last alert: timestamp=${last_ts:-unknown} severity=${last_sev:-unknown}"
  else
    echo "last alert: unavailable"
  fi
else
  echo "last alert: unavailable"
fi
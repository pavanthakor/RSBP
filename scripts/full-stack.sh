#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MONITORING_DIR="${ROOT_DIR}/deployments/monitoring"

DAEMON_START_SCRIPT="${ROOT_DIR}/scripts/start-rsbp.sh"
DAEMON_STOP_SCRIPT="${ROOT_DIR}/scripts/stop-rsbp.sh"
DAEMON_STATUS_SCRIPT="${ROOT_DIR}/scripts/status-rsbp.sh"

HEALTH_URL="http://127.0.0.1:9001/health"
ES_URL="http://127.0.0.1:9200"
GRAFANA_URL="http://127.0.0.1:3000"
KIBANA_URL="http://127.0.0.1:5601"

ACTION="${1:-up}"

if [[ "${ROOT_DIR}" == /mnt/* ]] && [[ -z "${RSBP_ENV:-}" ]]; then
  export RSBP_ENV="prod"
fi

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: missing required command: $1"
    exit 1
  }
}

wait_http_ok() {
  local url="$1"
  local name="$2"
  local retries="${3:-30}"
  local sleep_s="${4:-2}"

  local i
  for i in $(seq 1 "${retries}"); do
    if curl -fsS "${url}" >/dev/null 2>&1; then
      echo "OK: ${name} is reachable (${url})"
      return 0
    fi
    sleep "${sleep_s}"
  done

  echo "WARN: ${name} did not become ready in time (${url})"
  return 1
}

docker_compose() {
  if docker compose version >/dev/null 2>&1; then
    docker compose -f "${MONITORING_DIR}/docker-compose.yml" "$@"
    return
  fi
  if command -v docker-compose >/dev/null 2>&1; then
    docker-compose -f "${MONITORING_DIR}/docker-compose.yml" "$@"
    return
  fi
  echo "ERROR: neither 'docker compose' nor 'docker-compose' is available"
  exit 1
}

do_up() {
  echo "==> Building rsbpd binary"
  (cd "${ROOT_DIR}" && make build)

  echo "==> Starting monitoring stack (Elasticsearch, Kibana, Grafana, Filebeat)"
  docker_compose up -d

  echo "==> Waiting for Elasticsearch"
  wait_http_ok "${ES_URL}" "Elasticsearch" 45 2 || true

  echo "==> Starting rsbpd daemon"
  (cd "${ROOT_DIR}" && "${DAEMON_START_SCRIPT}")

  echo "==> Waiting for rsbpd health"
  wait_http_ok "${HEALTH_URL}" "RSBP daemon" 20 1 || true

  echo
  echo "==> Current daemon status"
  (cd "${ROOT_DIR}" && "${DAEMON_STATUS_SCRIPT}") || true

  echo
  echo "==> Service URLs"
  echo "RSBP Health : ${HEALTH_URL}"
  echo "Elasticsearch: ${ES_URL}"
  echo "Grafana      : ${GRAFANA_URL} (admin/rsbp123)"
  echo "Kibana       : ${KIBANA_URL}"
}

do_down() {
  echo "==> Stopping rsbpd daemon"
  (cd "${ROOT_DIR}" && "${DAEMON_STOP_SCRIPT}") || true

  echo "==> Stopping monitoring stack"
  docker_compose down
}

do_status() {
  echo "==> Daemon status"
  (cd "${ROOT_DIR}" && "${DAEMON_STATUS_SCRIPT}") || true

  echo
  echo "==> Monitoring containers"
  docker_compose ps || true

  echo
  echo "==> Endpoint checks"
  wait_http_ok "${HEALTH_URL}" "RSBP daemon" 1 0 || true
  wait_http_ok "${ES_URL}" "Elasticsearch" 1 0 || true
  wait_http_ok "${GRAFANA_URL}" "Grafana" 1 0 || true
  wait_http_ok "${KIBANA_URL}" "Kibana" 1 0 || true
}

do_logs() {
  echo "==> Daemon log tail"
  sudo tail -n 80 /var/log/rsbp/daemon.log || true

  echo
  echo "==> Monitoring logs tail"
  docker_compose logs --tail=120 || true
}

need_cmd curl
need_cmd docker
need_cmd make

case "${ACTION}" in
  up)
    do_up
    ;;
  down)
    do_down
    ;;
  restart)
    do_down
    do_up
    ;;
  status)
    do_status
    ;;
  logs)
    do_logs
    ;;
  *)
    echo "Usage: $0 {up|down|restart|status|logs}"
    exit 1
    ;;
esac

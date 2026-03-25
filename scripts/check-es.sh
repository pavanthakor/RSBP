#!/usr/bin/env bash

set -euo pipefail

ES_URL="${ES_URL:-http://localhost:9200}"
INDEX_PATTERN="${INDEX_PATTERN:-rsbp-alerts-*}"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: required command not found: $1" >&2
    exit 1
  }
}

require_cmd curl
require_cmd sed

extract_json_value() {
  local key="$1"
  sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\"\{0,1\}\([^\",}]*\)\"\{0,1\}.*/\1/p" | head -n 1
}

extract_count() {
  sed -n 's/.*"count"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -n 1
}

echo "Elasticsearch URL: ${ES_URL}"

cluster_health_json="$(curl -sS "${ES_URL}/_cluster/health")"
cluster_status="$(printf "%s" "$cluster_health_json" | extract_json_value "status")"
echo "Cluster health: ${cluster_status:-unknown}"

index_count="$(curl -sS "${ES_URL}/_cat/indices/${INDEX_PATTERN}?format=json" | grep -o '"index":"[^"]*"' | wc -l | tr -d ' ')"
total_docs="$(curl -sS "${ES_URL}/${INDEX_PATTERN}/_count" | extract_count)"
echo "Index count (${INDEX_PATTERN}): ${index_count:-0}"
echo "Total documents: ${total_docs:-0}"

docs_last_5m="$(curl -sS -X GET "${ES_URL}/${INDEX_PATTERN}/_count" -H "Content-Type: application/json" -d '{
  "query": {
    "range": {
      "@timestamp": {
        "gte": "now-5m",
        "lte": "now"
      }
    }
  }
}' | extract_count)"
docs_last_5m="${docs_last_5m:-0}"

if [[ "$docs_last_5m" =~ ^[0-9]+$ ]]; then
  ingest_rate=$((docs_last_5m / 5))
else
  ingest_rate=0
fi

echo "Ingest rate (docs/min over last 5 min): ${ingest_rate}"

oldest_json="$(curl -sS -X GET "${ES_URL}/${INDEX_PATTERN}/_search" -H "Content-Type: application/json" -d '{
  "size": 1,
  "sort": [{"@timestamp": {"order": "asc"}}],
  "_source": ["@timestamp", "timestamp"]
}')"
newest_json="$(curl -sS -X GET "${ES_URL}/${INDEX_PATTERN}/_search" -H "Content-Type: application/json" -d '{
  "size": 1,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "_source": ["@timestamp", "timestamp"]
}')"

oldest_ts="$(printf "%s" "$oldest_json" | sed -n 's/.*"@timestamp"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
newest_ts="$(printf "%s" "$newest_json" | sed -n 's/.*"@timestamp"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"

echo "Oldest @timestamp: ${oldest_ts:-n/a}"
echo "Newest @timestamp: ${newest_ts:-n/a}"

echo "Disk usage:"
curl -sS "${ES_URL}/_cat/allocation?v"

#!/usr/bin/env bash

set -euo pipefail

ES_URL="${ES_URL:-http://localhost:9200}"
SOURCE_PATTERN="rsbp-alerts-*"
DEST_INDEX="rsbp-alerts-clean"
WRITE_ALIAS="rsbp-current"

log() {
  echo "[setup] $*"
}

fail() {
  echo "[setup] ERROR: $*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

es_put() {
  local path="$1"
  local payload="$2"
  local code
  code="$(curl -sS -o /tmp/rsbp_es_resp.json -w "%{http_code}" -X PUT "${ES_URL}${path}" -H "Content-Type: application/json" -d "$payload")"
  if [[ "$code" != "200" && "$code" != "201" ]]; then
    echo "[setup] PUT ${path} failed (HTTP ${code})" >&2
    cat /tmp/rsbp_es_resp.json >&2 || true
    exit 1
  fi
}

es_post() {
  local path="$1"
  local payload="$2"
  local code
  code="$(curl -sS -o /tmp/rsbp_es_resp.json -w "%{http_code}" -X POST "${ES_URL}${path}" -H "Content-Type: application/json" -d "$payload")"
  if [[ "$code" != "200" && "$code" != "201" ]]; then
    echo "[setup] POST ${path} failed (HTTP ${code})" >&2
    cat /tmp/rsbp_es_resp.json >&2 || true
    exit 1
  fi
}

es_get_json() {
  local path="$1"
  curl -sS "${ES_URL}${path}"
}

extract_count() {
  sed -n 's/.*"count"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -n 1
}

extract_reindexed() {
  sed -n 's/.*"created"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -n 1
}

require_cmd curl
require_cmd sed

log "Checking Elasticsearch availability at ${ES_URL}"
curl -sS "${ES_URL}" >/dev/null || fail "cannot reach Elasticsearch at ${ES_URL}"

log "(1a) Setting number_of_replicas=0 for single-node cluster"
es_put "/_settings" '{"index":{"number_of_replicas":0}}'

log "(1b) Creating component template rsbp-mappings with explicit mappings"
es_put "/_component_template/rsbp-mappings" '{
  "template": {
    "mappings": {
      "dynamic": false,
      "properties": {
        "@timestamp": {"type": "date"},
        "timestamp": {"type": "date"},
        "id": {"type": "keyword"},
        "severity": {"type": "keyword"},
        "score": {"type": "float"},
        "pattern": {"type": "keyword"},
        "shell_category": {"type": "integer"},
        "suppressed": {"type": "boolean"},
        "suppress_reason": {"type": "keyword"},
        "fired_rules": {"type": "keyword"},
        "syscall_chain": {"type": "keyword"},
        "process": {
          "properties": {
            "pid": {"type": "long"},
            "ppid": {"type": "long"},
            "uid": {"type": "long"},
            "exe_path": {"type": "keyword"},
            "cmdline": {
              "type": "text",
              "fields": {
                "keyword": {"type": "keyword", "ignore_above": 4096}
              }
            },
            "comm": {"type": "keyword"}
          }
        },
        "network": {
          "properties": {
            "remote_ip": {"type": "ip"},
            "remote_port": {"type": "keyword"},
            "country": {"type": "keyword"},
            "asn_org": {"type": "keyword"},
            "is_vpn": {"type": "boolean"},
            "is_tor": {"type": "boolean"},
            "reputation_score": {"type": "integer"}
          }
        },
        "mitre_techniques": {
          "properties": {
            "id": {"type": "keyword"},
            "name": {"type": "keyword"}
          }
        },
        "host_info": {
          "properties": {
            "hostname": {"type": "keyword"},
            "os": {"type": "keyword"},
            "kernel_version": {"type": "keyword"}
          }
        }
      }
    }
  },
  "version": 1
}'

log "(1c) Creating ILM policy rsbp-policy (rollover: 10GB or 30d, delete: 30d)"
es_put "/_ilm/policy/rsbp-policy" '{
  "policy": {
    "phases": {
      "hot": {
        "actions": {
          "rollover": {
            "max_size": "10gb",
            "max_age": "30d"
          }
        }
      },
      "delete": {
        "min_age": "30d",
        "actions": {
          "delete": {}
        }
      }
    }
  }
}'

log "(1d) Creating index template rsbp-template using rsbp-mappings + ILM"
es_put "/_index_template/rsbp-template" '{
  "index_patterns": ["rsbp-alerts-*"],
  "priority": 500,
  "composed_of": ["rsbp-mappings"],
  "template": {
    "settings": {
      "index": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "lifecycle": {
          "name": "rsbp-policy",
          "rollover_alias": "rsbp-current"
        }
      }
    }
  }
}'

log "(2) Reindex existing data to ${DEST_INDEX} with explicit mappings"
source_count="$(es_get_json "/${SOURCE_PATTERN}/_count" | extract_count)"
source_count="${source_count:-0}"
log "Source document count before reindex: ${source_count}"

curl -sS -X DELETE "${ES_URL}/${DEST_INDEX}" >/dev/null || true

es_put "/${DEST_INDEX}" '{
  "settings": {
    "index": {
      "number_of_shards": 1,
      "number_of_replicas": 0,
      "lifecycle": {
        "name": "rsbp-policy",
        "rollover_alias": "rsbp-current"
      }
    }
  },
  "mappings": {
    "dynamic": false,
    "properties": {
      "@timestamp": {"type": "date"},
      "timestamp": {"type": "date"},
      "id": {"type": "keyword"},
      "severity": {"type": "keyword"},
      "score": {"type": "float"},
      "pattern": {"type": "keyword"},
      "shell_category": {"type": "integer"},
      "suppressed": {"type": "boolean"},
      "suppress_reason": {"type": "keyword"},
      "fired_rules": {"type": "keyword"},
      "syscall_chain": {"type": "keyword"},
      "process": {
        "properties": {
          "pid": {"type": "long"},
          "ppid": {"type": "long"},
          "uid": {"type": "long"},
          "exe_path": {"type": "keyword"},
          "cmdline": {
            "type": "text",
            "fields": {
              "keyword": {"type": "keyword", "ignore_above": 4096}
            }
          },
          "comm": {"type": "keyword"}
        }
      },
      "network": {
        "properties": {
          "remote_ip": {"type": "ip"},
          "remote_port": {"type": "keyword"},
          "country": {"type": "keyword"},
          "asn_org": {"type": "keyword"},
          "is_vpn": {"type": "boolean"},
          "is_tor": {"type": "boolean"},
          "reputation_score": {"type": "integer"}
        }
      },
      "mitre_techniques": {
        "properties": {
          "id": {"type": "keyword"},
          "name": {"type": "keyword"}
        }
      },
      "host_info": {
        "properties": {
          "hostname": {"type": "keyword"},
          "os": {"type": "keyword"},
          "kernel_version": {"type": "keyword"}
        }
      }
    }
  }
}'

reindex_result="$(curl -sS -X POST "${ES_URL}/_reindex?wait_for_completion=true" -H "Content-Type: application/json" -d '{
  "source": {"index": "rsbp-alerts-*"},
  "dest": {"index": "rsbp-alerts-clean"}
}')"

reindexed_created="$(printf "%s" "$reindex_result" | extract_reindexed)"
reindexed_created="${reindexed_created:-0}"
dest_count="$(es_get_json "/${DEST_INDEX}/_count" | extract_count)"
dest_count="${dest_count:-0}"

log "Reindex created docs: ${reindexed_created}"
log "Destination document count: ${dest_count}"

if [[ "$source_count" != "$dest_count" ]]; then
  fail "count mismatch after reindex (source=${source_count}, dest=${dest_count})"
fi

log "Counts match after reindex"

log "Updating alias ${WRITE_ALIAS} -> ${DEST_INDEX}"
curl -sS -X POST "${ES_URL}/_aliases" -H "Content-Type: application/json" -d '{
  "actions": [
    {"remove": {"index": "*", "alias": "rsbp-current", "ignore_unavailable": true}},
    {"add": {"index": "rsbp-alerts-clean", "alias": "rsbp-current", "is_write_index": true}}
  ]
}' >/tmp/rsbp_alias_resp.json

if ! grep -q '"acknowledged"[[:space:]]*:[[:space:]]*true' /tmp/rsbp_alias_resp.json; then
  cat /tmp/rsbp_alias_resp.json >&2 || true
  fail "failed to update alias rsbp-current"
fi

log "(3) Verifying live ingestion over 30 seconds"
before_count="$(es_get_json "/${WRITE_ALIAS}/_count" | extract_count)"
before_count="${before_count:-0}"
sleep 30
after_count="$(es_get_json "/${WRITE_ALIAS}/_count" | extract_count)"
after_count="${after_count:-0}"

if [[ "$after_count" -gt "$before_count" ]]; then
  delta=$((after_count - before_count))
  echo "LIVE INGESTION: OK (+${delta} documents)"
else
  echo "WARNING: No new documents in 30s"
fi

log "Elasticsearch setup completed successfully"

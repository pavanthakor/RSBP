#!/usr/bin/env bash
set -euo pipefail

echo "[verify] pwd: $(pwd)"

if [[ "$(pwd)" == /mnt/* ]]; then
  echo "❌ INVALID WORKSPACE: Running from /mnt"
  exit 1
fi

if [[ ! -f go.mod ]]; then
  echo "[verify][ERROR] go.mod not found in current directory"
  exit 1
fi

gomod_path="$(go env GOMOD)"
gomod_dir="$(dirname "$gomod_path")"

if [[ "$gomod_dir" != "$(pwd)" ]]; then
  echo "[verify][ERROR] cwd/go.mod mismatch"
  echo "  cwd      : $(pwd)"
  echo "  GOMOD dir: $gomod_dir"
  exit 1
fi

echo "[verify] go.mod: $gomod_path"
echo "[verify] GOPATH: $(go env GOPATH)"
echo "[verify] GOCACHE: $(go env GOCACHE)"
echo "[verify] GOMODCACHE: $(go env GOMODCACHE)"
echo "[verify] GOOS/GOARCH: $(go env GOOS)/$(go env GOARCH)"
echo "[verify] filesystem type: $(stat -f -c '%T' .)"

echo "[verify] cleaning caches..."
go clean -cache
go clean -modcache
go clean -testcache

echo "[verify] resolving modules..."
go mod tidy
go mod verify

echo "[verify] fresh build..."
go build ./...

echo "[verify] fresh tests..."
go test ./...

echo "ENVIRONMENT CONSISTENT"

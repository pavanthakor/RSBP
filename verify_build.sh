#!/usr/bin/env bash
set -euo pipefail

cwd="$(pwd)"
gomod="$(go env GOMOD)"
gomod_dir="$(dirname "$gomod")"

printf '[verify-build] cwd=%s\n' "$cwd"
printf '[verify-build] go.mod=%s\n' "$gomod"
printf '[verify-build] go version=%s\n' "$(go version)"

if [[ ! -f "$cwd/go.mod" ]]; then
  echo "[verify-build][ERROR] go.mod missing in cwd"
  exit 1
fi

if [[ "$gomod_dir" != "$cwd" ]]; then
  echo "[verify-build][ERROR] cwd and GOMOD directory mismatch"
  echo "  cwd      : $cwd"
  echo "  GOMOD dir: $gomod_dir"
  exit 1
fi

if [[ "$cwd" == /mnt/* ]]; then
  echo "[verify-build][WARN] workspace is on /mnt (Windows mount via WSL)."
  echo "[verify-build][WARN] For deterministic gopls/build behavior, prefer native Linux path: ~/rsbp"
fi

echo "[verify-build] cleaning caches"
go clean -cache
go clean -modcache
go clean -testcache

echo "[verify-build] resolving modules"
go mod tidy
go mod verify

echo "[verify-build] build"
go build ./...

echo "[verify-build] test"
go test ./...

echo "ENVIRONMENT CONSISTENT"

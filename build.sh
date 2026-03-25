#!/bin/bash

set -e

WD=$(pwd)

if [[ "$WD" == /mnt/* ]]; then
  echo "❌ ERROR: Building from /mnt is not allowed."
  echo "Move project to ~/rsbp:"
  echo "  mv $WD ~/rsbp"
  exit 1
fi

echo "✅ Workspace OK: $WD"

echo "🔧 Cleaning..."
go clean -cache -modcache -testcache

echo "📦 Tidying modules..."
go mod tidy

echo "🏗 Building..."
go build ./...

echo "🧪 Running tests..."
go test ./...

echo "✅ Build complete"

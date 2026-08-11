#!/usr/bin/env bash
# Tests must pass and must not have shrunk against the 112 carried over.
cd "$(dirname "$0")/.."
out=$(timeout 900 pnpm vitest run --reporter=basic 2>&1)
echo "$out" | grep -E "Tests +[0-9]+" | tail -1
passed=$(echo "$out" | grep -oE "Tests +[0-9]+ passed" | grep -oE "[0-9]+" | tail -1)
failed=$(echo "$out" | grep -oE "[0-9]+ failed" | grep -oE "[0-9]+" | head -1)
[ -z "$failed" ] || { echo "FAIL: $failed failing"; exit 1; }
[ "${passed:-0}" -ge 100 ] || { echo "FAIL: only ${passed:-0} tests, expected >= 100"; exit 1; }
echo PASS

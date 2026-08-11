#!/usr/bin/env bash
# Every module present, and zero InFlow references anywhere in src.
cd "$(dirname "$0")/.."
missing=0
for m in envelope allowance credential intent ledger store enforcement gate storage index; do
  [ -s "src/$m.ts" ] || { echo "MISSING src/$m.ts"; missing=1; }
done
[ "$missing" -eq 0 ] || { echo FAIL; exit 1; }
hits=$(grep -ril "inflow" src/ 2>/dev/null | wc -l)
echo "modules=10 inflow_references=$hits"
[ "$hits" -eq 0 ] || { echo "FAIL: InFlow referenced in $(grep -ril inflow src/)"; exit 1; }
echo PASS

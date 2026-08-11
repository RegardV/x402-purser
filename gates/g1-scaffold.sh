#!/usr/bin/env bash
cd "$(dirname "$0")/.."
for f in package.json tsconfig.json vitest.config.ts LICENSE README.md; do
  [ -s "$f" ] || { echo "FAIL: $f missing or empty"; exit 1; }
done
grep -q "Apache License" LICENSE || { echo "FAIL: LICENSE is not Apache-2.0"; exit 1; }
python3 -c "
import json,sys
d=json.load(open('package.json'))
assert d['name']=='purser', 'name must be purser'
assert d.get('license')=='Apache-2.0', 'license field must be Apache-2.0'
assert 'inflow' not in json.dumps(d).lower(), 'no inflow dependency permitted'
print('package.json ok')"
echo PASS

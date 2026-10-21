#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
node --check --input-type=module < nginx/php-uploadprogress.njs
node tests/test_njs.mjs
python3 -m json.tool aws/php-uploadprogress-r1.json > /dev/null
echo 'Static and mock checks passed. Engine validation remains pending.'

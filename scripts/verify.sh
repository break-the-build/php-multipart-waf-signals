#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
node --check --input-type=module < nginx/php-multipart-signals.njs
node tests/test_njs.mjs
PYTHONDONTWRITEBYTECODE=1 python3 scripts/benign_detection_poc.py
python3 -m json.tool aws/php-multipart-r1.json > /dev/null
echo 'Static and mock checks passed. Engine validation remains pending.'

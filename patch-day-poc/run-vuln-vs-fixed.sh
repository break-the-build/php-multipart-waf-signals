#!/bin/bash
# Patch-day PoC: differential behavior of the released CVE-class regression tests
# on a VULNERABLE vs FIXED PHP binary. Runs upstream's own tests — the ones the
# PHP security team added with the 2026-10-21 fix — under both binaries with
# identical inputs. No exploit code, no payloads; inert regression fixtures only.
#
# Runs INSIDE the research sandbox (php-asan-build image; trees at /src).
#
#   bash run-vuln-vs-fixed.sh <runner-tree> <vuln-tree> <fixed-tree> [fixed-tree2 ...]
# Example:
#   bash run-vuln-vs-fixed.sh /src/php-8.4.27 /src/php-8.4.26 /src/php-8.4.27 /src/php-8.2.35
#
# Output: verdict rows per tree + archived logs; also a summary markdown.
set -u
RUNNER="${1:?runner-tree with run-tests.php and the CVE tests}"; shift
VULN="${1:?vulnerable-tree}"; shift
OUTDIR="${OUTDIR:-/src/artifacts/patch-day-poc}"
mkdir -p "$OUTDIR/logs"
ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:log_path=/tmp/asan-poc"
export ASAN_OPTIONS

# files must be a SPACE-separated list (a newline-string becomes one filename)
RFC_FILES="ext/session/tests/rfc1867_sid_invalid.phpt ext/session/tests/rfc1867_incomplete_class_reserved_props.phpt ext/session/tests/rfc1867_no_user_code.phpt tests/basic/oom_rfc1867_upload_progress.phpt"

# OOM lifecycle set = the tests the patch added (runner tree; vulnerable tree
# lacks them, so the FIXED tree's copies run against the VULNERABLE binary)
cd "$RUNNER" || exit 1
OOM=$(ls Zend/tests/oom_*.phpt 2>/dev/null)
OOM_STD=$(find ext/standard -name "oom_*.phpt" 2>/dev/null | head -12)

run_suite() { # tree label testfiles...
  local tree="$1" label="$2"; shift 2
  (
    cd "$RUNNER"
    TEST_PHP_EXECUTABLE="$tree/sapi/cli/php" "${tree%/}/sapi/cli/php" run-tests.php \
      -d memory_limit=128M "$@"
  ) > "$OUTDIR/logs/$label.txt" 2>&1
  local fail pass
  fail=$(awk '/^Tests failed/ {print $4}' "$OUTDIR/logs/$label.txt" | head -1)
  pass=$(awk '/^Tests passed/ {print $4}' "$OUTDIR/logs/$label.txt" | head -1)
  printf "| %s | %s passed | %s failed |\n" "$tree" "${pass:-?}" "${fail:-?}"
}

{
echo "# Patch-day PoC — differential (upstream tests, vulnerable vs fixed binaries)"
echo "Run: $(date -u)"
echo
echo "| Tree | rfc1867 ×3 | OOM lifecycle |"
echo "|---|---|---|"
} > "$OUTDIR/differential.md"

for TREE in "$VULN" "$@"; do
  R=$(run_suite "$TREE" "rfc-$(basename "$TREE")" $RFC_FILES)
  O=$(run_suite "$TREE" "oom-$(basename "$TREE")" $OOM $OOM_STD)
  echo "$TREE:"; echo "$R"; echo "$O"
done
echo
echo "logs: $OUTDIR/logs/"

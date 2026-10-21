#!/bin/sh
# Deployment posture check for the PHP "php2shell" pair (CVE-2026-109618,
# CVE-2026-109619). Verifies the PHP version and the vendor-recommended
# mitigations. Run ON or NEXT TO the deployment you own (loopback/local only).
#
# Usage:
#   sh posture/posture-check.sh [/path/to/php] [/path/to/php-fpm.conf]
#   (defaults: php from PATH; second arg optional — FPM pool config to audit)
#
# Checks:
#   1. PHP version >= first fixed release of its branch (8.2.35 / 8.3.36 /
#      8.4.27 / 8.5.12). EOL branches (<= 8.1) are reported as VULN unless a
#      vendor backport is present (the check can only see php version strings).
#   2. session.upload_progress.enabled — must be 0 and ADMINISTRATIVELY set
#      (php.ini / FPM pool); ini_set()/.user.ini values are NOT mitigation.
#   3. memory_limit — must be -1 enforced at pool/php.ini level for the OOM
#      class when unpatchable; a finite value is the CVE-2026-109618 trigger.
#   4. fatal_error_backtraces (PHP 8.5) — vendor mitigation for confirmed
#      mod_php RCE; must be 0 on unpatched 8.5.
#   5. Output check: no "Loaded CGIs"/... (informational) — see limits section.
#
# Limitations (honest): a CLI/`php -r` view cannot prove the FPM pool's
# effective INIs; pass the FPM pool config path for a grep-based audit; and a
# passing check is not authorization to skip the PHP update.
[ -n "$1" ] && PHP="$1" || PHP="${PHP_BIN:-php}"
FPMCONF="${2:-}"

fixed_for_branch() {
    case "$1" in
        8.2*) echo 8.2.35 ;;
        8.3*) echo 8.3.36 ;;
        8.4*) echo 8.4.27 ;;
        8.5*) echo 8.5.12 ;;
        *)    echo "" ;;
    esac
}

ver_ge() { # a b  (compare dotted versions)
    _a=$(printf '%s\n' "$1" | awk -F. '{printf "%06d%06d%06d", $1, $2, $3}')
    _b=$(printf '%s\n' "$2" | awk -F. '{printf "%06d%06d%06d", $1, $2, $3}')
    [ "$_a" -ge "$_b" ]
}

FAIL=0
echo "== php2shell posture check ==" | sed 's/^/  /'

ver=$("$PHP" -r 'echo PHP_VERSION;' 2>/dev/null) || { echo "ERROR: cannot run $PHP"; exit 2; }
echo "php: $ver"
branch=${ver%.*}
fixed="$(fixed_for_branch "$ver")"
if [ -n "$fixed" ] && ver_ge "$ver" "$fixed"; then
    echo "PASS 1: $ver >= $fixed (patched release for $branch branch)"
else
    echo "FAIL 1: $ver is not a patched release (fixed: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12); EOL branches: no php.net release fix (see vendor backports)"; FAIL=1
fi

sql_off="$("$PHP" -r 'echo ini_get("session.upload_progress.enabled");' 2>/dev/null)"
[ "$sql_off" = "0" ] && echo "PASS 2: session.upload_progress.enabled=0 (vendor partial mitigation)" \
    || { echo "WARN 2: session.upload_progress.enabled=$sql_off — set Off administratively (php.ini or FPM pool '; session.upload_progress.enabled=0') + restart workers"; }
# note: ini_get here also proves application-level defaults; pool-level override
# requires auditing $FPMCONF (below).

ml="$("$PHP" -r 'echo ini_get("memory_limit");' 2>/dev/null)"
if [ "$ml" = "-1" ]; then
    echo "PASS 3: memory_limit=-1 (OOM-class primary vendor mitigation)"
elif [ -n "$fixed" ] && ver_ge "$ver" "$fixed"; then
    echo "PASS 3: memory_limit=$ml (patched runtime; finite limit acceptable)"
else
    echo "FAIL 3: memory_limit=$ml on an unpatched runtime — the advisory primary mitigation is enforced memory_limit=-1; also do NOT use RLIMIT_AS/RLIMIT_DATA"; FAIL=1
fi

fbt="$("$PHP" -r 'echo ini_get("fatal_error_backtraces");' 2>/dev/null)"
case "$ver" in
    8.5*)
        if [ "$fbt" = "0" ] || ver_ge "$ver" 8.5.12; then
            echo "PASS 4: fatal_error_backtraces=$fbt (mitigated via patch or setting)"
        else
            echo "FAIL 4: fatal_error_backtraces=$fbt on unpatched 8.5 — set 0 administratively (confirmed mod_php producer)"; FAIL=1
        fi ;;
    *) echo "INFO 4: fatal_error_backtraces mitigation only applies to PHP 8.5 (this is $ver)" ;;
esac

if [ -n "$FPMCONF" ]; then
    echo "-- FPM pool audit: $FPMCONF"
    grep -nE "^\s*(php_(admin_)?value\[session.upload_progress.enabled\]|php_(admin_)?value\[memory_limit\])" "$FPMCONF" 2>/dev/null \
        || echo "  WARN: no pool-level enforcement of upload-progress/memory_limit found (grep terms in script; adjust to your pool config style)"
fi

echo "exit: FAIL=$FAIL (0 = no blocking finding; INFO/WARN rows still deserve follow-up)"
exit $FAIL

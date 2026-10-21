# PHP upload-progress request-shape rules

Defensive WAF and IDS examples for deployments reviewing PHP's `session.upload_progress` feature. As of the official PHP security release of 2026-10-21 14:00 UTC, CVE-2026-109619 maps to a *stale global state* consumer class that includes the session upload-progress lifecycle (an upstream-confirmed producer/consumer window running before normal initialization), and CVE-2026-109618 maps to a distinct OOM/`longjmp` corruption class that this feature is not required for. Local PHP research demonstrated a stale top-level cached-pointer write and negative ASan/UBSan runs for the cached-pointer path — that specific chain is not the released fix's mechanism.

These rules identify traffic patterns for investigation. They are not a substitute for a PHP security update or proof that a request is malicious.

## Shipped rules

| File | Scope | Status |
|---|---|---|
| [`modsecurity/php-uploadprogress.conf`](modsecurity/php-uploadprogress.conf) | Parsed multipart field names, plus an optional size heuristic | Needs ModSecurity v3/connector validation. R4 deny-all is commented out. |
| [`suricata/php-uploadprogress.rules`](suricata/php-uploadprogress.rules) | Field-name pair, size heuristic, plus CVE-2026-109618 OOM-strategy shapes (header-storm, no-usable-Content-Length) and a CVE-2026-109619 producer/consumer sequencing approximation (xbits by source) | `suricata -T` SYNTAX-CLEAN on Suricata 7.0.10 for the current four-rule file (transcript: `suricata/syntax-check-suricata7.txt`). Traffic replay still pending. No counting claims. |
| [`nginx/php-uploadprogress.njs`](nginx/php-uploadprogress.njs) | njs `js_access` handler using parsed multipart fields | Mock-tested; needs nginx/njs staging validation. |
| [`aws/php-uploadprogress-r1.json`](aws/php-uploadprogress-r1.json), [`aws/php-uploadprogress-oom.json`](aws/php-uploadprogress-oom.json) | AWS WAF v2 field-name pair; OOM body-probe additions (method + multipart + progress field + body > 5 MiB) | JSON and structural tests pass; AWS API validation pending. |
| [`scripts/detection_rules.py`](scripts/detection_rules.py) | Offline inert request classifier | Python unit-tested. This is a model, not a deployed WAF rule. |

[Platform notes](docs/detection-platforms.md) map each rule to its actual coverage. [Tuning guidance](TUNING.md) lists body-inspection and false-positive limits.

## Rule meanings

- **R1:** a multipart POST with both `PHP_SESSION_UPLOAD_PROGRESS` and `PHPSESSID` body field names. Both can be legitimate in a specific application.
- **R2:** at least 40 repeated `t[]` names in the offline Python model. No shipped engine rule counts these within one request.
- **R3:** upload-progress field plus a body of at least 5 MiB. This is only a size heuristic, not an OOM detector.
- **R4:** optional denial of all progress-field uploads where the application never uses the feature. It is disabled by default and would reject the entire request.

The PHP configuration setting `session.upload_progress.enabled = Off` (enforced administratively, then restart workers) disables progress tracking while ordinary uploads continue. The primary research workspace tested that feature-path control on five local PHP builds. Per the 2026-10-21 advisory this blocks the confirmed upload-progress producing/consuming operations of CVE-2026-109619 and is considered prudent even after patching — but it is NOT a complete mitigation (the OOM class of CVE-2026-109618 is unaffected by it).

## Local checks

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
node tests/test_njs.mjs
python3 -m json.tool aws/php-uploadprogress-r1.json > /dev/null
```

These checks do **not** run a ModSecurity, Suricata, nginx, or AWS engine. Validate configuration and replay representative benign and matching requests in a staging environment before enabling blocking.

For njs 0.9.9 or newer, an example access-phase placement is:

```nginx
js_import waf from /absolute/path/php-uploadprogress.njs;
location /upload/ {
    js_access waf.checkUploadProgress;
    proxy_pass http://your_existing_upstream;
}
```

Use the application's actual location and upstream. `js_access` grants access when the handler returns without `r.return()`; `js_content` would replace the normal content handler and is not appropriate for this rule.

## Provenance and limits

The request shapes were informed by local source analysis and an untrusted public writeup. No third-party research code was executed to build this rule pack.

## Patch-day status (official release 2026-10-21 14:00 UTC)

- Advisories: [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) (CVE-2026-109618, OOM `longjmp` corruption) and [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) (CVE-2026-109619, stale global state; session upload-progress lifecycle confirmed among the affected paths). Release notice: [php.net archive](https://www.php.net/archive/2026.php#2026-10-21-5).
- Fixed versions: **8.2.35, 8.3.36, 8.4.27, 8.5.12**; minimal backports exist as `PHP-7.4/8.0/8.1-CVE-2026-109618-109619` branches.
- Vendor operational guidance shipped with the advisories (full text at the links): enforce `memory_limit=-1` administratively for the OOM class; keep `post_max_size` conservative and enforce decoded request size at the frontend; do **not** use `RLIMIT_AS`/`RLIMIT_DATA`; consider `pm.max_requests=1`; prefer startup `php.ini`/pool settings over per-request overrides; remove diagnostics from pre-init INI application; on PHP 8.5 set `fatal_error_backtraces=0`; audit with `log_errors=On` and `error_reporting=E_ALL`.
- Post-patch rule posture: upstream's fix removes the pre-executor decode/class-resolution machinery these shapes escalated against (see `ext/session/tests/rfc1867_no_user_code.phpt` upstream). Downgrade R1–R3 to observe on patched fleets; R4 remains optional (the vendor itself recommends the INI stopgap for fleets not using progress bars, even post-patch).
- See [docs/verification-2026-10-21.md](docs/verification-2026-10-21.md) for the local verification record and remaining engine-validation gates.

See [docs/detection-platforms.md](docs/detection-platforms.md) for the OOM/sequencing rule notes added on advisory day.

License: MIT, see [LICENSE](LICENSE).

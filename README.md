# PHP upload-progress request-shape rules

Defensive WAF and IDS examples for deployments reviewing PHP's `session.upload_progress` feature. The [PHP advisories](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) describe a cross-request session upload-progress path under CVE-2026-109619 and a distinct OOM/`longjmp` class under [CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w). [Wiz Research](https://www.wiz.io/blog/php2shell-php-rce) also reports an upload-progress unserializer variant in its 109618 grouping and a WordPress OPcache variant in its 109619 grouping. The request shapes in this repository have **not** been validated as signatures for any of those variants. Local PHP research demonstrated a stale cached-pointer write but no sanitizer-detected use-after-free access for that separate observation.

These rules identify traffic patterns for investigation and now default to observation. They are not a substitute for a PHP security update or proof that a request is malicious. The WordPress/OPcache, fatal-error-backtrace and other non-upload paths can occur without the fields matched here.

## Shipped rules

| File | Scope | Status |
|---|---|---|
| [`modsecurity/php-uploadprogress.conf`](modsecurity/php-uploadprogress.conf) | Parsed multipart field names, size heuristic and other advisory-inspired observations | R1/R3/R5/R7 log without denial. Needs ModSecurity v3/connector validation. Optional R4 deny-all is commented out. |
| [`suricata/php-uploadprogress.rules`](suricata/php-uploadprogress.rules) | Field-name pair, size heuristic and multipart part-header inflation alert | Current three-rule file has not been engine-checked. The archived Suricata 7.0.10 syntax transcript applies to the previous four-rule revision. Traffic replay is pending. |
| [`nginx/php-uploadprogress.njs`](nginx/php-uploadprogress.njs) | Observation-only njs `js_access` handler using parsed multipart fields | Mock-tested; needs nginx/njs staging validation. Logs do not deny requests. |
| [`aws/php-uploadprogress-r1.json`](aws/php-uploadprogress-r1.json) | AWS WAF v2 field-name pair example | Uses `Count`. JSON and structural tests pass; AWS API validation pending. The former 5 MiB body-size example was retired because AWS body inspection is capped far below that threshold. |
| [`scripts/detection_rules.py`](scripts/detection_rules.py) | Offline inert request classifier | Python unit-tested. This is a model, not a deployed WAF rule. |

[Platform notes](docs/detection-platforms.md) map each rule to its actual coverage. [Tuning guidance](TUNING.md) lists body-inspection and false-positive limits.

For an operational reading order, start with the [practitioner guide](docs/practitioner-guide.md), then review the [platform matrix](docs/detection-platforms.md) and [tuning notes](TUNING.md).

## Rule meanings

- **R1:** a multipart POST with both `PHP_SESSION_UPLOAD_PROGRESS` and `PHPSESSID` body field names. Both can be legitimate in a specific application.
- **R2:** at least 40 repeated `t[]` names in the offline Python model. No shipped engine rule counts these within one request.
- **R3:** upload-progress field plus a body of at least 5 MiB. This is only a size heuristic, not an OOM detector.
- **R4:** optional denial of all progress-field uploads where the application never uses the feature. It is disabled by default and would reject the entire request.

The PHP configuration setting `session.upload_progress.enabled = Off` (enforced administratively, then restart workers) disables progress tracking while ordinary uploads continue. The primary research workspace tested that feature-path control on five local PHP builds. Per PHP's advisory this blocks the confirmed upload-progress producing/consuming operations of CVE-2026-109619, but it is not a complete mitigation for other paths or CVE-2026-109618.

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

The request shapes were informed by local source analysis and public advisories. The [source and coverage update](docs/detection-platforms.md) distinguishes the published Wiz/Google research from the local cached-pointer observation. No third-party research code was executed to build this rule pack.

## Patch-day status (official release 2026-10-21 14:00 UTC)

- Advisories: [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) (CVE-2026-109618, OOM `longjmp` corruption) and [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) (CVE-2026-109619, stale global state; session upload-progress lifecycle confirmed among the affected paths). Release notice: [php.net archive](https://www.php.net/archive/2026.php#2026-10-21-5).
- Fixed versions: **8.2.35, 8.3.36, 8.4.27, 8.5.12**; minimal backports exist as `PHP-7.4/8.0/8.1-CVE-2026-109618-109619` branches.
- Vendor operational guidance shipped with the advisories (full text at the links): enforce `memory_limit=-1` administratively for the OOM class; keep `post_max_size` conservative and enforce decoded request size at the frontend; do **not** use `RLIMIT_AS`/`RLIMIT_DATA`; consider `pm.max_requests=1`; prefer startup `php.ini`/pool settings over per-request overrides; remove diagnostics from pre-init INI application; on PHP 8.5 set `fatal_error_backtraces=0`; audit with `log_errors=On` and `error_reporting=E_ALL`.
- Post-patch rule posture: keep R1–R3 as observations, and consider optional R4 only for applications that do not use upload progress. Upstream changes early initialization and upload-progress decoding behavior; the local request-shape rules do not demonstrate patch efficacy.
- See [docs/verification-2026-10-21.md](docs/verification-2026-10-21.md) for the local verification record and remaining engine-validation gates.

See [docs/detection-platforms.md](docs/detection-platforms.md) for the current coverage matrix and response-side investigation notes.

License: MIT, see [LICENSE](LICENSE).

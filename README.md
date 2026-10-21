# PHP multipart request-shape WAF/IDS signals

**Scope correction:** This project began with a cached-`zval *` observation in PHP's session upload-progress callback. That earlier finding was **separate from the vulnerabilities disclosed as CVE-2026-109618 and CVE-2026-109619**; local sanitizer tests did not establish a use-after-free for it. After the disclosures, we revised the WAF and IDS rules and documentation around the published issue classes: OOM/`longjmp` corruption ([CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)) and cross-request stale state ([CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)). Some disclosed paths involve upload progress; others do not.

The updated rules provide **observation-only signals for selected multipart request shapes** relevant to the disclosed research. They are not validated exploit signatures, do not cover every published variant, and cannot establish that a request triggered either CVE. [Wiz Research](https://www.wiz.io/blog/php2shell-php-rce) describes additional upload-progress, fatal-error-backtrace and WordPress OPcache variants outside this pack's reliable detection scope. Apply a fixed PHP runtime; use these rules to investigate traffic, not as a substitute for patching.

## Shipped rules

| File | Scope | Status |
|---|---|---|
| [`modsecurity/php-multipart-signals.conf`](modsecurity/php-multipart-signals.conf) | Parsed multipart field names, size heuristic and other advisory-inspired observations | R1/R3/R5/R7 log without denial. Needs ModSecurity v3/connector validation. Optional R4 deny-all is commented out. |
| [`suricata/php-multipart-signals.rules`](suricata/php-multipart-signals.rules) | Field-name pair, size heuristic and multipart part-header inflation alert | Engine-checked: Suricata 7.0.10 `-T` — 3/3 loaded, 0 failed, transcript `suricata/syntax-check-suricata7.txt` (this revision). Traffic replay pending. |
| [`nginx/php-multipart-signals.njs`](nginx/php-multipart-signals.njs) | Observation-only njs `js_access` handler using parsed multipart fields | Mock-tested; needs nginx/njs staging validation. Logs do not deny requests. |
| [`aws/php-multipart-r1.json`](aws/php-multipart-r1.json) | AWS WAF v2 field-name pair example | Uses `Count`. JSON and structural tests pass; AWS API validation pending. The former 5 MiB body-size example was retired because AWS body inspection is capped far below that threshold. |
| [`scripts/detection_rules.py`](scripts/detection_rules.py) | Offline inert request classifier | Python unit-tested. This is a model, not a deployed WAF rule. |
| [`scripts/benign_detection_poc.py`](scripts/benign_detection_poc.py) | Synthetic, offline proof of detection behavior | Exercises benign and matching shapes plus cross-request review; does not reproduce a CVE. |
| [`scripts/triage_events.py`](scripts/triage_events.py) | Redacted, offline request and outcome correlation | Python unit-tested. It prioritizes review and never proves exploitation. |

[Platform notes](docs/detection-platforms.md) map each rule to its actual coverage. [Tuning guidance](TUNING.md) lists body-inspection and false-positive limits.

For an operational reading order, start with the [practitioner guide](docs/practitioner-guide.md), [public PoC review and coverage map](docs/public-poc-review-2026-10-21.md), then review the [reliability research](docs/reliability-research-2026-10-21.md), [platform matrix](docs/detection-platforms.md), [Cloudflare response controls](docs/cloudflare-response-controls-2026-10-21.md) and [tuning notes](TUNING.md). The latest pass corrects the local multipart Content-Type header gates and adds offline response/origin triage; these improvements do not turn request-shape hits into exploit confirmation.

## Naming and migration

The project and active rule filenames now use **multipart request shapes** because R5/R7 observe broader multipart behavior, while R1/R3 still match upload-progress fields. Existing rule IDs remain the same. Update deployment references to these active files:

| Former file | Current file |
|---|---|
| `modsecurity/php-uploadprogress.conf` | `modsecurity/php-multipart-signals.conf` |
| `suricata/php-uploadprogress.rules` | `suricata/php-multipart-signals.rules` |
| `nginx/php-uploadprogress.njs` | `nginx/php-multipart-signals.njs` |
| `aws/php-uploadprogress-r1.json` | `aws/php-multipart-r1.json` |

The njs `js_access` function is now `checkPhpMultipartSignals`. The ModSecurity tag is now `php/multipart-observe`. The AWS R1 rule and CloudWatch metric name are now `PHPMultipartProgressFieldPair`; update dashboards or alerts that reference the old name. Archived evidence retains its historical filenames.

## Rule meanings

- **R1:** a multipart POST with both `PHP_SESSION_UPLOAD_PROGRESS` and `PHPSESSID` body field names. Both can be legitimate in a specific application.
- **R2:** at least 40 repeated `t[]` names in the offline Python model. No shipped engine rule counts these within one request.
- **R3:** upload-progress field plus a body of at least 5 MiB. This is only a size heuristic, not an OOM detector.
- **R4:** optional denial of all progress-field uploads where the application never uses the feature. It is disabled by default and would reject the entire request.
- **R5:** multipart part-header inflation or deeply nested field-name observation. Thresholds are arbitrary and need local validation.
- **R7:** multipart POST without a usable declared Content-Length. Chunked uploads can be legitimate.
- **R8:** upload-progress form field plus a `PHPSESSID` **cookie** (ModSecurity, njs and offline classifier). This is common in legitimate progress forms; it logs without denial and is not a CVE signature.

The PHP configuration setting `session.upload_progress.enabled = Off` (enforced administratively, then restart workers) disables progress tracking while ordinary uploads continue. The primary research workspace tested that feature-path control on five local PHP builds. Per PHP's advisory this blocks the confirmed upload-progress producing/consuming operations of CVE-2026-109619, but it is not a complete mitigation for other paths or CVE-2026-109618.

## Local checks

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
python3 scripts/benign_detection_poc.py
node tests/test_njs.mjs
python3 -m json.tool aws/php-multipart-r1.json > /dev/null
```

These checks do **not** run a ModSecurity, Suricata, nginx, or AWS engine. Validate configuration and replay representative benign and matching requests in a staging environment before enabling blocking.

For njs 0.9.9 or newer, an example access-phase placement is:

```nginx
js_import waf from /absolute/path/php-multipart-signals.njs;
location /upload/ {
    js_access waf.checkPhpMultipartSignals;
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
- See the [Wiz Research writeup](https://www.wiz.io/blog/php2shell-php-rce) for the authoritative bug-role mapping (CVE-2026-109618: upload-progress unserializer UAF + PS(id) memory disclosure; CVE-2026-109619: fatal-backtrace UAF + OPcache type confusion) and the vendor hunt signals now documented in TUNING.md and the platform notes.
- See [docs/verification-2026-10-21.md](docs/verification-2026-10-21.md) for the local verification record and remaining engine-validation gates.

See [docs/detection-platforms.md](docs/detection-platforms.md) for the current coverage matrix and response-side investigation notes.

License: MIT, see [LICENSE](LICENSE).

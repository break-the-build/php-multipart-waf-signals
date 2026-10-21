# PHP upload-progress request-shape rules

Defensive WAF and IDS examples for deployments reviewing PHP's `session.upload_progress` feature. The reported CVE-2026-109618 and CVE-2026-109619 identifiers have **not** been tied to this callback by a primary advisory in the evidence available to this repository. Local PHP research demonstrated a stale top-level cached-pointer write and negative ASan/UBSan runs, not a use-after-free access or code execution.

These rules identify traffic patterns for investigation. They are not a substitute for a PHP security update or proof that a request is malicious.

## Shipped rules

| File | Scope | Status |
|---|---|---|
| [`modsecurity/php-uploadprogress.conf`](modsecurity/php-uploadprogress.conf) | Parsed multipart field names, plus an optional size heuristic | Needs ModSecurity v3/connector validation. R4 deny-all is commented out. |
| [`suricata/php-uploadprogress.rules`](suricata/php-uploadprogress.rules) | Alert-only field-name pair and size heuristic | Needs `suricata -T` and traffic replay. No repeated-field count is claimed. |
| [`nginx/php-uploadprogress.njs`](nginx/php-uploadprogress.njs) | njs `js_access` handler using parsed multipart fields | Mock-tested; needs nginx/njs staging validation. |
| [`aws/php-uploadprogress-r1.json`](aws/php-uploadprogress-r1.json) | AWS WAF v2 field-name pair | JSON and structural tests pass; AWS API validation is pending. |
| [`scripts/detection_rules.py`](scripts/detection_rules.py) | Offline inert request classifier | Python unit-tested. This is a model, not a deployed WAF rule. |

[Platform notes](docs/detection-platforms.md) map each rule to its actual coverage. [Tuning guidance](TUNING.md) lists body-inspection and false-positive limits.

## Rule meanings

- **R1:** a multipart POST with both `PHP_SESSION_UPLOAD_PROGRESS` and `PHPSESSID` body field names. Both can be legitimate in a specific application.
- **R2:** at least 40 repeated `t[]` names in the offline Python model. No shipped engine rule counts these within one request.
- **R3:** upload-progress field plus a body of at least 5 MiB. This is only a size heuristic, not an OOM detector.
- **R4:** optional denial of all progress-field uploads where the application never uses the feature. It is disabled by default and would reject the entire request.

The PHP configuration setting `session.upload_progress.enabled = Off` disables progress tracking while ordinary uploads continue. The primary research workspace tested that feature-path control on five local PHP builds. Its relevance to either reported CVE remains unconfirmed.

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

The request shapes were informed by local source analysis and an untrusted public writeup. No third-party research code was executed to build this rule pack. The official PHP release notice available at the last check did not publish CVE-to-callback mapping or fixed versions. Review [TUNING.md](TUNING.md) and the PHP advisory when it becomes available.

License: MIT, see [LICENSE](LICENSE).

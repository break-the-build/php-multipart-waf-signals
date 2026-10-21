# Practitioner guide: PHP multipart request-shape observations

This pack helps **find selected unusual multipart requests for review**. It does not identify a successful PHP2Shell attempt, cover every CVE variant, or replace a patched PHP runtime. The shipped ModSecurity and njs rules log, the AWS rule counts, and Suricata rules alert. None blocks by default.

## Start with the runtime

Inventory the PHP binary actually serving requests, its SAPI, extensions and worker configuration. [PHP's advisories](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) and [release notice](https://www.php.net/archive/2026.php#2026-10-21-5) identify fixes in 8.2.35, 8.3.36, 8.4.27 and 8.5.12. Apply a fixed release or verified vendor backport and restart workers. [Google Cloud's guidance](https://cloud.google.com/blog/products/identity-security/responding-to-core-php-vulnerabilities-cve-2026-109618-cve-2026-109619) also calls out rebuilding custom images and upgrading unsupported runtimes.

| Published path | Source | What this pack can observe |
|---|---|---|
| OOM during partially initialized state (CVE-2026-109618) | [PHP advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) | Selected multipart shapes only; a match is not an OOM. |
| Cross-request stale session/decoder state (CVE-2026-109619) | [PHP advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) | Upload-progress field presence; the edge cannot verify same-worker reuse or stale state. |
| Wiz's upload-progress unserializer example (grouped under 109618) | [Wiz Research](https://www.wiz.io/blog/php2shell-php-rce) | Only some upload field names; no validated signature for the example. |
| Wiz's fatal-error backtrace and WordPress OPcache examples (grouped under 109619) | [Wiz Research](https://www.wiz.io/blog/php2shell-php-rce) | No specific coverage from these upload-field rules. |

The earlier cached `zval *` counter observation in the companion research is a separate, sanitizer-negative result. Do not assign its request shapes to either CVE.

## Read one event correctly

R1 means two configured-looking form field names appeared in one multipart request. A legitimate progress-enabled form may do that. R3 means a large body and a progress-looking field were observed; size alone is not memory exhaustion. R5 and R7 are broad multipart parsing observations. Correlate them with an origin request ID, worker ID when available, fatal or memory-limit errors, response status and worker restart. [Cloudflare](https://blog.cloudflare.com/php-vulnerabilities-waf-protection/) explains why request and response context improves confidence. Avoid logging raw uploads, session values or response cookies.

**If you see a match:** verify that the affected origin actually runs PHP and which PHP version handles the route; compare it with normal uploads; inspect origin error and worker telemetry; preserve a redacted request/response record. Escalate as a suspicious transaction only when independent origin or response evidence supports it. A single field-name hit is not a confirmed exploit.

**If you see no match:** do not infer safety. The body may be outside a WAF inspection window, multipart field names may be configured differently, or the published path may not involve upload progress at all.

## Why Suricata alerts need context

The Suricata rules inspect raw HTTP body bytes, not PHP's parsed form fields. Marker-like text inside an uploaded file can therefore satisfy a body expression even when PHP never treats it as a field name. Conversely, Suricata may inspect only a configured prefix of a request body. Treat its alerts as leads and compare them with origin-side parsed request and error telemetry where permitted. The local structural test verifies three `alert` signatures and no `drop`/`reject` action; it does not prove that those signatures trigger correctly on wire traffic.

For nginx njs, `r.log()` writes at the **info** log level. Enable the appropriate `error_log ... info` setting in a staging configuration if you need to see these observations. The handler parses at most 512 form fields and logs a generic parser failure when that limit or another parse condition is hit; absence of a field alert after such a failure is not evidence of a clean upload. Keep `client_max_body_size` set for the application's normal upload limit.

For AWS WAF, the supplied rule uses `Count` and CloudWatch metrics, with request sampling disabled. [AWS's VisibilityConfig reference](https://docs.aws.amazon.com/waf/latest/APIReference/API_VisibilityConfig.html) says ordinary logging redaction does **not** apply to sampled requests; enable sampling only after configuring web ACL data protection or accepting its data exposure. `CONTINUE` checks only the body bytes inside AWS's inspection window, so a missing match does not clear a large upload.

## Deployment decision and promotion record

| Origin condition | First action | Role of this pack |
|---|---|---|
| Vulnerable PHP version or uncertain vendor backport | Upgrade to a fixed release or verify the backport, then restart workers. If upload progress is unused, disable it in administrative PHP configuration. | Observe traffic while the runtime is corrected. A rule hit does not establish compromise. |
| Fixed PHP runtime | Keep the runtime current and confirm the new workers are serving requests. | Optional visibility into unusual multipart requests. Reassess signal value against normal uploads. |
| Upload progress required by the application | Preserve legitimate progress forms during staging replay. | Scope observation to relevant routes and use the configured field and session names. Do not enable the optional whole-upload denial rule. |

For each route and rule ID, record the engine and version, rule revision, body inspection limit, sample size and period of benign traffic, false-positive count, and the observed action. Replay ordinary file uploads, progress-enabled uploads, large files, chunked requests, and malformed forms through a staging origin. Confirm that the response reaches the application and that no active rule blocks it. A production block decision requires an application-specific false-positive review and a documented rollback owner; this repository has no such approval or measurement.

For redacted event exports, run [`scripts/triage_events.py`](../scripts/triage_events.py) to prioritize review using request matches plus response and origin signals. Its same-worker sequence requires an actual pseudonymous PHP worker identity; a shared client IP is insufficient. See the [reliability research](reliability-research-2026-10-21.md) for input fields, tests and limits.

Keep a short incident record with a redacted request ID, timestamp, route, rule ID, origin PHP version, HTTP status and relevant origin error or worker-restart observation. Avoid session IDs, cookies, form values, and raw files. When investigation ends, retain only the fields and period required by the local retention policy.

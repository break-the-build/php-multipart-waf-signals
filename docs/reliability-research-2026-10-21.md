# Reliability research and rule revision — 2026-10-21

This review asks whether the shipped observations reliably identify *requests that PHP will parse*, and whether the available evidence supports an exploit alert. They remain review leads. No vendor has published a complete, stable wire signature for every variant of CVE-2026-109618 or CVE-2026-109619.

## Source hierarchy and findings

| Evidence | What it establishes | Rule consequence |
|---|---|---|
| [PHP 109618 advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w), [PHP 109619 advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) | Distinct OOM/`longjmp` and stale-state classes; multiple affected paths. | A progress-field hit cannot identify a CVE or prove exploitation. Patch the runtime. |
| [Wiz PHP2Shell analysis](https://www.wiz.io/blog/php2shell-php-rce) | Describes multiple variants and suggests memory-limit errors, repeated 500s, unusual session-cookie responses, and worker churn as investigation clues. | Correlate redacted origin and response telemetry with request signals. These clues are not conclusive alone. |
| [Cloudflare PHP protection report](https://blog.cloudflare.com/php-vulnerabilities-waf-protection/) and [full-transaction explanation](https://blog.cloudflare.com/full-transaction-waf/) | Cloudflare deployed managed detections and emphasizes request-plus-response context; the exact managed signatures are not public. | Do not claim this open rule pack matches managed-rule coverage or confidence. |
| [Cloudflare CTO's X post](https://x.com/dok2001/status/2112811965735202970) | Known-vector rules are a stopgap and evolve as attacker traffic changes. | Keep local rules observational and update them from verified evidence. |
| [The PHP Foundation's X post](https://x.com/ThePHPF/status/2112633155631108544) | Contemporaneous official disclosure notice. | Use PHP advisories and source for technical specifics; a social post alone is not validation. |

The older cached-pointer upload-progress claim remains separate from these CVEs. This review did not download or execute third-party PoC code, send traffic to public targets, or attempt command execution.

## PHP parser comparison

`main/SAPI.c` in the preserved PHP 8.4.4 source selects the POST handler after splitting the Content-Type token at `;`, `,`, or a space (lines 183–201). A benign one-field multipart CGI request was run against locally built PHP 8.4.4 and fixed 8.4.27 in a `--network none` container. Both parsed `multipart/form-data; boundary=...`, `multipart/form-data,boundary=...`, and `multipart/form-data boundary=...`; neither parsed `multipart/form-datax; boundary=...` as multipart. This is a parser-matching regression, **not** a CVE reproduction. The preserved transcript is [`artifacts/reliability-2026-10-21/php-multipart-reliability-php-cgi.stdout`](../artifacts/reliability-2026-10-21/php-multipart-reliability-php-cgi.stdout), with binary SHA-256s in its manifest.

The ModSecurity and njs **header gates** and offline classifier now accept the three PHP-recognized separators and reject the tested suffix. The actual ModSecurity and njs form parsers have not been replayed with the nonstandard comma/space forms; their parsed-field rules may still miss those requests. The AWS example now requires the header to start with `multipart/form-data`, removing matches where the token appears later in an unrelated header. AWS and Suricata still use raw byte matching, so neither proves that PHP parsed the named body fields; both may match text inside a file part. The AWS prefix can still accept a malformed suffix. We did not add an unvalidated platform regex to hide that limit.

## Redacted event triage

[`scripts/triage_events.py`](../scripts/triage_events.py) reads ordered newline-delimited JSON from a **local, authorized, redacted** log export and emits only request IDs, review priority, and reason labels. It never opens a network connection. Input fields are:

| Field | Meaning |
|---|---|
| `request_id`, `timestamp` | Pseudonymous request key and ISO 8601 time with timezone; input must be ordered. |
| `rule_ids`, `multipart`, `status` | Matched local rule IDs, whether the origin saw multipart, and HTTP response code. |
| `origin_memory_error`, `origin_fatal_error`, `late_cleanup_diagnostic`, `preinit_ini_diagnostic`, `session_cookie_anomaly`, `worker_restart` | Boolean signals supplied by trusted origin/response processing. Supply anomaly *flags*, never cookie values or raw errors. |
| `worker_key` | Optional pseudonymous **PHP worker identity**, stable only over the review window. Never substitute client IP. |

Run `python3 scripts/triage_events.py < redacted-events.ndjson`. A rule hit alone yields `observe`. A matching request with an error, 5xx, worker restart or cookie anomaly yields `investigate`. A memory-error event followed by a multipart cookie-anomaly event on the **same worker**, or a fatal/late-cleanup diagnostic followed by a pre-init INI diagnostic on that worker, yields `high_priority_review` within the analyst-selected window. The default 300 seconds is a review convenience, not an exploit timing bound. `high_priority_review` means inspect evidence promptly; it does not mean compromise or either CVE was confirmed. Event producers must define and validate their own cookie-anomaly and worker-restart logic against their baseline.

## Verification and remaining gates

The revision passed 27 Python tests and 14 njs mock cases, including separator positives, invalid-suffix negatives, shared-IP non-correlation, expired-window non-correlation and output redaction. Logs and a revision manifest are in [`artifacts/reliability-2026-10-21/`](../artifacts/reliability-2026-10-21/). No active rule blocks traffic.

The current ModSecurity, Suricata, nginx/njs and AWS rules still require their actual engines, application-specific benign upload replay, and measured false-positive rates before anyone can claim operational reliability. No local test verifies all published PHP2Shell paths or a live exploit attempt. Prefer patched PHP and vendor managed protections where available; use this pack for bounded visibility and incident triage.

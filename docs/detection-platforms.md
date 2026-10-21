# Detection platform notes

These are defensive observations for selected PHP multipart request shapes. No rule here has been mapped to a validated exploit transcript for either CVE. The published WordPress demonstration does not establish that its requests contain these fields. Evaluate matches against each application's normal uploads and keep the supplied rules observational.

The [PHP stale-state advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) confirms an upload-progress consumer path; [Wiz](https://www.wiz.io/blog/php2shell-php-rce) separately describes an upload-progress unserializer variant under its 109618 grouping, a fatal-error backtrace variant and a WordPress OPcache variant under its 109619 grouping. [Google Cloud](https://cloud.google.com/blog/products/identity-security/responding-to-core-php-vulnerabilities-cve-2026-109618-cve-2026-109619) corroborates the broad CVE classes and fixed versions. This pack covers request shapes near some multipart paths; it does not cover the full set of variants.

| ID | Implemented rule | Meaning | Limit |
|---|---|---|---|
| R1 | ModSecurity, Suricata, AWS, njs | Multipart POST with both `PHP_SESSION_UPLOAD_PROGRESS` and `PHPSESSID` field names | Field names and body-inspection windows are deployment dependent. |
| R2 | Python classifier only | At least 40 repeated `t[]` fields | No native WAF/IDS counting rule is shipped. |
| R3 | ModSecurity, Suricata, njs | Progress field plus a body-size surrogate of at least 5 MiB | Size is not evidence of OOM or repeated parts; Suricata needs Content-Length. The former AWS body-size rule was retired. |
| R4 | Optional, commented ModSecurity policy | Deny any upload-progress form on applications that never use it | Denies the entire upload, unlike `session.upload_progress.enabled=Off`. |
| R5 | Suricata 20260006, ModSecurity 20260006 | Multipart part-header inflation or deeply nested field-name observation | Arbitrary thresholds; no exploit specificity. Suricata PCRE and body-inspection caps require validation. |
| R6 | Removed from Suricata; no active sequencing rule | Former same-client-IP correlation | An IP address does not identify a PHP worker or show that request-owned state survived. Use worker-aware origin telemetry for investigation. |
| R7 | ModSecurity and njs; Suricata not shipped | Multipart POST without a usable declared Content-Length | Chunked uploads can be legitimate. Both supplied rules log and allow this shape. |

## Shipped platform files

- **ModSecurity v3:** [`modsecurity/php-multipart-signals.conf`](../modsecurity/php-multipart-signals.conf) uses the parsed `ARGS_POST_NAMES` collection for multipart form field names. The [v3 reference](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29) limits `REQUEST_BODY` to URL-encoded body processing. Validate with the deployed connector and CRS policy. R4 is disabled by default.
- **Suricata:** [`suricata/php-multipart-signals.rules`](../suricata/php-multipart-signals.rules) contains alert-only R1, R3 and R5. `detection_filter` counts rule matches across time, so it is not used to infer repeated fields in one request. R3 uses the documented `http.content_len` numeric check and misses chunked requests without Content-Length. The current file has not had a fresh engine check; run `suricata -T` and replay representative traffic.
- **nginx njs:** [`nginx/php-multipart-signals.njs`](../nginx/php-multipart-signals.njs) is an observation-only `js_access` handler for njs 0.9.9 or newer. `readRequestForm()` parses multipart field names; all paths return without `r.return()`. Configure `client_max_body_size` and test body parsing, malformed forms, and ordinary uploads on a staging server. [Official njs module documentation](https://nginx.org/en/docs/http/ngx_http_js_module.html).
- **AWS WAF v2:** [`aws/php-multipart-r1.json`](../aws/php-multipart-r1.json) is a Count example with metrics enabled and request sampling disabled by default. `CONTINUE` on the body may miss fields outside the inspection window. The former 5 MiB `Body` size example was retired because the [AWS WAF body inspection limit](https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-setting-body-inspection-limit.html) is 8 KiB for ALB/AppSync and 16–64 KiB for supported configurable resources; [AWS explains](https://docs.aws.amazon.com/waf/latest/APIReference/API_Body.html) that `CONTINUE` inspects only the available body. The remaining file is checked locally as JSON and for its schema shape, but has not been submitted to AWS `CheckCapacity` or deployed.

## Other platforms

Cloudflare, Akamai, Imperva, Azure WAF, F5, Snort, and Zeek do not have deployable rules in this repository. Translate the table above only after checking current vendor syntax, request-body availability, inspection limits, and normal application traffic. Do not treat the former conceptual snippets as tested configurations.

## Response and origin telemetry

[Cloudflare's PHP2Shell report](https://blog.cloudflare.com/php-vulnerabilities-waf-protection/) explains why request-only matching is insufficient and describes full-transaction detection using request and response signals. Its [full-transaction article](https://blog.cloudflare.com/full-transaction-waf/) describes response-phase controls. This repository does not replicate those managed detections. For local incident review, correlate multipart anomalies with origin memory-limit/fatal errors, repeated 500 responses, unusual session-cookie behavior and worker restarts. Those are investigation leads from [Wiz's report](https://www.wiz.io/blog/php2shell-php-rce), not independently conclusive indicators. Preserve request ID, origin worker ID if available, status, timestamp and rule match without logging session-cookie values or raw upload contents.

## Validation status

The Python suite checks the local classifier and structural properties of the shipped files. The Node test exercises the njs handler with mock requests. No actual ModSecurity, nginx/njs, or AWS WAF engine test has run in this repository. Engine validation and benign-traffic replay remain required before operational use.

**2026-10-21 (earlier post-advisory round):** Suricata `-T` loaded the prior four-rule file (R1, R3, R5, R6): 4 loaded, 0 failed (Suricata 7.0.10; transcript `suricata/syntax-check-suricata7.txt`). R6 has since been removed. The current three-rule file still needs `-T` and traffic replay; the archived transcript must not be treated as validation of this revision.

**Version-bounds confirmation (Google Cloud, 2026-10-21):** vulnerable range authoritatively stated as PHP 5.4 through 8.5.11 (patched: 8.5.12/8.4.27/8.3.36/8.2.35; upstream fixes do not cover 8.1 or earlier — GCP summarised; php.net additionally ships minimal backport branches for 7.4/8.0/8.1); impact confirmed as RCE *and memory disclosure*. Disclosure chain: Wiz Research with AI (Gemini) contribution per GCP's writeup.

**Vendor first-party context (Cloudflare, 2026-10-21):** Cloudflare deployed default-included WAF protections at 03:02 UTC (Managed Free Ruleset `77454fe2…`, Managed Ruleset `efb7b8c9…`, seven "Anomalous Execution" rules each, plus a response-side rule in Managed Response Firewall `afffe227…`) and credits Calif.io, Wiz, OpenAI and Quarkslab in the coordinated disclosure; they observed attacker payload mutation against their rules before public disclosure and emphasize full-transaction (request+response) detection for higher-confidence blocking. Our request-only rules complement this layer and do not claim its confidence; see their changelog for the current set.

**Current revision:** Python structural tests and njs mock tests pass. Suricata, ModSecurity, nginx/njs-in-situ and AWS policy-outcome validation remain pending. Keep all rules in observation/alert mode until an engine check and benign-traffic replay are archived.

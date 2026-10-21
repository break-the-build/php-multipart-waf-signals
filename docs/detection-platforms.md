# Detection platform notes

These are defensive observations for selected PHP multipart request shapes. No rule here has been mapped to a validated exploit transcript for either CVE. The published WordPress demonstration does not establish that its requests contain these fields. Evaluate matches against each application's normal uploads and keep the supplied rules observational.

The [PHP stale-state advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) confirms an upload-progress consumer path; [Wiz](https://www.wiz.io/blog/php2shell-php-rce) separately describes an upload-progress unserializer variant under its 109618 grouping, a fatal-error backtrace variant and a WordPress OPcache variant under its 109619 grouping. [Google Cloud](https://cloud.google.com/blog/products/identity-security/responding-to-core-php-vulnerabilities-cve-2026-109618-cve-2026-109619) corroborates the broad CVE classes and fixed versions. This pack covers request shapes near some multipart paths; it does not cover the full set of variants.

| ID | Implemented rule | Meaning | Limit |
|---|---|---|---|
| R1 | ModSecurity, Suricata, AWS, njs | Multipart POST with both `PHP_SESSION_UPLOAD_PROGRESS` and `PHPSESSID` field names | Field names and body-inspection windows are deployment dependent. |
| R8 | ModSecurity, njs, Python classifier | Upload-progress field plus default session cookie name | A legitimate progress form can match; configured names and body parsing vary. Log only. |
| R2 | Python classifier only | At least 40 repeated `t[]` fields | No native WAF/IDS counting rule is shipped. |
| R3 | ModSecurity, Suricata, njs | Progress field plus a body-size surrogate of at least 5 MiB | Size is not evidence of OOM or repeated parts; Suricata needs Content-Length. The former AWS body-size rule was retired. |
| R4 | Optional, commented ModSecurity policy | Deny any upload-progress form on applications that never use it | Denies the entire upload, unlike `session.upload_progress.enabled=Off`. |
| R5 | Suricata 20260006, ModSecurity 20260006 | Multipart part-header inflation or deeply nested field-name observation | Arbitrary thresholds; no exploit specificity. Suricata PCRE and body-inspection caps require validation. |
| R6 | Removed from Suricata; no active sequencing rule | Former same-client-IP correlation | An IP address does not identify a PHP worker or show that request-owned state survived. Use worker-aware origin telemetry for investigation. |
| R7 | ModSecurity and njs; Suricata not shipped | Multipart POST without a usable declared Content-Length | Chunked uploads can be legitimate. Both supplied rules log and allow this shape. |

## Shipped platform files

- **ModSecurity v3:** [`modsecurity/php-multipart-signals.conf`](../modsecurity/php-multipart-signals.conf) uses the parsed `ARGS_POST_NAMES` collection for multipart form field names. The [v3 reference](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29) limits `REQUEST_BODY` to URL-encoded body processing. Validate with the deployed connector and CRS policy. R4 is disabled by default.
- **Suricata:** [`suricata/php-multipart-signals.rules`](../suricata/php-multipart-signals.rules) contains alert-only R1, R3 and R5. `detection_filter` counts rule matches across time, so it is not used to infer repeated fields in one request. R3 uses the documented `http.content_len` numeric check and misses chunked requests without Content-Length. The current file loads clean in `suricata -T` (see validation status); traffic replay remains pending.
- **nginx njs:** [`nginx/php-multipart-signals.njs`](../nginx/php-multipart-signals.njs) is an observation-only `js_access` handler for njs 0.9.9 or newer. `readRequestForm()` parses multipart field names; all paths return without `r.return()`. Configure `client_max_body_size` and test body parsing, malformed forms, and ordinary uploads on a staging server. [Official njs module documentation](https://nginx.org/en/docs/http/ngx_http_js_module.html).
- **AWS WAF v2:** [`aws/php-multipart-r1.json`](../aws/php-multipart-r1.json) is a Count example with metrics enabled and request sampling disabled by default. `CONTINUE` on the body may miss fields outside the inspection window. The former 5 MiB `Body` size example was retired because the [AWS WAF body inspection limit](https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-setting-body-inspection-limit.html) is 8 KiB for ALB/AppSync and 16–64 KiB for supported configurable resources; [AWS explains](https://docs.aws.amazon.com/waf/latest/APIReference/API_Body.html) that `CONTINUE` inspects only the available body. The remaining file is checked locally as JSON and for its schema shape, but has not been submitted to AWS `CheckCapacity` or deployed.

## Other platforms

Cloudflare, Akamai, Imperva, Azure WAF, F5, Snort, and Zeek do not have deployable rules in this repository. Translate the table above only after checking current vendor syntax, request-body availability, inspection limits, and normal application traffic. Do not treat the former conceptual snippets as tested configurations.

## Response and origin telemetry

[Cloudflare's PHP2Shell report](https://blog.cloudflare.com/php-vulnerabilities-waf-protection/) explains why request-only matching is insufficient and describes full-transaction detection using request and response signals. Its [full-transaction article](https://blog.cloudflare.com/full-transaction-waf/) describes response-phase controls. This repository does not replicate those managed detections. The offline [`triage_events.py`](../scripts/triage_events.py) can prioritize a redacted local export with same-transaction and same-worker outcome flags, including a non-multipart fatal/early-INI sequence; it is not an inline WAF rule or an exploit validator. For local incident review, correlate multipart anomalies with origin memory-limit/fatal errors, repeated 500 responses, unusual session-cookie behavior and worker restarts. Those are investigation leads from [Wiz's report](https://www.wiz.io/blog/php2shell-php-rce), not independently conclusive indicators. Preserve request ID, origin worker ID if available, status, timestamp and rule match without logging session-cookie values or raw upload contents.

## Response-side and workflow hunt signals (vendor-published, 2026-10-21)

Wiz's technical writeup documents the *response-side* and temporal signals that
request-only rules cannot express; fold these into your SIEM/hunt around the
network rules above:

- unusual multipart requests **followed by** memory-limit errors or repeated
  HTTP 500 responses from the same worker/source;
- unexpectedly large or malformed `PHPSESSID` response cookies (the confirmed
  PS(id) disclosure bug encodes reclaimed heap contents URL-encoded into that
  cookie on a LATER request handled by the same worker);
- unexplained PHP worker churn (pool recycle patterns beyond your configured
  `pm.max_requests`).

Role attribution: Wiz documents an upload-progress unserializer case under
CVE-2026-109618; PHP confirms upload progress as a producer or consumer in
CVE-2026-109619. R5/R7 are broad OOM request shapes, not proof of either
case. R6 was removed: an IP address cannot identify a PHP worker.

The [public PoC review](public-poc-review-2026-10-21.md) maps the remaining multipart and non-multipart gaps to the official advisories. In particular, the OPcache cross-worker variant has no defensible request-only signature here.

## Ecosystem detections and independent reports (sweep round, 2026-10-21 ~17:00 UTC)

- **Corelight Labs released an open-source Zeek + Suricata detection pack** alongside
  disclosure ([corelight/php2shell-detect](https://github.com/corelight/php2shell-detect),
  nine behavioral Zeek notice types: PHP_Crash_Sequence, Multipart_Header_Flood (maps to
  our R5), Large_Form_Key, serialized-token/collision/repetition notices, and a
  Potentially_Affected_PHP_Version inventory from Server/X-Powered-By banners + Suricata
  rare-marker + version-cache rules). For the Zeek lane this repository only sketches,
  the Corelight package is the reference implementation; the version-inventory notices
  double as patch-review fleet inventory. Adoption recommended before writing our own.
- **Datadog Security Labs** independently reproduced the CVE-2026-109618 OOM chain on
  PHP 8.5.11 (unauthenticated POST, command execution during failed-request cleanup,
  no crash required, ASLR bypassed via calibrated layout built on the memory-disclosure
  primitive). **Mitigation divergence:** Datadog reports community mitigations such as
  `session.upload_progress.enabled=0` "don't protect you" — stronger than the vendor
  advisory's "blocks the confirmed session paths but not other variants". This repo's
  wording therefore treats the INI stopgap as secondary/partial at best: **the PHP
  update remains the only complete fix** (also per core devs' public statements).
- **Fastly** shipped an NGWAF Virtual Patch (Templated Rule) for both CVEs and noted
  "evidence of active attacks in-the-wild pre-disclosure"; **cPanel** published
  concrete backport packages for 7.4/8.0/8.1 (ea-php7.4.33-19 / ea-php8.0.30-12 /
  ea-php8.1.34-5 plus the .35/.36/.27/.12 set); **Check Point/Tenable/SecurityWeek**
  report ~884k internet-facing hosts advertising PHP ≤ 8.1 (banner-level), and
  Cloudflare's CTO described "early attacks emerging" against its stopgap rules.
  **CISA KEV: neither CVE was in the catalog as of 17:07 UTC** (CISA CSV checked) —
  keep "observed attacks" separate from "KEV-confirmed exploitation".
- Action item for posture: pair this pack's request-side rules with the Corelight
  package (Zeek/behavioral + version inventory) and the response-side indicators in
  TUNING.md; nothing here replaces the runtime update.

## Validation status

The Python suite checks the local classifier and structural properties of the shipped files. The Node test exercises the njs handler with mock requests. No actual ModSecurity, nginx/njs, or AWS WAF engine test has run in this repository. Engine validation and benign-traffic replay remain required before operational use.

**2026-10-21 (fresh validation round on the renamed pack):** Suricata 7.0.10 `-T` on the CURRENT `suricata/php-multipart-signals.rules` (three rules: R1, R3, R5): **3 successfully loaded, 0 failed** (transcript: `suricata/syntax-check-suricata7.txt`). Earlier round validated the prior four-rule revision (R6 same-source sequencing since removed as it identifies sources, not workers). Engine check still covers SYNTAX only — traffic replay against representative benign and matching requests remains the pending gate before any deny switch.

**Version-bounds confirmation (Google Cloud, 2026-10-21):** vulnerable range authoritatively stated as PHP 5.4 through 8.5.11 (patched: 8.5.12/8.4.27/8.3.36/8.2.35; upstream fixes do not cover 8.1 or earlier — GCP summarised; php.net additionally ships minimal backport branches for 7.4/8.0/8.1); impact confirmed as RCE *and memory disclosure*. Disclosure chain: Wiz Research with AI (Gemini) contribution per GCP's writeup.

**Vendor first-party context (Cloudflare, 2026-10-21):** Cloudflare deployed default-included WAF protections at 03:02 UTC (Managed Free Ruleset `77454fe2…`, Managed Ruleset `efb7b8c9…`, seven "Anomalous Execution" rules each, plus a response-side rule in Managed Response Firewall `afffe227…`) and credits Calif.io, Wiz, OpenAI and Quarkslab in the coordinated disclosure; they observed attacker payload mutation against their rules before public disclosure and emphasize full-transaction (request+response) detection for higher-confidence blocking. Our request-only rules complement this layer and do not claim its confidence; see their changelog for the current set.

**Current revision:** The [reliability research](reliability-research-2026-10-21.md) records a benign PHP 8.4.4/8.4.27 parser comparison, separator fixes, AWS header-prefix tightening, and redacted triage tests. Python structural tests and njs mock tests pass. Suricata, ModSecurity, nginx/njs-in-situ and AWS policy-outcome validation remain pending. Keep all rules in observation/alert mode until an engine check and benign-traffic replay are archived.

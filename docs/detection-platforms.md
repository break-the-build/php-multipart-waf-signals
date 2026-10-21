# Detection platform notes

These are defensive request-shape heuristics for PHP session upload-progress traffic. Neither the two reported CVE identifiers nor a use-after-free access has been mapped to these shapes by the evidence in this repository. The rules should be evaluated against each application's normal uploads before blocking.

| ID | Implemented rule | Meaning | Limit |
|---|---|---|---|
| R1 | ModSecurity, Suricata, AWS, njs | Multipart POST with both `PHP_SESSION_UPLOAD_PROGRESS` and `PHPSESSID` field names | Field names and body-inspection windows are deployment dependent. |
| R2 | Python classifier only | At least 40 repeated `t[]` fields | No native WAF/IDS counting rule is shipped. |
| R3 | ModSecurity, Suricata, njs | Progress field plus a body-size surrogate of at least 5 MiB | Size is not evidence of OOM or repeated parts; Suricata needs Content-Length. |
| R4 | Optional, commented ModSecurity policy | Deny any upload-progress form on applications that never use it | Denies the entire upload, unlike `session.upload_progress.enabled=Off`. |
| R5 | Suricata 20260006, ModSecurity 20260006 | CVE-2026-109618 OOM strategy: >=96 consecutive header lines within multipart part headers (header-storm inflation) | PCRE window limits apply in Suricata; body-inspection caps may miss huge bodies. |
| R6 | Suricata 20260007, ModSecurity 20260007, njs | CVE-2026-109619 producer/consumer sequencing: producer-shaped request then later requests from the same source (Suricata xbits by IP; source != worker) | Approximation: correlates source IP, not worker identity; hunt/observe semantics only. |
| R7 | Suricata (docs), njs implemented | CVE-2026-109618 strategy: multipart POST without a usable declared Content-Length keeps feeding decoded body data | Suricata-side no-header match requires 8.x syntax and is documented, not shipped. |

## Shipped platform files

- **ModSecurity v3:** [`modsecurity/php-uploadprogress.conf`](../modsecurity/php-uploadprogress.conf) uses the parsed `ARGS_POST_NAMES` collection for multipart form field names. The [v3 reference](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29) limits `REQUEST_BODY` to URL-encoded body processing. Validate with the deployed connector and CRS policy. R4 is disabled by default.
- **Suricata:** [`suricata/php-uploadprogress.rules`](../suricata/php-uploadprogress.rules) contains alert-only R1 and R3. `detection_filter` counts rule matches across time, so it is not used to infer repeated fields in one request. R3 uses the documented `http.content_len` numeric check and misses chunked requests without Content-Length. Run `suricata -T` and replay representative traffic before enabling.
- **nginx njs:** [`nginx/php-uploadprogress.njs`](../nginx/php-uploadprogress.njs) is a `js_access` handler for njs 0.9.9 or newer. `readRequestForm()` parses multipart field names; a handler that returns without `r.return()` grants access. Configure `client_max_body_size` and test body parsing, malformed forms, and ordinary uploads on a staging server. [Official njs module documentation](https://nginx.org/en/docs/http/ngx_http_js_module.html).
- **AWS WAF v2:** [`aws/php-uploadprogress-r1.json`](../aws/php-uploadprogress-r1.json) is a rule-shaped R1 JSON example with method, Content-Type, and two body matches. Its `CONTINUE` handling inspects only the configured body window when a request exceeds the limit. The file is checked locally as JSON and for its schema shape, but has not been submitted to AWS `CheckCapacity` or deployed. [AWS Rule API](https://docs.aws.amazon.com/waf/latest/APIReference/API_Rule.html).

## Other platforms

Cloudflare, Akamai, Imperva, Azure WAF, F5, Snort, and Zeek do not have deployable rules in this repository. Translate the table above only after checking current vendor syntax, request-body availability, inspection limits, and normal application traffic. Do not treat the former conceptual snippets as tested configurations.

## Validation status

The Python suite checks the local classifier and structural properties of the shipped files. The Node test exercises the njs handler with mock requests. No actual ModSecurity, nginx/njs, or AWS WAF engine test has run in this repository. Engine validation and benign-traffic replay remain required before operational use.

**2026-10-21 (post-advisory round):** Suricata `-T` re-run on the CURRENT four-rule file (R1, R3, R5, R6): **4/4 loaded, 0 failed** (Suricata 7.0.10; transcript `suricata/syntax-check-suricata7.txt`). The OOM-strategy shapes (R5/R7) and the sequencing approximation (R6) encode the advisory's named strategies, not a verified exploit path; trigger replay and cross-engine checks remain the gate.

**Version-bounds confirmation (Google Cloud, 2026-10-21):** vulnerable range authoritatively stated as PHP 5.4 through 8.5.11 (patched: 8.5.12/8.4.27/8.3.36/8.2.35; upstream fixes do not cover 8.1 or earlier — GCP summarised; php.net additionally ships minimal backport branches for 7.4/8.0/8.1); impact confirmed as RCE *and memory disclosure*. Disclosure chain: Wiz Research with AI (Gemini) contribution per GCP's writeup.

**Vendor first-party context (Cloudflare, 2026-10-21):** Cloudflare deployed default-included WAF protections at 03:02 UTC (Managed Free Ruleset `77454fe2…`, Managed Ruleset `efb7b8c9…`, seven "Anomalous Execution" rules each, plus a response-side rule in Managed Response Firewall `afffe227…`) and credits Calif.io, Wiz, OpenAI and Quarkslab in the coordinated disclosure; they observed attacker payload mutation against their rules before public disclosure and emphasize full-transaction (request+response) detection for higher-confidence blocking. Our request-only rules complement this layer and do not claim its confidence; see their changelog for the current set.

**2026-10-21 update:** Suricata syntax check completed for the CURRENT shipped rule file: Suricata 7.0.10 `-T` loaded `suricata/php-uploadprogress.rules` with no parse errors or warnings (transcript: `suricata/syntax-check-suricata7.txt`). This still validates syntax only — no trigger replay, so the rules must stay in observation/alert mode until a lab replay is archived. ModSecurity, nginx/njs-in-situ, Snort, and AWS policy-outcome validation remain pending.

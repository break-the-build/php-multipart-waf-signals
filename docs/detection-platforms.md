# Detection platform notes

These are defensive request-shape heuristics for PHP session upload-progress traffic. Neither the two reported CVE identifiers nor a use-after-free access has been mapped to these shapes by the evidence in this repository. The rules should be evaluated against each application's normal uploads before blocking.

| ID | Implemented rule | Meaning | Limit |
|---|---|---|---|
| R1 | ModSecurity, Suricata, AWS, njs | Multipart POST with both `PHP_SESSION_UPLOAD_PROGRESS` and `PHPSESSID` field names | Field names and body-inspection windows are deployment dependent. |
| R2 | Python classifier only | At least 40 repeated `t[]` fields | No native WAF/IDS counting rule is shipped. |
| R3 | ModSecurity, Suricata, njs | Progress field plus a body-size surrogate of at least 5 MiB | Size is not evidence of OOM or repeated parts; Suricata needs Content-Length. |
| R4 | Optional, commented ModSecurity policy | Deny any upload-progress form on applications that never use it | Denies the entire upload, unlike `session.upload_progress.enabled=Off`. |

## Shipped platform files

- **ModSecurity v3:** [`modsecurity/php-uploadprogress.conf`](../modsecurity/php-uploadprogress.conf) uses the parsed `ARGS_POST_NAMES` collection for multipart form field names. The [v3 reference](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29) limits `REQUEST_BODY` to URL-encoded body processing. Validate with the deployed connector and CRS policy. R4 is disabled by default.
- **Suricata:** [`suricata/php-uploadprogress.rules`](../suricata/php-uploadprogress.rules) contains alert-only R1 and R3. `detection_filter` counts rule matches across time, so it is not used to infer repeated fields in one request. R3 uses the documented `http.content_len` numeric check and misses chunked requests without Content-Length. Run `suricata -T` and replay representative traffic before enabling.
- **nginx njs:** [`nginx/php-uploadprogress.njs`](../nginx/php-uploadprogress.njs) is a `js_access` handler for njs 0.9.9 or newer. `readRequestForm()` parses multipart field names; a handler that returns without `r.return()` grants access. Configure `client_max_body_size` and test body parsing, malformed forms, and ordinary uploads on a staging server. [Official njs module documentation](https://nginx.org/en/docs/http/ngx_http_js_module.html).
- **AWS WAF v2:** [`aws/php-uploadprogress-r1.json`](../aws/php-uploadprogress-r1.json) is a rule-shaped R1 JSON example with method, Content-Type, and two body matches. Its `CONTINUE` handling inspects only the configured body window when a request exceeds the limit. The file is checked locally as JSON and for its schema shape, but has not been submitted to AWS `CheckCapacity` or deployed. [AWS Rule API](https://docs.aws.amazon.com/waf/latest/APIReference/API_Rule.html).

## Other platforms

Cloudflare, Akamai, Imperva, Azure WAF, F5, Snort, and Zeek do not have deployable rules in this repository. Translate the table above only after checking current vendor syntax, request-body availability, inspection limits, and normal application traffic. Do not treat the former conceptual snippets as tested configurations.

## Validation status

The Python suite checks the local classifier and structural properties of the shipped files. The Node test exercises the njs handler with mock requests. No actual ModSecurity, nginx/njs, or AWS WAF engine test has run in this repository. Engine validation and benign-traffic replay remain required before operational use.

**2026-10-21 update:** Suricata syntax check completed for the CURRENT shipped rule file: Suricata 7.0.10 `-T` loaded `suricata/php-uploadprogress.rules` with no parse errors or warnings (transcript: `suricata/syntax-check-suricata7.txt`). This still validates syntax only — no trigger replay, so the rules must stay in observation/alert mode until a lab replay is archived. ModSecurity, nginx/njs-in-situ, Snort, and AWS policy-outcome validation remain pending.

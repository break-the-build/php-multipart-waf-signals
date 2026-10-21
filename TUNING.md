# Tuning and validation

The shipped rules are request-shape heuristics. Start in alert or detection-only mode and compare their hits with known legitimate upload traffic before enabling any block.

## Field-name rule (R1)

R1 targets multipart forms with both `PHP_SESSION_UPLOAD_PROGRESS` and `PHPSESSID` as body field names. ModSecurity and njs inspect parsed names; Suricata and AWS match body text within their inspection window. A legitimate application may use both. PHP permits a configured upload-progress field name and session name; update rules to match the application's settings. Raw-body middleboxes may inspect only an initial body window, so field order and placement affect visibility.

## Repeated fields (R2)

The Python classifier recognizes 40 or more `t[]` field-name appearances. No shipped ModSecurity or Suricata rule claims to count occurrences within one request. Do not replace this with a match-rate filter or a single-field denial.

## Large-body heuristic (R3)

ModSecurity, Suricata, and njs use a 5 MiB body-size surrogate with a progress field. It does not verify memory exhaustion or uniform parts and may flag ordinary large uploads. Scope it to the relevant application paths or leave it alert-only. Suricata's Content-Length check misses chunked requests. AWS R1 uses a limited body window and has no R3 rule here.

Set body-size and buffering limits to values appropriate for the application; avoid raising them solely to make this heuristic fire. For ModSecurity, check `SecRequestBodyLimit`, `SecRequestBodyNoFilesLimit`, and `INBOUND_DATA_ERROR`. For njs, `readRequestForm()` reads the request body; tune `client_max_body_size` and review memory use. Body parser failures return HTTP 400 in the provided njs handler.

## Optional deny-all progress policy (R4)

R4 is commented out in the ModSecurity file. Enable it only after confirming the application never uses upload-progress tracking. It denies the whole matching upload. The PHP setting `session.upload_progress.enabled = Off` instead permits the upload while omitting progress tracking; use that setting when the feature is unnecessary.

## Required deployment checks

- Run each engine's syntax/configuration validation and record version and result.
- Replay benign uploads, both-field uploads, large uploads, malformed forms, and chunked requests through a staging instance.
- Record rule IDs, expected action, actual action, false positives, body-inspection limit, and any parser errors.
- Reassess these stopgap rules after official PHP advisories and fixed releases are published.

## R6 sequencing window (CVE-2026-109619 approximation)

- The published Wiz demo envelope runs 65.2 s end-to-end with a ~48 s dwell between the
  first (state-publishing) request and the memory-capture/consumer sequence. Our shipped
  xbits expiry of 300 s covers it with margin. Tune between 120–300 s: shorter loses the
  demonstrated dwell; longer raises correlation noise from unrelated traffic sharing a
  source IP (NAT-heavy users).
- Remember the honest boundary of R6: source IP ≠ worker identity. It is a hunt signal for
  coordinated sequencing, not evidence a specific worker reused state. Attack-pairing that
  uses proxies or CDNs (a resolver-churn setup) will also break this approximation — the
  same caveat as the vendor's "must reach the same worker".

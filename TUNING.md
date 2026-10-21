# Tuning and validation

The shipped rules are request-shape heuristics. Start in alert or detection-only mode and compare their hits with known legitimate upload traffic before enabling any block.

## Field-name rule (R1)

R1 targets multipart forms with both `PHP_SESSION_UPLOAD_PROGRESS` and `PHPSESSID` as body field names. PHP 8.4.4 and 8.4.27 accepted semicolon, comma and space after the multipart media type in a benign local CGI test; ModSecurity and njs header gates, plus the offline classifier, now follow those observed separators. ModSecurity and njs form parsers have not been tested against the nonstandard comma/space forms; a header match may still produce no parsed-field alert. The AWS example matches a media type at the start of the header but remains a raw-byte approximation, as does Suricata. ModSecurity and njs inspect parsed names; Suricata and AWS match body text within their inspection window. A legitimate application may use both. PHP permits a configured upload-progress field name and session name; update rules to match the application's settings. Raw-body middleboxes may inspect only an initial body window, so field order and placement affect visibility.

## Cookie-carried session observation (R8)

R8 logs a progress-field multipart form with a default-named `PHPSESSID` cookie. It covers a shape R1 misses, but normal applications commonly send session cookies on upload forms. Scope by route, change the names if PHP is configured differently, and compare against benign traffic before treating a hit as interesting. It does not log the cookie value or block.

## Repeated fields (R2)

The Python classifier recognizes 40 or more `t[]` field-name appearances. No shipped ModSecurity or Suricata rule claims to count occurrences within one request. Do not replace this with a match-rate filter or a single-field denial.

## Large-body heuristic (R3)

ModSecurity, Suricata and njs use a 5 MiB body-size surrogate with a progress field. It does not verify memory exhaustion or uniform parts and may flag ordinary large uploads. Scope it to the relevant application paths or leave it alert-only. Suricata's Content-Length check misses chunked requests. The former AWS 5 MiB `Body` size example was retired: AWS forwards only an 8–64 KiB inspection window, depending on resource type and configuration, and `CONTINUE` evaluates available body content rather than a full 5 MiB body.

Set body-size and buffering limits to values appropriate for the application; avoid raising them solely to make this heuristic fire. For ModSecurity, check `SecRequestBodyLimit`, `SecRequestBodyNoFilesLimit`, and `INBOUND_DATA_ERROR`. For njs, `readRequestForm()` reads the request body; tune `client_max_body_size` and review memory use. The njs handler logs parser failures and lets the upstream process the request; it does not interpret a parse failure as an attack.

## Optional deny-all progress policy (R4)

R4 is commented out in the ModSecurity file. Enable it only after confirming the application never uses upload-progress tracking. It denies the whole matching upload. The PHP setting `session.upload_progress.enabled = Off` instead permits the upload while omitting progress tracking; use that setting when the feature is unnecessary.

## Required deployment checks

- Run each engine's syntax/configuration validation and record version and result.
- Replay benign uploads, both-field uploads, large uploads, malformed forms, and chunked requests through a staging instance.
- Record rule IDs, expected action, actual action, false positives, body-inspection limit, and any parser errors.
- Reassess these observations after each PHP runtime upgrade and compare matches with application traffic.

## Cross-request investigation

The former Suricata same-IP sequence rule has been removed. The screenshot's elapsed time is one demonstration, not a defensible detection window, and a client IP cannot identify a PHP worker. If origin telemetry includes worker identity, compare request IDs, worker IDs and fatal-error timing during incident review. The offline [triage utility](scripts/triage_events.py) can rank redacted events with those flags and separately review a later pre-init INI diagnostic after a fatal or late-cleanup diagnostic on the same worker; it does not provide Cloudflare's inline full-transaction detection or prove exploitation. The 300-second default is an analyst review window, not a vulnerability timing requirement.

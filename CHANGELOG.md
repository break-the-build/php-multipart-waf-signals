# Changelog

## 1.2.0 — 2026-10-21 (official advisory day)

- Added the official patch-day mapping: CVE-2026-109618 (OOM `longjmp`
  corruption; mitigations: enforced `memory_limit=-1`, post_max_size,
  NOT RLIMIT_AS/DATA) and CVE-2026-109619 (stale global state; the session
  upload-progress lifecycle is an upstream-confirmed producer/consumer window;
  mitigation: enforced `session.upload_progress.enabled=0` + restart workers;
  PHP 8.5 additionally `fatal_error_backtraces=0`).
- Fixed versions: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (+ backport branches for
  7.4/8.0/8.1). Advisory links in README.
- Updated rule-meaning notes: the upload-progress INI control now has vendor
  attribution as a partial, not complete, mitigation; per the vendor it remains
  prudent even post-patch for fleets not using progress bars.
- Post-patch posture: upstream removes the pre-executor decode machinery the
  shapes rode (`rfc1867_no_user_code.phpt`) — R1-R3 downgrade to observe on
  patched fleets; R4 stays optional.
- Suricata `-T` syntax-clean transcript for the current rules file archived.


## Unreleased — rule review and verification pass

- Replaced ModSecurity raw-body checks with multipart `ARGS_POST_NAMES` checks; removed the single-field rule that claimed to count 40 parts. The optional deny-all progress rule is commented out and described as a whole-request block.
- Replaced Suricata's match-rate-as-part-count rules with two alert-only heuristics. The large-body rule now uses a documented numeric Content-Length check at 5 MiB.
- Reworked nginx logic as an njs 0.9.9+ `js_access` handler using `readRequestForm()`, with explicit allow, deny, and parse-error paths. Added mock behavior tests.
- Added a structurally valid AWS WAF R1 example and tests for its rule-level fields and text transformations.
- Corrected the offline classifier's HTTP method and Content-Type checks; narrowed platform claims and documented missing engine validation.
- Parsed multipart boundaries in the offline classifier so field-like text inside a file's data is not treated as a field name. Removed unvalidated vendor snippets from the active platform guide; Git history retains the earlier drafts.

## 1.1.0 — 2026-10-21 (pushed ahead of the 14:00 UTC advisory)

Published pre-release notes on timing: the corrected threat model below is a
*reduction* of what the public leak page (jackalsyn.com 2026-10-21 correction)
already discloses, plus defensive detection rules for already-public request
shapes. No new technical detail beyond public state; see README "Status &
accuracy". Findings-specific deltas from our lab memory will follow in a
post-advisory (post-14:00 UTC) commit once the official patch text lands.

- **Corrected threat model.** Cached-pointer path confirmed non-UAF (Z_TRY_ADDREF
  holds the array; lab + independent leak-side correction now agree). RCE status
  stays vendor-asserted; corrected public page rates the reachable harm
  memory-safety, CVSS v4.0 5.3 Medium, prefork-style SAPIs only.
- New **OOM-churn arm** shape (progress field + multi-MB uniform parts):
  - Suricata rule 20260004 (Content-Length surrogate ≥ 10,000,000),
  - ModSecurity stage 3 (20260004) + R4 stopgap (20260005, progress-name deny-all
    for apps that never use progress bars),
  - nginx njs OOM early-return on ≥5 MiB + progress field, plus a fix for the
    groom counting bug (`test()` boolean never fired).
- `scripts/detection_rules.py`: `STATUS_OOM` + `_oom_state`; suite 8/8 OK incl.
  two new OOM tests.
- `docs/detection-platforms.md`: multi-platform rule pack for Cloudflare, AWS WAF,
  Akamai, Imperva, Azure WAF, F5 BIG-IP, ModSecurity CRS, Snort 3, Zeek, with
  honest body-inspection coverage caveats and the post-patch downgrade plan.
- TUNING.md: OOM knob, platform caveats, false-positive boundary notes.

## 1.0.0 — 2026-10-21
- Initial public release: defensive detection rules for the reported
  PHP `session.upload_progress` heap-UAF pair.
- Suricata (3 rules), ModSecurity (2+static, 1 counting), nginx njs heuristic.
- Inert Python classifier + unit tests (benign/arming/groom/junk).
- No exploit content; detection only.

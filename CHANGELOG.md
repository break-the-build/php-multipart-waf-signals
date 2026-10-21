# Changelog

## 1.1.0 — 2026-10-21 (post-advisory push pending)

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

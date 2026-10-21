# php-uploadprogress-waf

Defensive detection rules for PHP `session.upload_progress`
(CVE-2026-109618 / CVE-2026-109619, coordinated disclosure 2026-10-21 14:00 UTC).

This repository contains **detection/mitigation content only** — no exploit
code, no payload builders, no weaponized structures. The signatures were
derived from request *shapes* verified in an isolated local lab and
cross-checked against the public technical writeup.

## Status & accuracy (updated with the corrected threat model, 2026-10-21)

- The **cached-pointer chain described previously is not, by itself, a
  use-after-free primitive**: `Z_TRY_ADDREF` keeps the array alive, so the
  writes land in live (but logically detached) memory — silent state
  corruption, not a free-then-reuse weapon. The lab's 26-arm instrumented
  sweep (ASan+UBSan, 3 builds) produced no sanitizer diagnostic; an independent
  leak-side correction (Jackalsyn 2026-10-21) now publishes the same conclusion.
- The corrected public understanding points at a **cross-request
  `BG(unserialize)`/`BG(serialize)` orphan** reachable via a
  `memory_limit` bailout inside the pre-RINIT session machinery
  (prefork-style SAPIs only; php-fpm/CGI/LSAPI exit on the fatal) —
  memory-safety (**CVSS v4.0 5.3 Medium** in the corrected public page),
  explicitly **not demonstrated as code execution** by any public source.
- RCE severity continues to stand on the vendor's own rating (CVSS v4.0 9.2
  ×2) and the watchTowr reproduction statement — attributed, not reproduced
  here. No working public recreation exists to this timestamp.
- **v1.1.0 adds the OOM-churn arm rule (S6)** for the corrected shape
  and stops assuming the old groom chain is RCE staging.
- Guidance for post-patch downgrade is in `docs/detection-platforms.md` and
  TUNING.md.

## What this protects against

Shapes observable on the wire for both the original and corrected models:
- **Arming**: a staged multipart POST with the progress-name field
  (+ the documented "phase-2" re-decode churn caused by a >min_freq stall).
- **Groom** (original bundle): many repeated equal-size `t[]` parts.
- **OOM-churn arm** (corrected model): the progress field plus a body built
  from large uniform form-data parts (e.g. 20 × 262144 B) whose churn trips
  `memory_limit` inside the callback window (prefork-style SAPIs only).
- **Worker-stall** behavior the arm can leave behind (hung decode under
  tight `memory_limit` — availability, not RCE; validated in our lab).

## Strongest control (verified)

```
# php.ini or fpm pool config
session.upload_progress.enabled = Off
```

Verified in the lab to close the entire vulnerable code path. File uploads
themselves keep working; only the progress-bar poll feature is disabled.
Reload PHP-FPM after changing it.

## Layout

| Path | Content |
|---|---|
| `suricata/php-uploadprogress.rules` | arming-stage alert + groom detection_filter + **new** OOM-arm rule (Content-Length surrogate) |
| `modsecurity/php-uploadprogress.conf` | ModSecurity v3 rules (arming chain, groom counting, OOM-churn arm, R4 stopgap) |
| `nginx/php-uploadprogress.njs` | njs body heuristic (now with correct groom count + OOM early-return) |
| `docs/detection-platforms.md` | multi-platform pack (Cloudflare, AWS WAF, Akamai, Imperva, Azure, F5, ModSec CRS, Snort 3, Zeek) — with honest coverage caveats |
| `scripts/detection_rules.py` | inert classifier: clean / arming / groom / oom / junk |
| `tests/test_detection.py` | unit tests for the classifier |
| `TUNING.md` | false-positive notes, per-deployment knobs |

## Usage

**Suricata:** copy the rules into your rules directory and reload with
`suricatools` / `kill -USR2`. Body inspection requires request-body
reassembly (`request-body-minimal-block-size` tuned to your environment).

**ModSecurity:** `Include php-uploadprogress.conf` in your site config
(OWASP CRS compatible; needs `RequestBodyAccess On` and a request-body
limit ≥ 1 MB, otherwise logs will be vacuous).

**nginx:** requires `njs` module; wire the snippet into
`js_content` / a temporary location or into your access layer.

**Python:** `python3 -m unittest discover -s tests` runs the suite.

## Operating notes

- **Reject fast; do not tarpit.** The attacker's own handshake deliberately
  stalls (>min_freq pauses). Slow-laning wastes your worker time.
- **Custom INI names:** if you renamed `session.upload_progress.name`
  fleet-wide, rule 2 misses the default literal — add your name.
- **Coverage claim (honest):** signatures cover the arming stage and the
  bundle's documented recover stage. Unknown future variants require new
  coverage; this is a stopgap, not a guarantee.

## Provenance

- Verified trigger reconstruction + sanitizer logs: mirrored from an
  offline research lab (pinned php-src trees, ASan/UBSan builds).
- Public writeup consulted read-only; no third-party exploit code was
  executed at any point.

## License

MIT — see `LICENSE`.

# php-uploadprogress-waf

Defensive detection rules for the reported PHP `session.upload_progress`
heap use-after-free pair (CVE-2026-109618 / CVE-2026-109619, coordinated
disclosure scheduled 2026-10-21 14:00 UTC).

This repository contains **detection/mitigation content only** — no exploit
code, no payload builders, no weaponized structures. The signatures were
derived from request *shapes* verified in an isolated local lab and
cross-checked against the public technical writeup.

## What this protects against

`php_session_rfc1867_callback()` (ext/session/session.c) caches two raw
`zval*` bucket pointers (`post_bytes_processed`, `current_file_bytes_processed`)
into HashTables whose lifetime the request lifecycle does not preserve.
Exploitation narrations include: a single staged multipart POST that arms
both caches, a >min_freq socket stall that forces a second `update()`
(re-decode + `track_init` free), and a reclaim stage using many repeated
same-size form-data parts.

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
| `suricata/php-uploadprogress.rules` | arming-stage alert + groom-stage detection_filter rule |
| `modsecurity/php-uploadprogress.conf` | ModSecurity v3 rules (deny on arming shape, groom counting) |
| `nginx/php-uploadprogress.njs` | njs body heuristic for nginx (reject fast, do not tarpit) |
| `scripts/detection_rules.py` | inert classifier: clean / arming / groom / junk |
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

# Tuning & false positives

## Rule 20260001 (Suricata stage 1) / ModSecurity stage 1

- **False-positive risk:** an application that legitimately registers its
  session id as a *form field* named `PHPSESSID` in uploads. This is rare,
  but survey your environment before enabling deny rules; switch to
  `alert` first, then flip to `deny` after a week of clean logs.
- The ModSecurity pattern `.PHP_...` is an intentional character-class gap:
  it matches both `name="XXX"` (double quotes) and `name='XXX'`, so it also
  tolerates attribute reordering. If you need stricter matching, pin the
  `Content-Disposition` structure.
- **Chunk-transfer / reassembly:** multipart processing requires your MPM
  to re-assemble. Set `RequestBodyAccess On` and a request-body limit of
  at least 1 MiB for ModSecurity; in Suricata, tune
  `http.request-body-limit` similarly. Without this, exploitation via
  chunked transfer will simply be invisible.

## Rule 20260002 / 20260003 (groom stage)

- threshold **40** is well below the leaked bundle's 149 and far above any
  normal multi-file-upload form (typical ≤ 10 fields).
- If you observe false positives from a bespoke bulk API that legitimately
  posts hundreds of array-named form fields, scope the rule to endpoints
  that actually accept uploads (negative URI match).
- Glowtune variant names: some attackers reuse conventions (`t[]`,
  `a[]`, `f1`); add a comma-separated variant list as needed. Keep the
  *identical part size* property — it is the fingerprint, names are not.

## Timing (S3/S5, needs flow tooling — not included here)

Long pauses inside a single TCP flow followed by continued part bytes are
the min_freq exploit predicate. Zeek / Siestatic flow rules can express
"same flow, sends >1s apart, then more bytes". This repo does not include
that logic — it belongs to your NDR tooling.

## Strongest single control (repeat, verified)

```
session.upload_progress.enabled = Off
```

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

## Rule 20260004 / Stage 3-4 (OOM arm + R4 stopgap, corrected model)

- **`memory_limit` knob:** the OOM arm needs a multipart body large enough to
  trip `memory_limit` inside the rfc1867 window. The arm shape (velocity of the
  leak-v2 model) was 20 × 262144 B; our defaults at Suricata proxy (Content-Length ≥ 10,000,000),
  ModSecurity `REQUEST_BODY_LENGTH @ge 5242880` (5 MiB), and nginx njs
  `body.length >= 5 MiB + progress field` are deliberately above the shape.
  If a production app posts MULTI-MB upload progress traffic legitimately, the
  OOM rule will false-positive — scope it by URI, raise the threshold, or
  prefer the R4/stopgap lane (INI off) for those apps.
- **Body-inspection honesty:** a multi-MB body will not be fully visible to most
  WAF middleboxes. All OOM rules above are *surrogates* sized for what the
  parser sees — the real fix remains the INI stopgap; the rules exist as
  pre-patch tripwires. Validate the Content-Length subway against chunked
  transfer (no CL header) — chunked bodies slip past the surrogate.
- nginx njs `r.requestText` buffers in full; for multi-MB buffers keep your
  `client_max_body_size` caps sensible or migrate the OOM check to
  `js_body_filter` on modern njs.

## Timing (S3/S5, needs flow tooling — not included here)

Long pauses inside a single TCP flow followed by continued part bytes are
the min_freq exploit predicate. Zeek / Siestatic flow rules can express
"same flow, sends >1s apart, then more bytes". This repo does not include
that logic — it belongs to your NDR tooling.

## Strongest single control (repeat, verified)

```
session.upload_progress.enabled = Off
```

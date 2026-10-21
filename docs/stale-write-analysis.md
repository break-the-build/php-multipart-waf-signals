# Stale write in the upload-progress machinery — pre-release analysis summary

One-command live reproduction (loopback, instrumented print trace):

```sh
# in the research sandbox (php-asan-build image):
bash /src/harness/demo.sh /src/php-8.4.26/sapi/cli/php /src/php-8.4.26-defensive/sapi/cli/php
```

Recorded run: [`artifacts/stale-write-demo-transcript.txt`](artifacts/stale-write-demo-transcript.txt)
(pinned commit `c31ae58…` / `php-8.4.26`; deterministic ASan addresses).

## What the trace shows

```
CACHE P1=0x51200001a7c0 tbl=0x506000019940      <- raw zval* cached into table T_old
SEP data tbl=0x506000019940 rc=2                <- END event; refcount triggers a dup
SEPDONE data tbl(new)=0x50600001a1e0            <- progress->data retargeted to a fresh table
USE  P1(STALE-WRITE end)=0x51200001a7c0         <- cached pointer WRITES into the detached T_old
TI destroy old _SESSION tbl=…19f40              <- track_init destroys the old tree
```

- **Proven:** the write-through-stale-pointer happens in-tree (site 1,
  `post_bytes_processed`, tag line 3380 after the `SEPARATE_ARRAY` dup at 3378).
  Consequence in-tree: silent progress-state corruption (the final write lands in a
  table the live state no longer reads).
- **Not proven, and deliberately not claimed:** a free-before-use (the stale write
  still precedes the only in-tree free), any code execution, or that this site is
  either of the 2026-10-21 CVE mechanisms. The official advisories map those to a
  separate OOM `longjmp` class (CVE-2026-109618) and a stale-global-state
  producer/consumer family (CVE-2026-109619).

## Context

- 26 sweep arms across three sanitizer builds (vuln 8.4.26, 8.2.34, and a research
  patch build) produced no sanitizer diagnostic; the churn regime was verified to
  execute at scale (412–413 large decodes per run) so the negative is not a coverage gap.
- Independent labs (jackalsyn corrected page; jaiswalakshansh lab + 68-repo audit;
  xuehuolll audit) reached the same conclusions: the circulated cached-pointer
  "use-after-free" is not reproducible on stock PHP.
- A candidate defensive patch (per-use re-lookup instead of caching) exists in the
  research workspace as a demonstration; it is superseded for the CVE classes by the
  released upstream patch and kept only as a defect exhibit.

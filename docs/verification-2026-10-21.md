# Ten-pass local verification record

The fixes were prepared in an isolated local copy and applied to this repository after review. No public target was contacted and no exploit code was run.

| Pass | Check and refinement | Result |
|---:|---|---|
| 1 | Baseline Python classifier suite | 8/8 passed; did not cover engine files. |
| 2 | ModSecurity multipart semantics | Replaced `REQUEST_BODY` with parsed POST parameter names; Python suite passed. |
| 3 | Repeated-field denial | Removed rules that blocked one field while claiming to count 40; Python suite passed. |
| 4 | Suricata size check | Replaced match-rate count and incorrect size proxy; Python suite passed. |
| 5 | nginx handler phase | Replaced `js_content` guidance with `js_access` and `readRequestForm()`; JS syntax passed. |
| 6 | nginx behavior | Seven mock request cases passed, including allow, deny, boundary size, and parser failure. |
| 7 | AWS example | Added rule-shaped JSON with rule-level Action and VisibilityConfig; JSON parse passed. |
| 8 | Rule-file regression tests | AWS shape, ModSecurity body variable, and Suricata count/size checks passed. |
| 9 | Source and documentation cross-check | Tightened ModSecurity to `ARGS_POST_NAMES`; updated platform claims and parsing; 15 Python and seven JS cases passed. |
| 10 | Final local verification | Run `scripts/verify.sh`; record its stdout, stderr, and exit status in `artifacts/verification-final.*`. |

After applying the changes to the target checkout, `scripts/verify.sh` passed again: 15 Python tests and seven njs mock cases. Its stdout, stderr, and exit status are saved as `artifacts/verification-target.*`. `git diff --check` passed, and every transferred file was byte-for-byte identical to the isolated copy.

The official ModSecurity v3 reference describes `ARGS_POST_NAMES` as POST body parameter names and limits `REQUEST_BODY` to URL-encoded processing. Suricata documents numeric `byte_test` on `http.content_len`; nginx documents `js_access` allow behavior and `readRequestForm()`. These source checks support the revisions but do not replace engine execution.

**Remaining gate:** This host has no `suricata`, ModSecurity rule validator, `nginx`, or `njs` binary in PATH. No actual engine syntax check, staging replay, or AWS API validation was completed. Keep all new rules in observation mode until those checks pass in the target deployment.

Before transfer, the target repository already had an uncommitted edit to `docs/detection-platforms.md`. Its earlier diff is preserved as `artifacts/preexisting-platform-doc.patch.gz`; the latest full text and diff are preserved as `artifacts/preexisting-platform-doc-latest.md` and `artifacts/preexisting-platform-doc-latest.patch.gz`. The compressed patches preserve the exact diff bytes without introducing whitespace errors into the active Git diff. That edit asserted that `byte_test` cannot inspect `http.content_len`; the [Suricata HTTP keyword documentation](https://docs.suricata.io/en/suricata-7.0.12/rules/http-keywords.html) explicitly gives a numeric `byte_test` example for this string buffer. The edit was preserved for review rather than incorporated into the active guidance. A separate preexisting `suricata/syntax-check-suricata7.txt` reports syntax validation for the old rule file; it does not validate these revised rules.

# Ten-pass practitioner review — 21 October 2026

Scope: the local defensive rule examples in this repository. This review does not validate a CVE exploit or authorize blocking live traffic. The starting tree is the working copy of commit `ee65068ff0186465bf76074accdc19f86f71ee70`, including the prior Wiz/Google/Cloudflare updates. The starting suite passed 15 Python tests and nine njs mock cases (`artifacts/php-waf-loop-baseline.*`).

## Rubric

Each dimension is scored 0–5: 0 absent; 1 asserted only; 2 plausible but unvalidated; 3 locally checked with explicit limits; 4 primary-source grounded and independently checked in at least one relevant environment; 5 validated in each target engine with representative benign traffic, documented rollback and measured false positives. Scores describe this rule pack's evidence, not CVE severity.

| Dimension | What a practitioner should be able to verify | Starting score |
|---|---|---:|
| Source and variant accuracy | PHP/Wiz/Google/Cloudflare claims map to the right CVE and rule scope | 3 |
| Rule semantics | Each engine does what the file and comments say | 2 |
| Detection specificity | Benign uploads and marker-like file contents do not become confident alerts | 2 |
| Coverage honesty | The pack distinguishes request-only observations from runtime and response signals | 3 |
| Safe deployment | Defaults, body limits, privacy, rollback and promotion criteria are clear | 3 |
| Reproducibility | Tests, output, revisions and engine checks are preserved | 2 |
| Practitioner explanation | An operator can decide what to deploy, tune and investigate without reading research code | 2 |

## Iteration record

1. **Baseline and rubric:** Existing 15 Python / nine njs mock checks pass. Scores above establish what needs evidence; engine validation remains a known limit.
2. **Source map:** Added a practitioner guide that separates the PHP advisory classes, Wiz's named variants and the older cached-pointer observation. It states what an edge rule can and cannot observe.
3. **ModSecurity audit clarity:** Gave each active rule an operator-readable message and a common observation tag. The structural test checks that active rules contain no denial action. Connector parsing and audit-log output remain untested.
4. **Suricata safety and interpretation:** Added a three-alert/no-drop invariant and documented raw-body false positives and request-body inspection limits. The current rule revision still needs an actual `suricata -T` and packet replay; the archived syntax transcript is for an earlier revision.
5. **njs length and parser handling:** Require a positive decimal safe integer for the declared length before applying the size heuristic. Added malformed and unsafe-length mock cases and documented the info-level log and 512-field parse limit. A real nginx/njs integration run remains pending.
6. **AWS semantics and privacy:** Kept the rule in `Count`, asserted `CONTINUE` on both body matches, disabled sampled requests by default and retained metrics. Documented the body window and AWS's warning that logging redaction does not protect sampled requests. AWS `CheckCapacity` and policy-outcome validation remain pending.
7. **Offline multipart parser:** Restricted delimiter recognition to complete MIME boundary lines and added a file-content marker test. This removes a false positive in the inert classifier; it does not make raw-body Suricata or AWS matches equivalent to PHP's parser.
8. **Field parsing specificity:** Required the actual `form-data` disposition token instead of a substring such as `not-form-data`. Added a negative regression case; this applies to the offline model only.
9. **Operational runbook:** Added a runtime-first deployment decision table, staging replay set, promotion record and redacted incident fields. This makes the difference between an observation and an incident decision explicit.

10. **Final audit:** Reviewed source mapping, rule actions, mock outcomes and limitations together; added this scorecard and an evidence manifest. The current examples remain observation-only. No deployment-engine outcome is claimed.

## Final scorecard

| Dimension | Start | Final | Evidence and remaining gap |
|---|---:|---:|---|
| Source and variant accuracy | 3 | 4 | Practitioner guide links PHP advisories and the Wiz, Google and Cloudflare accounts; rule IDs do not claim CVE-specific exploit detection. |
| Rule semantics | 2 | 3 | Static tests and njs mock cases check actions and parse behavior; actual engine loading and transactions are pending. |
| Detection specificity | 2 | 3 | Added benign marker and malformed disposition regressions; no representative production false-positive sample exists. |
| Coverage honesty | 3 | 4 | Platform matrix names request-only coverage, body windows and unshipped variants. |
| Safe deployment | 3 | 4 | Count/alert/log defaults, AWS sampling off and a staging/promotion checklist are explicit; local operators must set rollback ownership. |
| Reproducibility | 2 | 3 | Baseline and ten pass outputs, exit codes and revision manifest are archived; real engine integration has not been repeated for this revision. |
| Practitioner explanation | 2 | 4 | Guide gives runtime-first decisions, event meaning, no-match meaning and a redacted investigation record. |
| **Total** | **17/35** | **25/35** | A 5/5 in any engine-dependent dimension would require deployment-specific evidence. |

The archived checks are `artifacts/php-waf-loop-baseline.*`, `artifacts/php-waf-loop-pass01.*` through `artifacts/php-waf-loop-pass10.*`, and `artifacts/php-waf-loop-target-final.*`. `artifacts/php-waf-loop-manifest.txt` records the base revision and changed-file hashes. A zero exit code means the local Python and mock checks passed, not that a WAF engine accepted or enforced a rule.

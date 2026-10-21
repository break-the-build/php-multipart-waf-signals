# Local evidence manifest — 2026-10-21

## Source and binary identity

- WAF project starting commit: `7e0022cd9fe5860b016379af23cc50015125554e`.
- PHP 8.4.4 `main/SAPI.c` SHA-256: `9bdafb2a503d7a38d175181dcefc1abb13173265fbdbda4ed7c44a2227263894` (preserved local source).
- PHP 8.4.27 `main/SAPI.c` SHA-256: `f4618191798ee7fe32ee717139a9d9eafbe1eb8d5be28add0d3e645535cfc9ac` (preserved local source).
- PHP 8.4.4 CGI binary SHA-256: `fed7746c2a89f62b629aef6b50aa434880b6972c6a79a5f25f0582221b806c80`.
- PHP 8.4.27 CGI binary SHA-256: `70b8a1a46a246e03f6abe9b68f1e5b14c554b59d0a147e36762f8172f508687f`.

## Iteration record

| Stage | Evidence | Result |
|---|---|---|
| Baseline before parser edits | `php-multipart-reliability-baseline.*` | Existing local suite passed. |
| Parser and regression change | `php-multipart-reliability-pass01.*` | Suite passed with comma/space and invalid-suffix cases. |
| Offline triage addition | `php-multipart-reliability-pass02.stdout`, `.stderr` | 27 Python tests and 14 njs cases passed. The shell wrapper then failed because `status` is a read-only zsh variable; no process exit code was captured for this stage. |
| AWS prefix refinement | `php-multipart-reliability-pass03.*` | Suite exit 0. |
| Benign local PHP CGI comparison | `php-multipart-reliability-php-cgi.*` | Exit 0, network-disabled Docker container; source and binary identities above. No exploit or sanitizer claim. |
| Offline triage CLI sample | `php-multipart-reliability-triage.*` | Exit 0; output omits the injected raw cookie. Synthetic metadata only. |
| Documentation and final local verification | `final.*` | Suite exit 0: 27 Python tests, 14 njs mock cases, JSON parse and Node syntax checks. |

The repository's actual WAF/IDS engines were not run for this revision. The archived Suricata syntax test belongs to a prior rules-file revision. Operational replay and false-positive measurement remain open gates.

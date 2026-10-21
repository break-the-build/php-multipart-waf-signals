# Evidence manifest — public PoC review, 2026-10-21

WAF repository starting revision: `ffcd5e4` (`vendor hunt signals ...`). New rule files and tests are recorded by the commit containing this manifest. Third-party code was fetched only for static inspection after user approval. It was **never executed**.

## Pinned untrusted sources

| Repository | Checkout HEAD | Key file SHA-256 | Preserved local checkout archive SHA-256 |
|---|---|---|---|
| `0x4148/CVE-2026-109618-php2shell-lab` | `bc40fb2c96d5e92121e6bf8b996f7ba3ad057413` | `scripts/php2shell_poc.py`: `04b18aaa2c50934aaf9ab97c0f299340e6bd1f9b3e92e11437367c3e9e223c2f` | `1619d1ea1895192ab01d9901a04986af163538be5ca7d63c4bb370545713a99c` |
| `Is4yev/php2shell-poc` | `d1889464eb7f69513907d1516bdd97019519b3ef` | `splat.py`: `7559a1a5e67c449911909739e2234bd8b94dee640daaf91dbd47d69ad8f79e5e` | `fa92e5cbb27ec63315cdd5b92de00a27082894704a2757f78ed49e52794cd2ac` |
| `eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC` | `4730f74fe9141ac895ce24f459179c747ce08de9` | `poc_109618.py`: `59e7cc786dcad70dedfd49424a2f22ed4b73841d8ddaeec8e7c2c9ad38fc2bed` | `859c08b8552deffa8bbd5f547dd79786b84387be5baefc8da058ea09a81266f4` |

The archives are stored in the companion local research workspace under `artifacts/third-party-{0x4148-bc40fb2c,is4yev-d1889464,eness-4730f74f}-static.tar.gz`; they are untrusted research material and are not part of the public WAF repository.

## Benign PHP comparison identity

- PHP 8.4.26 tag commit `c31ae58ecbedc7a85dac0eee5a6a88da73543e70`; CGI SHA-256 `7f62af8277061f87f016e29534c0f2c5ac0009d219ed449f1aa46de8f71dedab`.
- PHP 8.4.27 tag commit `00d8bae801541db0d95a698e108bb4b1b273fe6e`; CGI SHA-256 `70b8a1a46a246e03f6abe9b68f1e5b14c554b59d0a147e36762f8172f508687f`.
- Network-disabled local image identity: `php-asan-build:latest`, image ID `sha256:dbb03d3a4a343c47370ecff59b1fafaffa32487cd2e7be6b202ee1ef0b955b10`.
- `benign-cookie-form.body` SHA-256 `e229c9e41f0679afcaed50e4b126a2596342e787d00af737688c902e3abefe62`; `benign-cookie-observer.php` SHA-256 `a777d70bd17357da49ec2cc81ece4c61345fe5905e7fa20112564a73c4b6e4e6`. Both are inert local fixtures.
- CGI environment: `SCRIPT_FILENAME=/probe/index.php`, `REQUEST_METHOD=POST`, `CONTENT_TYPE=multipart/form-data; boundary=----b`, `CONTENT_LENGTH=690`, `HTTP_COOKIE=PHPSESSID=synthetic`, `REDIRECT_STATUS=1`, `ASAN_OPTIONS=detect_leaks=0:halt_on_error=1`; stdin is the 690-byte body. Container launched with `--network none --memory 512m` and read-only fixture/binary mounts.

## Local iterations

| Stage | Output prefix | Result |
|---|---|---|
| Existing baseline | `php-waf-poc-review-baseline` | Exit 0; 27 Python tests, 14 njs mock cases. |
| Origin/response triage for early-INI path | `php-waf-poc-review-pass01` | Exit 0; 31 Python tests, 14 njs cases. |
| Synthetic offline demonstration | `php-waf-poc-review-pass02` | Exit 0; 31 Python tests, 14 njs cases. |
| R8 ModSecurity/njs log-only observation | `php-waf-poc-review-pass03` | Exit 0; 31 Python tests, 16 njs cases. |
| R8 offline classifier alignment | `php-waf-poc-review-pass04` | Exit 0; 33 Python tests, 16 njs cases. |
| Source review and coverage documentation | `php-waf-poc-review-pass05` | Exit 0; 33 Python tests, 16 njs cases. |
| Benign PHP 8.4.26/8.4.27 CGI comparison | `php-waf-poc-review-php-cgi` | Exit 0; both builds parsed the same cookie-plus-progress-field form. Network disabled, 690-byte synthetic body, ASan enabled without invalid-access report. This is **not** a CVE differential. |
| Final documentation/evidence verification | `final` | Exit 0; 33 Python tests, 16 njs cases, Node syntax, JSON parse and synthetic PoC. |

No actual ModSecurity, njs/nginx, Suricata or AWS engine was run in this review. Their detection quality and false-positive rate remain unmeasured. No stock-build sanitizer UAF trace was produced or claimed.

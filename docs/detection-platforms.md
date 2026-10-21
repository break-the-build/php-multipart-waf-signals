# Detection rule pack v2 — multi-platform (WAF + NIDS)

Translator layer for the signature inventory in `docs/detection-uploadprogress.md`
(corrected threat model: cached-pointer chain dead at addref; OOM-churn orphan arm;
post-patch posture pending the 2026-10-21 14:00 UTC release — see `#post-patch`).

Boundary (per AGENTS.md): inert request shapes only, no payloads, no scanner logic.
Every snippet below encodes STRUCTURE. Platform templates that could not be
double-checked against vendor docs at writing time are flagged `VALIDATE` — treat
them as starting points, not kept promises.

## Semantics recap — what each platform rule encodes

| Rule | Encodes | Meaning |
|---|---|---|
| R1 | S1 + S2 | arming: progress name field + body-SID in one multipart POST (unusual for real clients) |
| R2 | S4 | groom: ≥40 repeated same-name `t[]` form-data parts |
| R3 | S1 + S6 | OOM-churn arm: progress field present AND ≥4 large (≥128 KiB) form-data parts in the same body |
| R4 | stopgap enforcement | deny ANY multipart body containing the progress name — makes the edge enforce `session.upload_progress.enabled=Off` for apps that don't use progress bars (validated mitigation) |
| R5 | posture | post-patch downgrade plan (see tail) |

Rule IDs: WAF-style 2026-0001..0004; Suricata 20260001..20260003; Snort 202_60001...; treat as placeholders for your numbering policy.

---

## 1. Web Application Firewalls

### 1.1 Cloudflare WAF (Business/Enterprise — custom rules)

Cloudflare exposes raw request body (`http.request.body.raw`) on plans with body inspection,
with a default body-inspect window; on Free/Pro plans full body match is unavailable —
for those, R4 head-fragment matching is approximated on `http.request.uri`, `Content-Type`,
and the FIRST-body fragment if the plan permits. VALIDATE on your plan's limits.

```
# R1 arming (expression)
(http.request.method eq "POST"
  and any(http.request.headers["content-type"][*] contains "multipart/form-data")
  and http.request.body.raw contains "PHP_SESSION_UPLOAD_PROGRESS"
  and http.request.body.raw contains "name=\"PHPSESSID\"")
→ Block (id: 2026-0001)

# R3 OOM arm — requires larger body-inspect window than default; VALIDATE
(http.request.method eq "POST"
  and any(http.request.headers["content-type"][*] contains "multipart/form-data")
  and http.request.content.length gt 10000000
  and http.request.body.raw contains "PHP_SESSION_UPLOAD_PROGRESS")
→ Block (id: 2026-0003)

# R4 stopgap-ini enforcement for apps that never need progress bars
(http.request.method eq "POST"
  and any(http.request.headers["content-type"][*] contains "multipart/form-data")
  and http.request.body.raw contains "PHP_SESSION_UPLOAD_PROGRESS")
→ Block (id: 2026-0004)
```

### 1.2 AWS WAF v2 (rule JSON)

AWS inspects the body up to `BodyInspectionLimit` (default 8 KiB; configurable per rule
to 64 KiB with InspectWithBodyOnly / inspect limits) — the OOM part (multi-MB) lands
ABOVE it, so R3 is expressed as `SizeConstraintStatement` on BODY total length + an
arming ByteMatch that fits the first window. VALIDATE the exact body-inspection limit
for your WAF policy.

```
R1 arming (web ACL rule):
{
  "Name": "PHPUP-arming-S1S2",
  "Priority": 100,
  "Statement": {
    "AndStatement": {
      "Statements": [
        {"ByteMatchStatement": {
          "SearchString": "PHP_SESSION_UPLOAD_PROGRESS",
          "FieldToMatch": {"Body": {"OversizeHandling": "CONTINUE"}},
          "TextTransformations": [{"Type": "LOWERCASE", "Priority": 0}],
          "PositionalConstraint": "CONTAINS"}},
        {"ByteMatchStatement": {
          "SearchString": "name=\"PHPSESSID\"",
          "FieldToMatch": {"Body": {"OversizeHandling": "CONTINUE"}},
          "TextTransformations": [{"Type": "LOWERCASE", "Priority": 0}],
          "PositionalConstraint": "CONTAINS"}}
      ]},
    "VisibilityConfig": {"SampledRequestsEnabled": true, "CloudWatchMetricsEnabled": true},
    "Action": {"Block": {}}, "OverrideAction": {"None": {}}
  }
}

R3 pseudo — byte-match (progress, first 8KB) + size constraint:
{ "SizeConstraintStatement": {
    "ComparisonOperator": "GT",
    "Size": 10000000,
    "FieldToMatch": {"Body": {"OversizeHandling": "CONTINUE"}},
    "TextTransformations": [{ "Type": "NONE", "Priority": 0 }]},
  ...AND with ByteMatch(progress, Body, CONTAINS)... }
```

### 1.3 Akamai App & API Protector (custom rule template — VALIDATE)

WAP policies typically express this as a custom protection rule matching the request body;
in policy JSON, conceptually:

```
R1: scope: request.url:! "/upload-progress-exempt*" (optional)
    ||   condition: request.body contains "PHP_SESSION_UPLOAD_PROGRESS"
    && condition: request.body contains "name=\"PHPSESSID\""
    action: deny 403
R4 the same single condition drop, for apps where no app uses uploads.
```

Akamai rules with body-match require `breakpoint` / body inspection enabled and have a
default body-inspect cap; review the exact max under your Kona/App & API Protector plan.

### 1.4 Imperva WAF (Cloud WAF / SecureSphere style — VALIDATE)

Content/parameter rule concept:

```
Name: PHPUP-arming-2026
Type: Block (403)
Condition:
  Content-Type contains multipart/form-data
  AND RequestBody contains "PHP_SESSION_UPLOAD_PROGRESS"
  AND RequestBody contains "name=\"PHPSESSID\""
```

Imperva matches content inspection inside request bodies with size limits; count-based
repeated-part rules (R2) should be implemented as a Lua/parameter-rule where supported.

### 1.5 Azure WAF v2 (Front Door / AppGW custom rules template)

Azure custom rules can match `RequestBody` with a body-inspect limit (DEFAULT around
128KB; NOT the multi-MB OOM reach — see AWS-style workaround for R3).

```
R1 arming: top-level Custom Rule
  Action: Block
  MatchConditions:
    - RequestMatchVariables: [ { variableName: RequestBody } ]  # + method POST + multipart request header
      Operator: Contains
      MatchValues: [ "PHP_SESSION_UPLOAD_PROGRESS" ]
    - RequestMatchVariables: [ { variableName: RequestBody } ]
      Operator: Contains
      MatchValues: [ "name=\"PHPSESSID\"" ]
```

### 1.6 F5 BIG-IP (Advanced WAF/ASM + iRule option)

ASM/Advanced-WAF native path: create an attack signature with
`Attack String` = `name="PHP_SESSION_UPLOAD_PROGRESS"`, protocol=multipart POST; policy
action Block. For R4 stopgap enforcement beyond ASM policy, an iRule with
limited body collect works (the arming header pair sits in the first few KB):

```
when HTTP_REQUEST {
    if { [HTTP::header value Content-Type] contains "multipart/form-data" } {
        HTTP::collect 8192  ; # first window only - R1 lives there for the leak shapes
    }
}
when HTTP_REQUEST_DATA {
    set body [HTTP::payload]
    if { [string match -nocase "*name=\"PHP_SESSION_UPLOAD_PROGRESS\"*" $body]
         && [string match -nocase "*name=\"PHPSESSID\"*" $body] } {
        ; # R1 arming pair -> block
        reject
    } elseif { [string match -nocase "*PHP_SESSION_UPLOAD_PROGRESS*" $body] } {
        ; # R4 stopgap :: deny progress arm (no-progress apps) by policy
        reject
    }
    HTTP::release
}
```

### 1.7 ModSecurity with OWASP CRS (supplementary file; keep CRS default body limits)

```
# PHPUP-2026-0001 arming (phase 2: body available)
SecRule REQUEST_URI "@rx .*" "id:20260001,phase:2,deny,log,status:403,chain"
    SecRule REQUEST_METHOD "@streq POST"
        SecRule REQUEST_HEADERS:Content-Type "@rx multipart/form-data"
            SecRule REQUEST_BODY "@rx (?i)name=.PHP_SESSION_UPLOAD_PROGRESS."
                SecRule REQUEST_BODY "@rx (?i)name=.PHPSESSID."

# PHPUP-2026-0002 groom: repeated t[] parts
# (counting; tune to CRS body-reassemble dialect e.g. via REQUEST_BODY_SIZE or Lua)
# see docs rule for counting variant in a Lua rule counting `name="t[]"` >= 40

# PHPUP-2026-0003 OOM arm (progress field + large uniform parts ≥4)
SecRule REQUEST_URI "@rx .*" "id:20260003,phase:2,deny,log,status:403,chain"
    SecRule REQUEST_METHOD "@streq POST"
        SecRule REQUEST_HEADERS:Content-Type "@rx multipart/form-data"
            SecRule REQUEST_BODY "@rx (?i)name=.PHP_SESSION_UPLOAD_PROGRESS."
                SecRule REQUEST_BODY_LENGTH "@ge 520000"

# PHPUP-2026-0004 stopgap enforcement at edge (progress-name field deny-all):
SecRule REQUEST_METHOD "@streq POST" "id:20260004,phase:2,drop,log,status:403,chain"
    SecRule REQUEST_HEADERS:Content-Type "@rx multipart/form-data"
        SecRule REQUEST_BODY "@rx (?i)name=.PHP_SESSION_UPLOAD_PROGRESS."
```

Note (RL1/CRS-900): REQUEST_BODY matches only when SecRequestBodyAccess On and
the body'mime is being parsed; with SecRequestBodyLimit your cap applies (keep at
least 12 MB to retain OOM visibility, or accept partial coverage and say so in
your rules.json changelog).

---

## 2. Network Intrusion Detection

### 2.1 Suricata (HTTP app-layer; rev 2 incl. OOM arm)

```
# 20260001 rev2 — arming pair
alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"PHP UPLOADPROGRESS arming: progress key + body SID"; \
    flow:established,to_server; http.method; content:"POST"; \
    http.request_body; content:"PHP_SESSION_UPLOAD_PROGRESS"; nocase; \
    content:"name=\"PHPSESSID\""; nocase; within:64000; \
    pcre:"/boundary=/iR"; \
    detection_filter:track by_src, count 1, seconds 60; \
    classtype:web-application-attack; sid:20260001; rev:2;)

# 20260002 rev2 — groom: >=40 repeated same-name parts
alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"PHP UPLOADPROGRESS groom: repeated t[] parts"; \
    flow:established,to_server; http.method; content:"POST"; \
    http.request_body; content:"Content-Disposition|3a 20|form-data|3b 20|name=\"t[]\""; nocase; \
    detection_filter:track by_flow, count 40, seconds 30; \
    classtype:web-application-attack; sid:20260002; rev:2;)

# 20260003 rev1 — OOM arm: progress field + total body > 10MB (use Content-Length as proxy)
alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"PHP UPLOADPROGRESS OOM arm: progress + large body"; \
    flow:established,to_server; http.method; content:"POST"; \
    http.content_len; byte_test:0,>,10000000,0,relative; \
    http.request_body; content:"PHP_SESSION_UPLOAD_PROGRESS"; nocase; within:4000; \
    classtype:web-application-attack; sid:20260003; rev:1;)
```

Set `http.request-body-limit` ≥ 20000000 in suricata.yaml for the OOM rule; else this
rule degrades to a header-window-only match for R1-like body prefixes.

### 2.2 Snort 3

```
# Snort 3 app-layer keywords (http body) — validate parser config request-body depth
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS \
  ( msg:"PHP UP arming: progress + body SID"; \
    flow:established,to_server; http_method; content:"POST"; http_uri; \
    http_client_body; content:"PHP_SESSION_UPLOAD_PROGRESS"; nocase; \
    http_client_body; content:"name=\"PHPSESSID\""; nocase; within:64000; \
    metadata:policy balanced-ips alert; \
    detection_filter:track by_src, count 1, seconds 60; \
    classtype:attempted-admin; sid:20260001; rev:2; )
```

Snort 3 doesn't carry our numbering conventions — your policy's `sid` pool will differ.

### 2.3 Zeek (script for flow-timing signals S3/S5; test before prod)

Zeek is strongest for the flow-level signals no body regex sees:
same connection, ≥2 sends spaced >1.3s, and continued file bytes across the gap.

```
# php_up_stall.zeek — PROTOTYPE (test in a shadow circuit before prod)
module php_up_stall;
export {
  redef enum Log::ID += { LOG };
}
event http_message_done(c: connection, is_orig: bool, part: string) {
  if ( !is_orig ) return;
  if ( "multipart/form-data" !in c$http$refs_in ) return;
  local r = c->conn; if (|r->stall_gaps| >= 1) { r->note (...)
    # sketch: record conn, uid, ts, first+last send timestamps, stall gaps
  }
}
event new_connection(c: connection) { add to watch set }
event connection_gap(c: connection, dt: double) {
  if (dt > 1.3) { add c->uid to stall set }
}
```

Tune thresholds; alert-only is by-design (no payload semantics):
post to your Zeek policy after unit pass in a shadow stack.
Sketch intent only — Zeek's HTTP analyzer does not expose send-gap callbacks directly;
you would implement S3/S5 via conn flow sampling (`conn.log` delta_ts) or a custom
DPI hook, VALIDATE against your Zeek version before prod.
(Include this honesty note with any deployment of this snippet.)

---

## 3. `#post-patch` — downgrade schedule

Once upstream releases fixed versions (auto branch in this repo's advisory pipeline —
`build/scripts/check-release.sh` will pin the moved tags):

- R1/R2/R3: **BLOCK → OBSERVE** for 2 weeks, then drop unless your estate includes
  unpatchable old versions you also accepted as in-scope.
- R4 (stopgap, progress-name field deny): RETIRE when the `php.ini` stopgap has rolled out
  per server; if you managed a `/upload-progress-exempt` allowlist for legit progress users,
  rebuild rules to allow-uri only-benign progress users at their app paths.
- Keep: S3/S5 flow signals and process-spawn detection (see Huntress 2026-10-21 writeup on
  watching PHP worker processes for anomalous children) for the post-patch drift window.

## Coverage honesty

- The OOM arm lives in MULTI-MB bodies. Most body-inspecting WAFs cap body inspection
  (8 KiB AWS default WAF body-inspection; Cloudflare/Azure/Akamai per-plan caps; ModSec
  `SecRequestBodyLimit`). Plan WAF coverage assuming an OOM-visibility gap unless your
  platform's inspector policy proves bigger windows; for the OOM shape your restrictive
  fallback is R4-style edge enforcement (drop the progress arm as such) + size-constraint
  at the load balancer, then the runtime INI stopgap closes the whole path server-side.
- All data above is inert (structural strings) — nothing in these rules fires on executed
  code segments; the repository test suite encodes benign/arming/groom/oom/junk shapes.
```

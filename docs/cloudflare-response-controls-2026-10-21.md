# Cloudflare response controls: what changed for PHP2Shell

Source review: 2026-10-21. This is an operational guide, not a copy of Cloudflare's unpublished PHP2Shell signatures.

## The new detection surface

Cloudflare says its [full transaction detection](https://blog.cloudflare.com/full-transaction-waf/) evaluates a request with its origin response. A response custom rule can replace a matching origin response with a block page before the requester receives it. It **cannot reverse anything the origin already did**. Cloudflare says its first managed response protections cover [PHP2Shell](https://blog.cloudflare.com/php-vulnerabilities-waf-protection/), including request and response evidence that this repository's request-only R1–R8 rules cannot express.

On a Cloudflare-proxied zone, review **Security → Security Rules** and the **Cloudflare Managed Response Firewall Default** ruleset. Cloudflare describes this as the supported route to its managed full-transaction detections, with a scope that can be narrowed for an application. Review matching events in Security Analytics and Security Events. Do not infer from the presence of this repository's multipart field names that a Cloudflare PHP2Shell managed detection matched.

## A custom response rule example

Cloudflare's [published example](https://blog.cloudflare.com/full-transaction-waf/) is an application access policy, **not a PHP2Shell signature**:

```text
http.request.uri.path starts_with "/admin"
and not http.request.headers["x-internal-user"][0] eq "true"
and http.response.code eq 200
and http.response.headers["content-type"][0] contains "text/html"
```

The example blocks an unmarked request to an administration path only after the origin returns successful HTML. Authentication failures, redirects, and other paths do not satisfy it. Before using an analogous rule, scope it to the actual host and protected routes, and ensure a trusted authentication gateway **removes any client-supplied `x-internal-user` header and sets its own marker**. Otherwise the marker is spoofable. A `200 text/html` page alone may be a public login page; verify the application's normal responses first. Start with **Log**, inspect representative events and false positives, then consider **Block** only for a reviewed application policy.

Cloudflare says all plans can create up to three response custom rules with Log and Block actions. Paying customers can use `cf.waf.signature.response.*` detection results where the rollout has reached their zone; field access should be checked in the live rule editor. Its article states that custom response rules **cannot inspect the response body yet**. Consequently this repository supplies no guessed PHP2Shell response expression or cookie-length threshold. Use the managed response ruleset for Cloudflare's PHP2Shell detection, and update PHP to a fixed runtime.

## What this means for the local rule pack

| Signal | Where it is evaluated | What it can establish |
|---|---|---|
| R1–R8 multipart observations | Request inspection | A request shape worth reviewing; not exploitation. |
| Status, content type, redacted cookie anomaly, origin error | Offline `triage_events.py` or a response-capable product | More context for a single transaction; still requires investigation. |
| Cloudflare managed full-transaction detection | Cloudflare response phase | A vendor detection outcome; inspect its event and scope. |
| Custom protected-route response policy | Cloudflare response custom rule | A possible access-control failure for that application; not a PHP CVE diagnosis. |

Response blocking can prevent disclosure of a matching response, but it cannot undo memory corruption, code execution, or other origin-side effects. Request-side mitigation and a patched PHP runtime remain necessary. Preserve redacted request IDs, response status, rule ID/action, and origin worker IDs where available; never export raw cookies or response bodies into this project's triage fixtures.

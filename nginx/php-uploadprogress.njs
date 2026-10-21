// PHP session.upload_progress UAF pair (CVE-2026-109618 / CVE-2026-109619)
// Defensive detection only. Requires the njs http module.
// Wire in: js_content this file at the access layer, call checkUploadProgress(r).
//
// Operation: reject fast (no tarpit). Attacker handshakes stall on purpose.

function checkUploadProgress(r) {
    if (r.method !== "POST") { return null; }
    var ct = r.headersIn["Content-Type"] || "";
    if (!ct.includes("multipart/form-data")) { return null; }

    // Avoid buffering giant bodies: inspect up to 1 MiB.
    var limit = 1024 * 1024;
    var len = Number(r.headersIn["Content-Length"] || 0);
    if (len === 0 || len > limit) { return null; }

    var body = "";
    // NOTE: reading the body is only possible in a content/rewrite phase
    // handler that returns HTTP_ constants; adjust to your wiring.
    // The checks below assume body is available.
    body = (typeof r.requestText !== "undefined") ? r.requestText : "";
    if (!body) { return null; }

    var arm = /name="?PHP_SESSION_UPLOAD_PROGRESS"?/i.test(body)
           && /name="?PHPSESSID"?/i.test(body);
    var groom = (/name="?t\[\]"?/gi.test(body) || "").length >= 40;

    if (groom || arm) { r.log("PHP UPLOADPROGRESS trigger shape detected"); return r.return(403); }
    return null;
}

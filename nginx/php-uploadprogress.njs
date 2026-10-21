// PHP session.upload_progress UAF pair (CVE-2026-109618 / CVE-2026-109619)
// Defensive detection only. Requires the njs http module.
// Wire in: js_content this file at the access layer, call checkUploadProgress(r).
//
// Operation: reject fast (no tarpit). Attacker handshakes stall on purpose.
//
// v1.1.0 corrected-model additions:
// - OOM-churn arm (progress field + multi-MB body): bodies in this shape are
//   returned early, before heavy parsing work, with only an 8 KiB scan.
// - Fixed groom counting (previous boolean-test arithmetic never fired).

function checkUploadProgress(r) {
    if (r.method !== "POST") { return null; }
    var ct = r.headersIn["Content-Type"] || "";
    if (!ct.includes("multipart/form-data")) { return null; }

    var body = "";
    // NOTE: reading the body is only possible in a content/rewrite phase
    // handler that returns HTTP_ constants; adjust to your wiring.
    // The checks below assume body is available.
    body = (typeof r.requestText !== "undefined") ? r.requestText : "";
    if (!body) { return null; }

    // OOM arm (corrected model, leak-v2): large uniform form-data parts.
    // Surrogate: total body >= 5 MiB AND the progress field in the first 8 KiB
    // (the field always sits at the head of the leak's arm shapes).
    if (body.length >= 5 * 1024 * 1024
        && /name="?PHP_SESSION_UPLOAD_PROGRESS"?/.test(body.slice(0, 8192))) {
        r.log("PHP UPLOADPROGRESS oom arm: large body + progress field");
        return r.return(403);
    }

    var arm = /name="?PHP_SESSION_UPLOAD_PROGRESS"?/i.test(body)
           && /name="?PHPSESSID"?/i.test(body);

    // Fix: previous boolean-test arithmetic never counted (test() has no length)
    var groomCount = (body.match(/name="?t\[\]"?/gi) || []).length;
    var groom = groomCount >= 40;

    if (arm || groom) {
        r.log("PHP UPLOADPROGRESS trigger shape detected (arm=" + arm
              + " groom=" + groomCount + ")");
        return r.return(403);
    }
    return null;
}

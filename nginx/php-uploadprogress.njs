// Use as a js_access handler with njs >= 0.9.9. Benign requests return
// without calling r.return(), so nginx continues to the normal content handler.
// Enable only on upload locations after testing the application's forms.

const LARGE_BODY_BYTES = 5242880;
const MAX_FORM_KEYS = 512;

async function checkUploadProgress(r) {
    if (r.method !== "POST") return;
    const contentType = r.headersIn["Content-Type"] || "";
    if (!/^multipart\/form-data(?:;|$)/i.test(contentType)) return;

    let form;
    try {
        form = await r.readRequestForm({maxKeys: MAX_FORM_KEYS});
    } catch (error) {
        r.log("PHP upload-progress rule could not parse multipart form: " + error);
        r.return(400);
        return;
    }

    if (!form.has("PHP_SESSION_UPLOAD_PROGRESS")) return;

    if (form.has("PHPSESSID")) {
        r.log("PHP upload-progress field with body session id");
        r.return(403);
        return;
    }

    // Size-only heuristic; Content-Length is absent for chunked requests.
    const contentLength = Number(r.headersIn["Content-Length"] || 0);
    if (Number.isFinite(contentLength) && contentLength >= LARGE_BODY_BYTES) {
        r.log("PHP upload-progress field with large multipart body");
        r.return(403);
    }
}

export default {checkUploadProgress};

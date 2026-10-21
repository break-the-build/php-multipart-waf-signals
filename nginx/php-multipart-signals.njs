// Observation-only js_access handler for njs >= 0.9.9. Returning without
// r.return() lets nginx continue to the normal content handler. Apply only
// to upload locations after checking normal application traffic.

const LARGE_BODY_BYTES = 5242880;
const MAX_FORM_KEYS = 512;

async function checkPhpMultipartSignals(r) {
    if (r.method !== "POST") return;
    const contentType = r.headersIn["Content-Type"] || "";
    if (!/^multipart\/form-data(?:;|$)/i.test(contentType)) return;

    // A multipart request without a usable declared length is an advisory
    // investigation lead, but normal chunked uploads also have this shape.
    const lengthHeader = r.headersIn["Content-Length"];
    const declared = typeof lengthHeader === "string" && /^[1-9][0-9]*$/.test(lengthHeader)
        ? Number(lengthHeader) : NaN;
    if (!Number.isSafeInteger(declared)) {
        r.log("PHP multipart request without usable Content-Length; review request limits");
        return;
    }

    let form;
    try {
        form = await r.readRequestForm({maxKeys: MAX_FORM_KEYS});
    } catch (_) {
        r.log("PHP upload-progress rule could not parse multipart form");
        return;
    }

    if (!form.has("PHP_SESSION_UPLOAD_PROGRESS")) return;

    if (form.has("PHPSESSID")) {
        r.log("PHP upload-progress field with body session id");
    }

    // Size-only heuristic; Content-Length is absent for chunked requests.
    if (declared >= LARGE_BODY_BYTES) {
        r.log("PHP upload-progress field with large multipart body");
    }
}

export default {checkPhpMultipartSignals};

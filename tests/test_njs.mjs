import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const source = await readFile(new URL('../nginx/php-uploadprogress.njs', import.meta.url), 'utf8');
const {default: rules} = await import('data:text/javascript,' + encodeURIComponent(source));

function request(fields, length = 1000, options = {}) {
    const status = [];
    const logs = [];
    const r = {
        method: options.method || 'POST',
        headersIn: {'Content-Type': options.type || 'multipart/form-data; boundary=x', 'Content-Length': String(length)},
        async readRequestForm({maxKeys}) {
            assert.equal(maxKeys, 512);
            if (options.error) throw new Error('invalid form');
            return {has: name => fields.includes(name)};
        },
        return(code) { status.push(code); },
        log(message) { logs.push(message); },
    };
    return {r, status, logs};
}

for (const [fields, length, expected] of [
    [['file'], 1000, []],
    [['PHP_SESSION_UPLOAD_PROGRESS'], 1000, []],
    [['PHP_SESSION_UPLOAD_PROGRESS', 'PHPSESSID'], 1000, [403]],
    [['PHP_SESSION_UPLOAD_PROGRESS'], 5242879, []],
    [['PHP_SESSION_UPLOAD_PROGRESS'], 5242880, [403]],
]) {
    const test = request(fields, length);
    await rules.checkUploadProgress(test.r);
    assert.deepEqual(test.status, expected);
}
const invalid = request([], 1000, {error: true});
await rules.checkUploadProgress(invalid.r);
assert.deepEqual(invalid.status, [400]);
const get = request(['PHP_SESSION_UPLOAD_PROGRESS'], 1000, {method: 'GET'});
await rules.checkUploadProgress(get.r);
assert.deepEqual(get.status, []);
console.log('njs access-handler behavior: 7/7 passed');

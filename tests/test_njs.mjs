import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const source = await readFile(new URL('../nginx/php-multipart-signals.njs', import.meta.url), 'utf8');
const {default: rules} = await import('data:text/javascript,' + encodeURIComponent(source));

function request(fields, length = 1000, options = {}) {
    const status = [];
    const logs = [];
    const r = {
        method: options.method || 'POST',
        headersIn: {'Content-Type': options.type || 'multipart/form-data; boundary=x', 'Content-Length': options.contentLength ?? String(length)},
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
    [['PHP_SESSION_UPLOAD_PROGRESS', 'PHPSESSID'], 1000, []],
    [['PHP_SESSION_UPLOAD_PROGRESS'], 5242879, []],
    [['PHP_SESSION_UPLOAD_PROGRESS'], 5242880, []],
]) {
    const test = request(fields, length);
    await rules.checkPhpMultipartSignals(test.r);
    assert.deepEqual(test.status, expected);
    if (fields.includes('PHP_SESSION_UPLOAD_PROGRESS') &&
        (fields.includes('PHPSESSID') || length >= 5242880)) {
        assert.ok(test.logs.length > 0);
    }
}
const invalid = request([], 1000, {error: true});
await rules.checkPhpMultipartSignals(invalid.r);
assert.deepEqual(invalid.status, []);
assert.match(invalid.logs[0], /could not parse multipart form/);
const get = request(['PHP_SESSION_UPLOAD_PROGRESS'], 1000, {method: 'GET'});
await rules.checkPhpMultipartSignals(get.r);
assert.deepEqual(get.status, []);
const missingLength = request(['PHP_SESSION_UPLOAD_PROGRESS'], 0);
await rules.checkPhpMultipartSignals(missingLength.r);
assert.deepEqual(missingLength.status, []);
assert.match(missingLength.logs[0], /without usable Content-Length/);
const malformedLength = request(['PHP_SESSION_UPLOAD_PROGRESS'], 1000, {contentLength: '1e7'});
await rules.checkPhpMultipartSignals(malformedLength.r);
assert.deepEqual(malformedLength.status, []);
assert.match(malformedLength.logs[0], /without usable Content-Length/);
const unsafeLength = request(['PHP_SESSION_UPLOAD_PROGRESS'], 1000, {contentLength: '9007199254740993'});
await rules.checkPhpMultipartSignals(unsafeLength.r);
assert.match(unsafeLength.logs[0], /without usable Content-Length/);
const pair = request(['PHP_SESSION_UPLOAD_PROGRESS', 'PHPSESSID']);
await rules.checkPhpMultipartSignals(pair.r);
assert.deepEqual(pair.status, []);
assert.match(pair.logs[0], /body session id/);
console.log('njs access-handler behavior: 11/11 passed');

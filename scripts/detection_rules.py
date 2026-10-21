#!/usr/bin/env python3
"""Inert classifier for selected PHP multipart request-shape observations.

No execution of any external code, no payload construction: text signatures only.
"""
import re

BOUNDARY = re.compile(rb'(?:^|;)\s*boundary=(?:"([^"]+)"|([^;\s]+))', re.I)
FIELD_NAME = re.compile(rb'(?:^|;)\s*name="([^"]*)"', re.I)
FORM_DISPOSITION = re.compile(rb'^content-disposition:\s*form-data(?:\s*;|\s*$)', re.I)

STATUS_ARMING = "arming"          # progress name + body SID in one multipart POST
STATUS_GROOM = "groom"            # repeated t[] parts >= threshold
STATUS_OOM = "oom"                # progress arm + >=4 large form-data parts (>=128KiB each)
STATUS_CLEAN = "clean"
STATUS_JUNK = "junk"              # not multipart/POST shaped

# S6 (corrected threat model): OOM-churn arm — multipart body dominated by N or
# more large form-data parts (read-only reconstruction of the leak-v2 arm shape:
# 20 x 262144B fields inflating session decode/encode churn past memory_limit
# inside the rfc1867 pre-RINIT window). Structural observation only.
OOM_MIN_PARTS = 4
OOM_MIN_PART_SIZE = 131072  # 128 KiB — parts below this are ordinary uploads
OOM_TOTAL_MIN = 524288      # 512 KiB minimum total body before considering the shape


def _parts(payload: bytes, boundary: bytes):
    # Delimiters are complete MIME lines. Splitting on the boundary token alone
    # would invent form fields from marker-like bytes inside uploaded files.
    delimiter = re.compile(rb'(?:\A|\r\n)--' + re.escape(boundary) + rb'(?=\r\n|--)')
    markers = list(delimiter.finditer(payload))
    if not markers or markers[0].start() != 0:
        return
    for index, marker in enumerate(markers[:-1]):
        if payload[marker.end():marker.end() + 2] == b'--':
            break
        chunk = payload[marker.end() + 2:markers[index + 1].start()]
        headers, separator, content = chunk.partition(b'\r\n\r\n')
        if not separator:
            continue
        disposition = next((line for line in headers.split(b'\r\n')
                            if line.lower().startswith(b'content-disposition:')), b'')
        if not FORM_DISPOSITION.match(disposition):
            continue
        name = FIELD_NAME.search(disposition)
        if name:
            yield name.group(1), len(content), b'filename=' in disposition.lower()


def _oom_state(parts, payload_size: int) -> bool:
    if payload_size < OOM_TOTAL_MIN:
        return False
    return sum(not is_file and size >= OOM_MIN_PART_SIZE
               for _, size, is_file in parts) >= OOM_MIN_PARTS


def classify(body: bytes, threshold_t: int = 40) -> str:
    headers, separator, payload = body.partition(b"\r\n\r\n")
    if not separator:
        return STATUS_JUNK
    lines = headers.split(b"\r\n")
    if not lines[0].startswith(b"POST "):
        return STATUS_JUNK
    content_type = next((line.partition(b':')[2].strip() for line in lines[1:]
                         if line.lower().startswith(b'content-type:')), b'')
    if not content_type.lower().startswith(b'multipart/form-data'):
        return STATUS_JUNK
    boundary_match = BOUNDARY.search(content_type)
    if not boundary_match:
        return STATUS_JUNK
    parts = list(_parts(payload, boundary_match.group(1) or boundary_match.group(2)))
    names = [name for name, _, _ in parts]
    progress_name = b'PHP_SESSION_UPLOAD_PROGRESS' in names
    arm = progress_name and b'PHPSESSID' in names
    groom = names.count(b't[]') >= threshold_t
    if groom:
        return STATUS_GROOM
    # S6 requires the progress arm; a plain multi-MB upload without the field
    # is ordinary bulk traffic, not this shape.
    if progress_name and _oom_state(parts, len(payload)):
        return STATUS_OOM
    if arm:
        return STATUS_ARMING
    return STATUS_CLEAN


BENIGN_UPLOAD = (
    b"POST /upload.php HTTP/1.1\r\n"
    b"Content-Type: multipart/form-data; boundary=----b\r\n\r\n"
    b"------b\r\n"
    b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
    b"traceme\r\n"
    b"------b\r\n"
    b'Content-Disposition: form-data; name="file1"; filename="doc.pdf"\r\n\r\n'
    + b"D" * 512 +
    b"\r\n------b--\r\n"
)

ARMING_SHAPE = (
    b"POST /upload.php HTTP/1.1\r\n"
    b"Content-Type: multipart/form-data; boundary=----b\r\n\r\n"
    b"------b\r\n"
    b'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n'
    + b"a" * 32 +
    b"\r\n------b\r\n"
    b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
    b"x\r\n"
    b"------b\r\n"
    b'Content-Disposition: form-data; name="f"; filename="a"\r\n\r\n'
    b"Z\r\n"
    b"------b--\r\n"
)

GROOM_SHAPE = (
    b"POST /upload.php HTTP/1.1\r\n"
    b"Content-Type: multipart/form-data; boundary=----b\r\n\r\n"
    + b"".join(
        b"------b\r\n"
        b'Content-Disposition: form-data; name="t[]"\r\n\r\n'
        + b"R" * 288 +
        b"\r\n"
        for _ in range(149)
    ) +
    b"------b--\r\n"
)

OOM_SHAPE = (
    b"POST /upload.php HTTP/1.1\r\n"
    b"Content-Type: multipart/form-data; boundary=----b\r\n\r\n"
    b"------b\r\n"
    b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
    b"x\r\n"
    + b"".join(
        b"------b\r\n"
        b'Content-Disposition: form-data; name="f0"\r\n\r\n'
        + b"A" * OOM_MIN_PART_SIZE +
        b"\r\n"
        for _ in range(OOM_MIN_PARTS)
    ) +
    b"------b--\r\n"
)

OOM_SHAPE_PLAIN = (
    b"POST /upload.php HTTP/1.1\r\n"
    b"Content-Type: multipart/form-data; boundary=----b\r\n\r\n"
    b"------b\r\n"
    b'Content-Disposition: form-data; name="f0"; filename="bulk.bin"\r\n\r\n'
    + b"A" * (OOM_MIN_PART_SIZE * OOM_MIN_PARTS) +
    b"\r\n------b--\r\n"
)

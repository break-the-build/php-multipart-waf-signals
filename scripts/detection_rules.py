#!/usr/bin/env python3
"""Detection matcher for PHP session.upload_progress trigger shapes (inert only).

No execution of any external code, no payload construction: text signatures only.
"""
import re

SIG_PROGRESS = re.compile(rb'(?i)name="PHP_SESSION_UPLOAD_PROGRESS"')
SIG_BODY_SID = re.compile(rb'(?i)name="PHPSESSID"')
SIG_T_ARRAY = re.compile(rb'(?i)name="t\[\]"')

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


def _oom_state(body: bytes) -> bool:
    if len(body) < OOM_TOTAL_MIN:
        return False
    large = 0
    for segment in body.split(b'Content-Disposition: form-data; name="', 256):
        head = segment.lstrip(b'-\r\n')
        if len(head) >= OOM_MIN_PART_SIZE:
            large += 1
    return large >= OOM_MIN_PARTS


def classify(body: bytes, threshold_t: int = 40) -> str:
    is_multipart = b"multipart/form-data" in body.lower()
    if not is_multipart:
        return STATUS_JUNK
    progress_name = bool(SIG_PROGRESS.search(body))
    arm = progress_name and bool(SIG_BODY_SID.search(body))
    groom = len(SIG_T_ARRAY.findall(body)) >= threshold_t
    if groom:
        return STATUS_GROOM
    # S6 requires the progress arm; a plain multi-MB upload without the field
    # is ordinary bulk traffic, not this shape.
    if progress_name and _oom_state(body):
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

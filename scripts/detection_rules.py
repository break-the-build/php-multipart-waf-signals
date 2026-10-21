#!/usr/bin/env python3
"""Detection matcher for PHP session.upload_progress trigger shapes (inert only).

No execution of any external code, no payload construction: text signatures only.
"""
import re

SIG_PROGRESS = re.compile(rb'(?i)name="PHP_SESSION_UPLOAD_PROGRESS"')
SIG_BODY_SID = re.compile(rb'(?i)name="PHPSESSID"')
SIG_T_ARRAY = re.compile(rb'(?i)name="t\[\]"')

STATUS_ARMING = "arming"          # progress name + body SID in one multipart POST
STATUS_GROOM = "groom"            # repeated t[] parts >=阈值高出阈
STATUS_CLEAN = "clean"
STATUS_JUNK = "junk"              # not multipart/POST shaped


def classify(body: bytes, threshold_t: int = 40) -> str:
    is_multipart = b"multipart/form-data" in body.lower()
    if not is_multipart:
        return STATUS_JUNK
    arm = bool(SIG_PROGRESS.search(body)) and bool(SIG_BODY_SID.search(body))
    groom = len(SIG_T_ARRAY.findall(body)) >= threshold_t
    if groom:
        return STATUS_GROOM
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

#!/usr/bin/env python3
"""Offline proof of detection behavior with synthetic, non-exploit inputs.

This does not contact a server, exercise PHP memory corruption, or establish
that either CVE was triggered. It demonstrates a true request-shape match,
a benign negative control, and worker-aware event correlation.
"""

import json

from detection_rules import (ARMING_SHAPE, BENIGN_UPLOAD, STATUS_ARMING, STATUS_CLEAN,
                             STATUS_COOKIE_PROGRESS, classify)
from triage_events import triage


def run():
    benign = classify(BENIGN_UPLOAD)
    progress_pair = classify(ARMING_SHAPE)
    cookie_shape = BENIGN_UPLOAD.replace(b'Content-Type:',
                                         b'Cookie: PHPSESSID=synthetic\r\nContent-Type:', 1)
    cookie_progress = classify(cookie_shape)
    if (benign != STATUS_CLEAN or progress_pair != STATUS_ARMING
            or cookie_progress != STATUS_COOKIE_PROGRESS):
        raise AssertionError('request-shape classifier regression')

    events = [
        {'request_id': 'synthetic-producer', 'timestamp': '2026-10-21T14:00:00Z',
         'multipart': False, 'worker_key': 'worker-a', 'origin_fatal_error': True},
        {'request_id': 'synthetic-other-worker', 'timestamp': '2026-10-21T14:00:30Z',
         'multipart': False, 'worker_key': 'worker-b', 'preinit_ini_diagnostic': True},
        {'request_id': 'synthetic-same-worker', 'timestamp': '2026-10-21T14:00:45Z',
         'multipart': False, 'worker_key': 'worker-a', 'preinit_ini_diagnostic': True},
    ]
    results = list(triage(events))
    if results[1]['priority'] == 'high_priority_review':
        raise AssertionError('different workers were correlated')
    if results[2]['priority'] != 'high_priority_review':
        raise AssertionError('same-worker sequence was missed')

    print(json.dumps({'ordinary_upload': benign,
                      'progress_field_pair': progress_pair,
                      'progress_with_session_cookie': cookie_progress,
                      'cross_request_review': results[-1],
                      'proof_scope': 'synthetic detection behavior only'}, sort_keys=True))


if __name__ == '__main__':
    run()

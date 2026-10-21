#!/usr/bin/env python3
"""Prioritize redacted PHP multipart observations; never decide exploit success.

Input is newline-delimited JSON from an authorized local log export. This tool
has no network access and does not inspect request bodies or cookie values.
"""

import argparse
from datetime import datetime
import json
import sys


def _timestamp(value):
    if not isinstance(value, str):
        raise ValueError('timestamp must be an ISO 8601 string with a timezone')
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('timestamp must include a timezone')
    return parsed.timestamp()


def triage(events, window_seconds=300):
    """Yield metadata-only review leads in input order.

    Cross-request escalation requires a pseudonymous PHP worker key and a
    prior origin memory error. Client IP is never used as a worker proxy.
    """
    if window_seconds <= 0:
        raise ValueError('window_seconds must be positive')
    prior_error = {}
    previous_time = None
    for event in events:
        if not isinstance(event, dict):
            raise ValueError('each event must be an object')
        request_id = event.get('request_id')
        if not isinstance(request_id, str) or not request_id:
            raise ValueError('request_id must be a nonempty string')
        now = _timestamp(event.get('timestamp'))
        if previous_time is not None and now < previous_time:
            raise ValueError('events must be ordered by timestamp')
        previous_time = now

        rule_ids = event.get('rule_ids', [])
        if not isinstance(rule_ids, list) or any(not isinstance(item, int) for item in rule_ids):
            raise ValueError('rule_ids must be a list of integers')
        status = event.get('status')
        if status is not None and (not isinstance(status, int) or not 100 <= status <= 599):
            raise ValueError('status must be an HTTP status integer')
        worker = event.get('worker_key')
        if worker is not None and (not isinstance(worker, str) or not worker):
            raise ValueError('worker_key must be a nonempty pseudonymous string')

        shape = bool(rule_ids)
        memory_error = event.get('origin_memory_error') is True
        cookie_anomaly = event.get('session_cookie_anomaly') is True
        restart = event.get('worker_restart') is True
        multipart = event.get('multipart') is True
        prior = prior_error.get(worker) if worker else None
        same_worker_sequence = (cookie_anomaly and multipart and prior is not None
                                and 0 <= now - prior <= window_seconds)

        reasons = []
        if shape:
            reasons.append('request_shape')
        if memory_error:
            reasons.append('origin_memory_error')
        if shape and status is not None and status >= 500:
            reasons.append('matching_request_5xx')
        if cookie_anomaly:
            reasons.append('session_cookie_anomaly')
        if shape and restart:
            reasons.append('worker_restart')
        if same_worker_sequence:
            reasons.append('same_worker_error_then_cookie_anomaly')

        if reasons:
            if same_worker_sequence:
                priority = 'high_priority_review'
            elif (shape and (memory_error or cookie_anomaly or restart or (status or 0) >= 500)
                  or cookie_anomaly):
                priority = 'investigate'
            else:
                priority = 'observe'
            yield {'request_id': request_id, 'priority': priority, 'reasons': reasons}

        if memory_error and worker:
            prior_error[worker] = now


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--window-seconds', type=int, default=300,
                        help='same-worker review window; analyst choice, not an exploit limit')
    args = parser.parse_args(argv)
    events = (json.loads(line) for line in sys.stdin if line.strip())
    try:
        for result in triage(events, args.window_seconds):
            print(json.dumps(result, sort_keys=True))
    except (ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))


if __name__ == '__main__':
    main()

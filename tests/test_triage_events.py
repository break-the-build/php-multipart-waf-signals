import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from triage_events import triage


def event(request_id, second, **changes):
    row = {
        'request_id': request_id,
        'timestamp': f'2026-10-21T14:{second // 60:02d}:{second % 60:02d}Z',
        'multipart': True,
        'rule_ids': [],
        'status': 200,
    }
    row.update(changes)
    return row


class TriageTests(unittest.TestCase):
    def test_request_shape_alone_is_only_observe(self):
        result = list(triage([event('r1', 0, rule_ids=[20260001])]))
        self.assertEqual(result[0]['priority'], 'observe')

    def test_same_transaction_origin_evidence_is_investigate(self):
        result = list(triage([event('r1', 0, rule_ids=[20260006], status=500,
                                    origin_memory_error=True)]))
        self.assertEqual(result[0]['priority'], 'investigate')
        self.assertIn('origin_memory_error', result[0]['reasons'])

    def test_same_worker_sequence_is_higher_priority(self):
        rows = [event('producer', 0, worker_key='worker-a', origin_memory_error=True),
                event('consumer', 45, worker_key='worker-a', session_cookie_anomaly=True)]
        result = list(triage(rows))
        self.assertEqual(result[-1]['priority'], 'high_priority_review')

    def test_shared_client_ip_is_not_worker_identity(self):
        rows = [event('producer', 0, client_ip='192.0.2.1', origin_memory_error=True),
                event('consumer', 45, client_ip='192.0.2.1', session_cookie_anomaly=True)]
        result = list(triage(rows))
        self.assertEqual(result[-1]['priority'], 'investigate')

    def test_different_worker_and_expired_window_do_not_correlate(self):
        rows = [event('producer', 0, worker_key='worker-a', origin_memory_error=True),
                event('other-worker', 45, worker_key='worker-b', session_cookie_anomaly=True),
                event('late', 360, worker_key='worker-a', session_cookie_anomaly=True)]
        result = list(triage(rows, window_seconds=300))
        self.assertTrue(all(row['priority'] != 'high_priority_review' for row in result))

    def test_nonmultipart_fatal_then_preinit_diagnostic_is_reviewed(self):
        rows = [event('producer', 0, multipart=False, worker_key='worker-a',
                      origin_fatal_error=True),
                event('consumer', 45, multipart=False, worker_key='worker-a',
                      preinit_ini_diagnostic=True)]
        result = list(triage(rows))
        self.assertEqual(result[-1]['priority'], 'high_priority_review')
        self.assertIn('same_worker_producer_then_preinit_diagnostic', result[-1]['reasons'])

    def test_late_cleanup_then_preinit_diagnostic_is_reviewed(self):
        rows = [event('producer', 0, multipart=False, worker_key='worker-a',
                      late_cleanup_diagnostic=True),
                event('consumer', 45, multipart=False, worker_key='worker-a',
                      preinit_ini_diagnostic=True)]
        self.assertEqual(list(triage(rows))[-1]['priority'], 'high_priority_review')

    def test_ini_diagnostic_requires_same_worker_and_recent_producer(self):
        rows = [event('producer', 0, multipart=False, worker_key='worker-a',
                      origin_fatal_error=True),
                event('other', 45, multipart=False, worker_key='worker-b',
                      preinit_ini_diagnostic=True),
                event('late', 360, multipart=False, worker_key='worker-a',
                      preinit_ini_diagnostic=True)]
        self.assertTrue(all(row['priority'] != 'high_priority_review'
                            for row in triage(rows, window_seconds=300)))

    def test_ini_diagnostic_without_worker_identity_does_not_correlate(self):
        rows = [event('producer', 0, multipart=False, client_ip='192.0.2.1',
                      origin_fatal_error=True),
                event('consumer', 45, multipart=False, client_ip='192.0.2.1',
                      preinit_ini_diagnostic=True)]
        self.assertTrue(all(row['priority'] != 'high_priority_review' for row in triage(rows)))

    def test_cookie_value_is_never_emitted(self):
        rows = [event('r1', 0, session_cookie_anomaly=True, raw_cookie='private-value')]
        result = list(triage(rows))
        self.assertNotIn('private-value', str(result))

    def test_unsorted_input_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'ordered'):
            list(triage([event('later', 45), event('earlier', 0)]))


if __name__ == '__main__':
    unittest.main()

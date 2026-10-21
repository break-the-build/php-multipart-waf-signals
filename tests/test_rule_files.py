import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class RuleFileTests(unittest.TestCase):
    def test_aws_rule_has_valid_top_level_shape_and_case_matching(self):
        rule = json.loads((ROOT / 'aws/php-uploadprogress-r1.json').read_text())
        self.assertEqual({'Name', 'Priority', 'Statement', 'Action', 'VisibilityConfig'}, set(rule))
        self.assertNotIn('OverrideAction', rule)
        statements = rule['Statement']['AndStatement']['Statements']
        self.assertEqual(len(statements), 4)
        for statement in statements:
            match = statement['ByteMatchStatement']
            self.assertEqual(match['TextTransformations'][0]['Type'],
                             'LOWERCASE' if 'SingleHeader' in match['FieldToMatch'] else 'NONE')
        self.assertEqual(rule['VisibilityConfig']['MetricName'], rule['Name'])
        self.assertEqual(rule['Action'], {'Count': {}})
        self.assertFalse(rule['VisibilityConfig']['SampledRequestsEnabled'])
        self.assertTrue(rule['VisibilityConfig']['CloudWatchMetricsEnabled'])
        body_matches = [s['ByteMatchStatement']['FieldToMatch']['Body']
                        for s in statements if 'Body' in s['ByteMatchStatement']['FieldToMatch']]
        self.assertEqual(body_matches, [{'OversizeHandling': 'CONTINUE'}] * 2)

    def test_modsecurity_uses_parsed_multipart_names(self):
        rules = (ROOT / 'modsecurity/php-uploadprogress.conf').read_text()
        active = '\n'.join(line for line in rules.splitlines() if not line.lstrip().startswith('#'))
        self.assertNotIn('SecRule REQUEST_BODY ', active)
        self.assertIn('SecRule ARGS_POST_NAMES "@streq PHPSESSID"', active)
        self.assertNotIn('SecRule ARGS_POST_NAMES "@streq t[]"', active)
        self.assertNotIn('id:20260005', active)
        self.assertIn('id:20260001,phase:2,pass,log,chain', active)
        self.assertIn('id:20260004,phase:2,pass,log,chain', active)
        self.assertEqual(active.count("tag:'phpup/observe'"), 4)
        self.assertNotIn('deny,log', active)

    def test_suricata_does_not_use_match_rate_as_part_count(self):
        rules = (ROOT / 'suricata/php-uploadprogress.rules').read_text()
        active = '\n'.join(line for line in rules.splitlines() if not line.lstrip().startswith('#'))
        self.assertNotIn('detection_filter:', active)
        self.assertIn('byte_test:0,>=,5242880,0,string,dec', active)
        self.assertNotIn('xbits:', active)
        self.assertEqual(active.count('alert http '), 3)
        self.assertNotIn('drop http ', active)
        self.assertNotIn('reject http ', active)


if __name__ == '__main__':
    unittest.main()

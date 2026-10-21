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

    def test_modsecurity_uses_parsed_multipart_names(self):
        rules = (ROOT / 'modsecurity/php-uploadprogress.conf').read_text()
        active = '\n'.join(line for line in rules.splitlines() if not line.lstrip().startswith('#'))
        self.assertNotIn('SecRule REQUEST_BODY ', active)
        self.assertIn('SecRule ARGS_POST_NAMES "@streq PHPSESSID"', active)
        self.assertNotIn('SecRule ARGS_POST_NAMES "@streq t[]"', active)
        self.assertNotIn('id:20260005', active)

    def test_aws_oom_rule_combines_method_multipart_progress_and_size(self):
        rule = json.loads((ROOT / 'aws/php-uploadprogress-oom.json').read_text())
        self.assertEqual({'Name', 'Priority', 'Statement', 'Action', 'VisibilityConfig'}, set(rule))
        statements = rule['Statement']['AndStatement']['Statements']
        self.assertEqual(len(statements), 4)
        for statement in statements[:-1]:
            self.assertIn('ByteMatchStatement', statement)
        self.assertIsInstance(statements[-1]['SizeConstraintStatement']['Size'], int)
        self.assertEqual(rule['Action'], {'Block': {}})

    def test_suricata_does_not_use_match_rate_as_part_count(self):
        rules = (ROOT / 'suricata/php-uploadprogress.rules').read_text()
        active = '\n'.join(line for line in rules.splitlines() if not line.lstrip().startswith('#'))
        self.assertNotIn('detection_filter:', active)
        self.assertIn('byte_test:0,>=,5242880,0,string,dec', active)


if __name__ == '__main__':
    unittest.main()

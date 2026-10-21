import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from detection_rules import (
    ARMING_SHAPE,
    BENIGN_UPLOAD,
    GROOM_SHAPE,
    OOM_SHAPE,
    OOM_SHAPE_PLAIN,
    STATUS_ARMING,
    STATUS_CLEAN,
    STATUS_GROOM,
    STATUS_JUNK,
    STATUS_OOM,
    classify,
)


class DetectionTests(unittest.TestCase):
    def test_benign_upload_is_clean(self):
        self.assertEqual(classify(BENIGN_UPLOAD), STATUS_CLEAN)

    def test_arming_shape_detected(self):
        self.assertEqual(classify(ARMING_SHAPE), STATUS_ARMING)

    def test_groom_shape_detected(self):
        self.assertEqual(classify(GROOM_SHAPE), STATUS_GROOM)

    def test_non_multipart_is_junk(self):
        self.assertEqual(classify(b"<html>hello</html>"), STATUS_JUNK)

    def test_non_post_multipart_is_junk(self):
        self.assertEqual(classify(ARMING_SHAPE.replace(b"POST ", b"GET ", 1)), STATUS_JUNK)

    def test_multipart_word_only_in_payload_is_junk(self):
        self.assertEqual(classify(b"POST / HTTP/1.1\r\nContent-Type: text/plain\r\n\r\n"
                                  + ARMING_SHAPE), STATUS_JUNK)

    def test_php_accepted_comma_boundary_is_detected(self):
        altered = ARMING_SHAPE.replace(b'multipart/form-data; boundary=',
                                       b'multipart/form-data,boundary=', 1)
        self.assertEqual(classify(altered), STATUS_ARMING)

    def test_php_accepted_space_boundary_is_detected(self):
        altered = ARMING_SHAPE.replace(b'multipart/form-data; boundary=',
                                       b'multipart/form-data boundary=', 1)
        self.assertEqual(classify(altered), STATUS_ARMING)

    def test_multipart_suffix_is_not_accepted(self):
        altered = ARMING_SHAPE.replace(b'multipart/form-data; boundary=',
                                       b'multipart/form-datax; boundary=', 1)
        self.assertEqual(classify(altered), STATUS_JUNK)

    def test_field_name_text_inside_file_data_is_not_a_field(self):
        altered = BENIGN_UPLOAD.replace(b'D' * 512, b'name="PHPSESSID"' + b'D' * 495)
        self.assertEqual(classify(altered), STATUS_CLEAN)

    def test_boundary_token_inside_file_data_is_not_a_part(self):
        fake = (b'prefix------b\r\n'
                b'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n'
                b'not-a-real-part')
        altered = BENIGN_UPLOAD.replace(b'D' * 512, fake + b'D' * 512)
        self.assertEqual(classify(altered), STATUS_CLEAN)

    def test_non_form_data_disposition_does_not_count_as_field(self):
        altered = ARMING_SHAPE.replace(b'Content-Disposition: form-data; name="PHPSESSID"',
                                       b'Content-Disposition: not-form-data; name="PHPSESSID"')
        self.assertEqual(classify(altered), STATUS_CLEAN)

    def test_query_parameter_is_not_a_body_field(self):
        altered = BENIGN_UPLOAD.replace(b'POST /upload.php ', b'POST /upload.php?PHPSESSID=x ', 1)
        self.assertEqual(classify(altered), STATUS_CLEAN)

    def test_progress_only_body_is_clean(self):
        self.assertEqual(classify(BENIGN_UPLOAD), STATUS_CLEAN)

    def test_oom_churn_shape_detected(self):
        # Corrected (leak-v2) arm: progress field + repeated large form-data parts.
        self.assertEqual(classify(OOM_SHAPE), STATUS_OOM)

    def test_plain_large_upload_is_not_oom(self):
        # Same geometry without the progress field = ordinary bulk upload.
        self.assertEqual(classify(OOM_SHAPE_PLAIN), STATUS_CLEAN)

    def test_file_is_inert(self):
        source = (Path(__file__).resolve().parents[1] / "scripts" / "detection_rules.py").read_text()
        for prohibited in ("system(", "zend_fcall_info", "shell"):
            self.assertNotIn(prohibited, source)


if __name__ == "__main__":
    unittest.main()

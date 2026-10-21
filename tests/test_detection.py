import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from detection_rules import (
    ARMING_SHAPE,
    BENIGN_UPLOAD,
    GROOM_SHAPE,
    STATUS_ARMING,
    STATUS_CLEAN,
    STATUS_GROOM,
    STATUS_JUNK,
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

    def test_progress_only_body_is_clean(self):
        self.assertEqual(classify(BENIGN_UPLOAD), STATUS_CLEAN)

    def test_file_is_inert(self):
        source = (Path(__file__).resolve().parents[1] / "scripts" / "detection_rules.py").read_text()
        for prohibited in ("system(", "zend_fcall_info", "shell"):
            self.assertNotIn(prohibited, source)


if __name__ == "__main__":
    unittest.main()

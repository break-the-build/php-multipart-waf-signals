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

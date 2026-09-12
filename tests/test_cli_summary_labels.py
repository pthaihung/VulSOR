from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src.UI.cli import SummaryRecorder, sample_run_label


class CliSummaryLabelTests(unittest.TestCase):
    def test_run_pipeline_uses_pipeline_label_instead_of_target_stage_label(self) -> None:
        self.assertEqual("run-pipeline", sample_run_label(3, exact_stage=False))
        self.assertEqual("Stage 3 - adjudication", sample_run_label(3, exact_stage=True))

    def test_run_pipeline_summary_filename_uses_pipeline_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            summary = SummaryRecorder.create(root, split="test", stage=3, exact_stage=False)
            exact = SummaryRecorder.create(root, split="test", stage=3, exact_stage=True)

            self.assertRegex(summary.path.name, r"^\d{8}-\d{6}_test_run-pipeline\.txt$")
            self.assertRegex(exact.path.name, r"^\d{8}-\d{6}_test_only-stage-3\.txt$")


if __name__ == "__main__":
    unittest.main()

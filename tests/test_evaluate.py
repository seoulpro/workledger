from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[1]


class EvaluationTests(unittest.TestCase):
    def test_synthetic_labeled_fixture_has_no_regressions(self) -> None:
        result = subprocess.run(
            [sys.executable, str(REPOSITORY / "scripts" / "evaluate.py"), "--json"],
            cwd=REPOSITORY,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        payload = json.loads(result.stdout)

        self.assertEqual(payload["precision"], 1.0)
        self.assertEqual(payload["recall"], 1.0)
        self.assertEqual(payload["false_positive"], 0)
        self.assertEqual(payload["false_negative"], 0)


if __name__ == "__main__":
    unittest.main()

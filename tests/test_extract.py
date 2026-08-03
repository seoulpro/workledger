from __future__ import annotations

import unittest
from pathlib import Path

from workledger.adapter import CanonicalRecord
from workledger.extract import extract_findings
from workledger.model import Category
from workledger.scanner import scan


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "mixed"


class ExtractionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = scan(FIXTURE_ROOT, probe_git=False)
        cls.alpha = cls.report.find_project("alpha")
        assert cls.alpha is not None

    def test_projects_are_reconstructed_without_paths(self) -> None:
        self.assertEqual({item.name for item in self.report.projects}, {"alpha", "legacy"})
        serialized = str(self.report.to_dict())
        self.assertNotIn("/home/example", serialized)
        self.assertNotIn("C:\\Users\\example", serialized)
        self.assertNotIn("Synthetic alpha work", serialized)

    def test_explicit_state_transitions_are_reduced(self) -> None:
        states = {(finding.category, finding.summary): finding.status for finding in self.alpha.findings}

        self.assertEqual(states[(Category.TASK, "Add incremental scanning.")], "done")
        self.assertEqual(states[(Category.APPROVAL, "Publish package.")], "granted")
        self.assertEqual(states[(Category.BLOCKER, "Deployment needs credentials.")], "resolved")

    def test_compaction_summary_is_low_confidence_open_work(self) -> None:
        finding = next(item for item in self.alpha.findings if item.summary == "Add Windows path tests.")

        self.assertEqual(finding.status, "open")
        self.assertAlmostEqual(finding.confidence, 0.7)
        self.assertEqual(finding.evidence[0].kind, "compaction_summary")

    def test_tool_results_verify_commit_and_deployment(self) -> None:
        categories = {(item.category, item.status) for item in self.alpha.findings}

        self.assertIn((Category.COMMIT, "verified"), categories)
        self.assertIn((Category.DEPLOYMENT, "succeeded"), categories)

    def test_old_direct_message_schema_is_extracted(self) -> None:
        legacy = self.report.find_project("legacy")
        assert legacy is not None
        categories = {(item.category, item.status) for item in legacy.findings}

        self.assertIn((Category.DECISION, "accepted"), categories)
        self.assertIn((Category.TASK, "open"), categories)

    def test_secrets_and_personal_paths_are_masked(self) -> None:
        token = "sk-" + "synthetic123456789"
        assignment = "API" + "_KEY=" + "synthetic-value"
        record = CanonicalRecord(
            session_ref="s-0000000000",
            line=1,
            timestamp="2026-01-01T00:00:00Z",
            kind="message",
            role="assistant",
            text=f"TODO: Rotate {token} at /home/example/private/config.env; {assignment}",
        )
        serialized = str([item.to_dict() for item in extract_findings([record])])

        self.assertNotIn(token, serialized)
        self.assertNotIn("synthetic-value", serialized)
        self.assertIn("[TOKEN]", serialized)
        self.assertIn("[PATH]", serialized)
        self.assertIn("[REDACTED]", serialized)

    def test_conservative_natural_language_keeps_the_observed_subject(self) -> None:
        record = CanonicalRecord(
            session_ref="s-0000000000",
            line=4,
            timestamp="2026-01-01T00:00:00Z",
            kind="message",
            role="assistant",
            text="- We decided to keep the adapter read-only.\n- Still needs migration coverage.",
        )

        findings = extract_findings([record])
        states = {(item.category, item.summary): item.status for item in findings}
        self.assertEqual(states[(Category.DECISION, "- We decided to keep the adapter read-only.")], "accepted")
        self.assertEqual(states[(Category.TASK, "- Still needs migration coverage.")], "open")

    def test_unfinished_excludes_resolved_findings(self) -> None:
        unfinished = {(item.category, item.summary) for item in self.alpha.unfinished}

        self.assertNotIn((Category.TASK, "Add incremental scanning."), unfinished)
        self.assertNotIn((Category.APPROVAL, "Publish package."), unfinished)
        self.assertNotIn((Category.BLOCKER, "Deployment needs credentials."), unfinished)
        self.assertIn((Category.TASK, "Add Windows path tests."), unfinished)


if __name__ == "__main__":
    unittest.main()

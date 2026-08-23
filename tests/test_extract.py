from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from workledger.adapter import CanonicalRecord
from workledger.extract import ExtractionBudget, extract_findings
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

    def test_structured_secret_edge_cases_are_masked_in_findings(self) -> None:
        secrets = ("739104", 'synthetic\\"suffix', "!synthetic!")
        texts = (
            f'TODO: rotate {{"password": {secrets[0]}}}',
            f'TODO: rotate password="{secrets[1]}" next',
            f"TODO: rotate https://:{secrets[2]}@example.invalid/private",
        )
        records = [
            CanonicalRecord(
                session_ref=f"s-{index:010d}",
                origin_key=f"origin-{index}",
                line=1,
                timestamp="2026-01-01T00:00:00Z",
                kind="message",
                role="assistant",
                text=text,
            )
            for index, text in enumerate(texts)
        ]

        serialized = str([item.to_dict() for item in extract_findings(records)])

        for secret in secrets:
            self.assertNotIn(secret, serialized)
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

    def test_tool_result_cannot_pair_with_call_from_another_session(self) -> None:
        call = CanonicalRecord(
            session_ref="s-1111111111",
            line=1,
            timestamp="2026-01-01T00:00:00Z",
            kind="tool_call",
            tool_name="exec_command",
            tool_input={"cmd": "git commit -m synthetic"},
            call_id="shared-call-id",
            order=1,
        )
        foreign_output = CanonicalRecord(
            session_ref="s-2222222222",
            line=2,
            timestamp="2026-01-01T00:00:01Z",
            kind="tool_output",
            tool_output="[main abcdef123456] synthetic",
            call_id="shared-call-id",
            order=2,
        )
        matching_output = CanonicalRecord(
            session_ref=call.session_ref,
            line=3,
            timestamp="2026-01-01T00:00:02Z",
            kind="tool_output",
            tool_output="[main abcdef123456] synthetic",
            call_id="shared-call-id",
            order=3,
        )

        foreign_findings = extract_findings([call, foreign_output])
        matching_findings = extract_findings([call, matching_output])

        self.assertNotIn(Category.COMMIT, {item.category for item in foreign_findings})
        self.assertIn(
            (Category.COMMIT, "verified"),
            {(item.category, item.status) for item in matching_findings},
        )

    def test_tool_result_uses_collision_resistant_origin_identity(self) -> None:
        call = CanonicalRecord(
            session_ref="s-colliding0",
            origin_key="origin-a",
            line=1,
            timestamp="2026-01-01T00:00:00Z",
            kind="tool_call",
            tool_name="exec_command",
            tool_input={"cmd": "git commit -m synthetic"},
            call_id="shared-call-id",
            order=1,
        )
        foreign_output = CanonicalRecord(
            session_ref=call.session_ref,
            origin_key="origin-b",
            line=2,
            timestamp="2026-01-01T00:00:01Z",
            kind="tool_output",
            tool_output="[main abcdef123456] synthetic",
            call_id="shared-call-id",
            order=2,
        )
        matching_output = CanonicalRecord(
            session_ref=call.session_ref,
            origin_key=call.origin_key,
            line=3,
            timestamp="2026-01-01T00:00:02Z",
            kind="tool_output",
            tool_output="[main abcdef123456] synthetic",
            call_id="shared-call-id",
            order=3,
        )

        self.assertEqual(extract_findings([call, foreign_output]), [])
        self.assertIn(
            (Category.COMMIT, "verified"),
            {(item.category, item.status) for item in extract_findings([call, matching_output])},
        )

    def test_orphan_tool_result_cannot_create_a_deployment_finding(self) -> None:
        output = CanonicalRecord(
            session_ref="s-0000000000",
            origin_key="origin-a",
            line=1,
            timestamp="2026-01-01T00:00:00Z",
            kind="tool_result",
            tool_name="deploy",
            tool_output="Deployment succeeded",
            call_id="missing-call",
        )

        self.assertEqual(extract_findings([output]), [])

    def test_offset_timestamps_are_reduced_in_utc_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sessions = root / "sessions"
            sessions.mkdir()
            records = [
                {
                    "timestamp": "2025-12-31T22:00:00Z",
                    "type": "session_meta",
                    "payload": {"id": "timezone-session", "cwd": "/workspace/timezone"},
                },
                {
                    "timestamp": "2026-01-01T01:00:00+02:00",
                    "type": "response_item",
                    "payload": {
                        "type": "message",
                        "role": "assistant",
                        "content": "TODO: Normalize timestamps.",
                    },
                },
                {
                    "timestamp": "2025-12-31T23:30:00Z",
                    "type": "response_item",
                    "payload": {
                        "type": "message",
                        "role": "assistant",
                        "content": "DONE: Normalize timestamps.",
                    },
                },
            ]
            (sessions / "rollout.jsonl").write_text(
                "".join(json.dumps(item) + "\n" for item in records),
                encoding="utf-8",
            )

            report = scan(root, probe_git=False)

        project = report.find_project("timezone")
        assert project is not None
        finding = next(item for item in project.findings if item.category == Category.TASK)
        self.assertEqual(finding.status, "done")
        self.assertEqual(project.last_activity, "2025-12-31T23:30:00Z")

    def test_unknown_repository_cleanliness_is_not_reported_as_dirty(self) -> None:
        record = CanonicalRecord(
            session_ref="repo-0000000000",
            line=0,
            timestamp=None,
            kind="repository_state",
            metadata={"commit_hash": "abcdef123456", "clean": None},
        )

        findings = extract_findings([record])

        self.assertIn("cleanliness unknown", findings[0].summary)
        self.assertNotIn("has local changes", findings[0].summary)

    def test_shared_candidate_budget_bounds_multiple_projects(self) -> None:
        diagnostics = []
        budget = ExtractionBudget(remaining_candidates=1)
        record = CanonicalRecord(
            session_ref="s-0000000000",
            line=1,
            timestamp="2026-01-01T00:00:00Z",
            kind="message",
            role="assistant",
            text="TODO: first\nTODO: second",
        )

        first = extract_findings([record], diagnostics=diagnostics, budget=budget)
        second = extract_findings([record], diagnostics=diagnostics, budget=budget)

        self.assertEqual(len(first), 1)
        self.assertEqual(second, [])
        self.assertEqual(budget.remaining_candidates, 0)
        self.assertIn("candidate_budget_exceeded", {item.code for item in diagnostics})


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import tempfile
import unittest
import os
from pathlib import Path

from workledger.model import Category
from workledger.scanner import scan


class IndexSelectionTests(unittest.TestCase):
    def test_unindexed_rollout_is_metadata_only_unless_requested(self) -> None:
        main_id = "11111111-1111-4111-8111-111111111111"
        child_id = "22222222-2222-4222-8222-222222222222"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sessions = root / "sessions"
            sessions.mkdir()
            (root / "session_index.jsonl").write_text(
                json.dumps({"id": main_id, "thread_name": "Synthetic", "updated_at": "2026-01-01T00:00:00Z"}) + "\n",
                encoding="utf-8",
            )
            self.write_rollout(sessions / f"rollout-{main_id}.jsonl", main_id, "TODO: Indexed work.")
            self.write_rollout(
                sessions / f"rollout-{child_id}-{main_id}.jsonl",
                child_id,
                "TODO: Unindexed detail.",
                parent=main_id,
            )

            default_report = scan(root, probe_git=False)
            exhaustive_report = scan(root, probe_git=False, include_unindexed=True)

        default_project = default_report.find_project("sample")
        exhaustive_project = exhaustive_report.find_project("sample")
        assert default_project is not None and exhaustive_project is not None
        default_summaries = {item.summary for item in default_project.findings}
        exhaustive_summaries = {item.summary for item in exhaustive_project.findings}
        self.assertIn("Indexed work.", default_summaries)
        self.assertNotIn("Unindexed detail.", default_summaries)
        self.assertIn("Unindexed detail.", exhaustive_summaries)
        self.assertIn(
            (Category.BRANCH, "observed"),
            {(item.category, item.status) for item in default_project.findings},
        )
        self.assertEqual(default_report.stats.metadata_only_files, 1)
        self.assertEqual(exhaustive_report.stats.metadata_only_files, 0)

    def test_invalid_index_id_cannot_select_every_rollout(self) -> None:
        rollout_id = "33333333-3333-4333-8333-333333333333"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sessions = root / "sessions"
            sessions.mkdir()
            (root / "session_index.jsonl").write_text(
                json.dumps({"id": ".", "updated_at": "2026-01-01T00:00:00Z"}) + "\n",
                encoding="utf-8",
            )
            self.write_rollout(
                sessions / "rollout-background.jsonl",
                rollout_id,
                "TODO: Must remain metadata-only.",
            )

            report = scan(root, probe_git=False)

        project = report.find_project("sample")
        assert project is not None
        self.assertNotIn(
            "Must remain metadata-only.",
            {finding.summary for finding in project.findings},
        )
        self.assertEqual(report.stats.metadata_only_files, 1)
        self.assertIn("index_id_invalid", {item.code for item in report.diagnostics})

    @unittest.skipUnless(os.name == "posix", "symbolic-link semantics are POSIX-specific")
    def test_rejected_index_does_not_broaden_default_scan(self) -> None:
        indexed_id = "indexed-session"
        background_id = "background-session"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sessions = root / "sessions"
            sessions.mkdir()
            outside_index = root.parent / f"{root.name}-outside-index.jsonl"
            outside_index.write_text(json.dumps({"id": indexed_id}) + "\n", encoding="utf-8")
            try:
                (root / "session_index.jsonl").symlink_to(outside_index)
            except OSError as error:
                self.skipTest(f"symbolic links are unavailable: {error}")
            self.write_rollout(
                sessions / "rollout-indexed.jsonl",
                indexed_id,
                "TODO: Indexed content must remain metadata-only after index rejection.",
            )
            self.write_rollout(
                sessions / "rollout-background.jsonl",
                background_id,
                "TODO: Background content must remain metadata-only.",
            )

            report = scan(root, probe_git=False)
            outside_index.unlink()

        project = report.find_project("sample")
        assert project is not None
        summaries = {finding.summary for finding in project.findings}
        self.assertNotIn(
            "Indexed content must remain metadata-only after index rejection.",
            summaries,
        )
        self.assertNotIn("Background content must remain metadata-only.", summaries)
        self.assertEqual(report.stats.metadata_only_files, 2)
        self.assertIn("unsafe_source_path", {item.code for item in report.diagnostics})

    def test_index_selection_uses_exact_session_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sessions = root / "sessions"
            sessions.mkdir()
            (root / "session_index.jsonl").write_text(
                json.dumps({"id": "Trusted-Session"}) + "\n",
                encoding="utf-8",
            )
            self.write_rollout(
                sessions / "rollout.jsonl",
                "trusted-session",
                "TODO: Case-colliding content must remain metadata-only.",
            )

            report = scan(root, probe_git=False)

        project = report.find_project("sample")
        assert project is not None
        self.assertNotIn(
            "Case-colliding content must remain metadata-only.",
            {finding.summary for finding in project.findings},
        )
        self.assertEqual(report.stats.metadata_only_files, 1)

    @staticmethod
    def write_rollout(path: Path, session_id: str, message: str, *, parent: str | None = None) -> None:
        payload = {"id": session_id, "cwd": "/workspace/sample", "git": {"branch": "main"}}
        if parent:
            payload["parent_thread_id"] = parent
        records = [
            {"timestamp": "2026-01-01T00:00:00Z", "type": "session_meta", "payload": payload},
            {
                "timestamp": "2026-01-01T00:01:00Z",
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": message}],
                },
            },
        ]
        path.write_text("".join(json.dumps(item) + "\n" for item in records), encoding="utf-8")


if __name__ == "__main__":
    unittest.main()

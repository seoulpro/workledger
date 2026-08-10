from __future__ import annotations

import unittest

from workledger.redact import redact


class RedactionTests(unittest.TestCase):
    def test_common_provider_tokens_are_masked(self) -> None:
        tokens = (
            "gh" + "p_" + ("a" * 36),
            "github" + "_pat_" + ("B" * 32),
            "npm" + "_" + ("c" * 36),
            "AKIA" + ("D" * 16),
            "AI" + "za" + ("e" * 35),
            "xox" + "b-" + ("f" * 24),
            "sk" + "_live_" + ("g" * 24),
        )

        for token in tokens:
            with self.subTest(token_prefix=token[:6]):
                redacted = redact(f"TODO: rotate {token}")
                self.assertNotIn(token, redacted)
                self.assertIn("[TOKEN]", redacted)


if __name__ == "__main__":
    unittest.main()

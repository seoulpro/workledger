from __future__ import annotations

import unittest
import time

from workledger.redact import redact, safe_ref


_PRIVATE_KEY_BEGIN = "-----BEGIN " + "PRIVATE KEY-----"


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

    def test_structured_and_prefixed_secrets_are_masked(self) -> None:
        samples = (
            ('{"password": "synthetic-password"}', "synthetic-password"),
            ('{"authorization": "synthetic-auth"}', "synthetic-auth"),
            ("OPENAI_API_KEY=synthetic-key", "synthetic-key"),
            ("CLIENT_SECRET: 'synthetic-secret'", "synthetic-secret"),
            ("Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
            (
                'Authorization: Digest username="synthetic", response="secret-response"',
                "secret-response",
            ),
            ("https://user:synthetic-pass@example.invalid/x", "synthetic-pass"),
        )

        for value, secret in samples:
            with self.subTest(value=value):
                self.assertNotIn(secret, redact(value))

    def test_quoted_secret_matching_is_linear_for_unterminated_escapes(self) -> None:
        value = '{"password":"' + ("\\" * 8_192)
        started = time.monotonic()

        result = redact(value)

        self.assertLess(time.monotonic() - started, 2.0)
        self.assertLessEqual(len(result), 180)

    def test_escaped_quoted_secret_is_masked(self) -> None:
        secret = 'synthetic\\"password'

        self.assertNotIn(secret, redact('{"password":"' + secret + '"}'))

    def test_quoted_secret_name_with_unquoted_scalar_is_masked(self) -> None:
        secret = "739104"

        result = redact('{"password": ' + secret + "}")

        self.assertNotIn(secret, result)
        self.assertIn("[REDACTED]", result)

    def test_escaped_quote_secret_suffix_is_masked(self) -> None:
        secret = 'synthetic\\"suffix'

        for separator in (" ", ",", ";"):
            with self.subTest(separator=separator):
                result = redact(f'password="{secret}"{separator}next')

                self.assertNotIn("suffix", result)
                self.assertIn("[REDACTED]", result)

    def test_uri_password_with_empty_username_is_masked(self) -> None:
        secret = "!synthetic!"

        result = redact(f"https://:{secret}@example.invalid/private")

        self.assertNotIn(secret, result)
        self.assertIn("[REDACTED]", result)

    def test_unterminated_private_key_is_masked(self) -> None:
        secret = "synthetic-private-material"
        value = f"TODO: {_PRIVATE_KEY_BEGIN} {secret}"

        result = redact(value)

        self.assertNotIn(secret, result)
        self.assertIn("[PRIVATE KEY]", result)

    def test_adversarial_redaction_shapes_have_bounded_runtime(self) -> None:
        values = (
            "TODO: " + ("segment-" * 4_000),
            "TODO: " + (_PRIVATE_KEY_BEGIN * 4_000),
            "TODO: " + ("a." * 12_000),
        )

        for value in values:
            with self.subTest(prefix=value[:32]):
                started = time.monotonic()
                result = redact(value)

                self.assertLess(time.monotonic() - started, 1.0)
                self.assertLessEqual(len(result), 180)

    def test_paths_outside_home_directories_are_masked(self) -> None:
        paths = (
            "/private/tmp/workledger/private.txt",
            "D:\\service\\private\\config.json",
            "\\\\server\\share\\private.txt",
            "../../private/config.json",
            "file:///D:/service/private/config.json",
            '"/private/client name/config.json"',
        )

        for path in paths:
            with self.subTest(path=path):
                self.assertEqual(redact(f"TODO: inspect {path}"), "TODO: inspect [PATH]")

    def test_terminal_and_bidi_controls_are_removed(self) -> None:
        value = "TODO: safe\x1b]52;c;clipboard\x07\u202esecret"
        redacted = redact(value)

        self.assertNotIn("\x1b", redacted)
        self.assertNotIn("\x07", redacted)
        self.assertNotIn("\u202e", redacted)

    def test_display_references_do_not_collapse_distinct_surrogates(self) -> None:
        self.assertNotEqual(safe_ref("session\ud800"), safe_ref("session\ud801"))

    def test_ordinary_web_url_is_not_mistaken_for_a_file_path(self) -> None:
        value = "TODO: review https://example.invalid/docs/path"

        self.assertEqual(redact(value), value)


if __name__ == "__main__":
    unittest.main()

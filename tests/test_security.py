import unittest

from pathlib import Path
import tempfile

from proton_agent_mail.security import (
    redact,
    token_ok,
    extract_bearer,
    default_bind,
    new_token,
    sanitize_folder,
    sanitize_message_id,
)


class SecurityTests(unittest.TestCase):
    def test_token_compare(self):
        t = new_token()
        self.assertTrue(token_ok(t, t))
        self.assertFalse(token_ok(t[:-1] + "x", t))
        self.assertFalse(token_ok("", t))
        self.assertFalse(token_ok(None, t))

    def test_bearer(self):
        self.assertEqual(extract_bearer("Bearer abc"), "abc")
        self.assertIsNone(extract_bearer("Basic abc"))

    def test_redact(self):
        s = redact("Authorization: Bearer supersecretvalue")
        self.assertNotIn("supersecretvalue", s)

    def test_sanitize(self):
        self.assertEqual(sanitize_folder("INBOX"), "INBOX")
        with self.assertRaises(RuntimeError):
            sanitize_folder("../../etc/passwd")
        with self.assertRaises(RuntimeError):
            sanitize_message_id("; rm -rf /")

    def test_bind_loopback(self):
        import os

        os.environ.pop("PROTON_AGENT_ALLOW_LAN", None)
        os.environ["PROTON_AGENT_BIND"] = "127.0.0.1"
        self.assertEqual(default_bind(), "127.0.0.1")
        os.environ["PROTON_AGENT_BIND"] = "0.0.0.0"
        with self.assertRaises(RuntimeError):
            default_bind()


if __name__ == "__main__":
    unittest.main()

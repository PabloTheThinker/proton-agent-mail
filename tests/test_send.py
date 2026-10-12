import unittest

from proton_agent_mail.server import build_message


class SendHeaderTests(unittest.TestCase):
    """A caller that reaches /messages/send already holds the bearer token, so
    these guard the case the threat model cares about: an agent that has been
    prompt-injected smuggling extra headers through `to` or `subject`.
    """

    def test_rejects_crlf_in_subject(self):
        with self.assertRaises(ValueError):
            build_message("agent@localhost", "a@b.com", "Hi\r\nBcc: evil@example.com", "body")

    def test_rejects_newline_in_to(self):
        with self.assertRaises(ValueError):
            build_message("agent@localhost", "a@b.com\nBcc: evil@example.com", "Hi", "body")

    def test_non_ascii_subject_is_encoded_not_raw(self):
        # A raw non-ASCII header is rejected by Bridge; the wire must be ASCII.
        msg = build_message("agent@localhost", "a@b.com", "Café — question", "body")
        head = msg.as_bytes().split(b"\n\n", 1)[0]
        self.assertTrue(all(b < 128 for b in head), "headers must be pure ASCII on the wire")
        self.assertEqual(str(msg["Subject"]), "Café — question")

    def test_clean_message_keeps_its_headers(self):
        msg = build_message("agent@localhost", "a@b.com", "Hi", "body")
        raw = msg.as_string()
        self.assertIn("To: a@b.com", raw)
        self.assertIn("Subject: Hi", raw)
        self.assertIn("body", raw)
        self.assertNotIn("Bcc", raw)


if __name__ == "__main__":
    unittest.main()

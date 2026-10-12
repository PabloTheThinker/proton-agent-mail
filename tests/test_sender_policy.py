"""Service-side sender policy and correct reply headers."""

import unittest
from unittest import mock

from proton_agent_mail import bridge
from proton_agent_mail.bridge import BridgeClient
from proton_agent_mail.server import AgentHandler, parse_send_as

ENV = (
    "Ada Lovelace — Example Co <ada@example.org>;"
    "Example Co <contact@example.org>;"
    "Example Security <security@example.org>"
)


def handler(send_as=ENV):
    h = AgentHandler.__new__(AgentHandler)
    h.send_as = parse_send_as(send_as)
    h.from_addr = "agent@localhost"
    return h


class ResolveFromTests(unittest.TestCase):
    def test_parse_keeps_order_and_display_names(self):
        d = parse_send_as(ENV)
        self.assertEqual(list(d)[0], "ada@example.org")
        self.assertEqual(d["security@example.org"], "Example Security <security@example.org>")

    def test_default_is_the_first_entry(self):
        self.assertIn("ada@example.org", handler()._resolve_from(""))

    def test_reply_comes_from_the_address_that_was_written_to(self):
        h = handler()
        self.assertIn("contact@", h._resolve_from("", ["contact@example.org"]))
        self.assertIn("security@", h._resolve_from("", ["ada@example.org", "security@example.org"]))

    def test_reply_to_a_non_sending_address_uses_the_default(self):
        self.assertIn("ada@", handler()._resolve_from("", ["admin@example.org"]))

    def test_explicit_from_must_be_allowed(self):
        h = handler()
        self.assertIn("contact@", h._resolve_from("contact@example.org"))
        for bad in ("admin@example.org", "someone@gmail.com"):
            with self.assertRaises(ValueError):
                h._resolve_from(bad)

    def test_without_configuration_an_explicit_from_is_refused(self):
        with self.assertRaises(ValueError):
            handler("")._resolve_from("ada@example.org")
        self.assertEqual(handler("")._resolve_from(""), "agent@localhost")


RAW = (
    b"From: Pat <pat@example.com>\r\nReply-To: pat.work@example.com\r\n"
    b"To: Example Co <contact@example.org>\r\nCc: x@example.com\r\n"
    b"Subject: =?utf-8?q?Question_about_the_lab?=\r\nMessage-ID: <abc123@example.com>\r\n"
    b"References: <root@example.com>\r\nDelivered-To: contact@example.org\r\n\r\n"
)


class FakeIMAP:
    def uid(self, *a):
        return "OK", [(b"1 (UID 7 BODY[HEADER] {99}", RAW), b")"]

    def logout(self):
        pass


class HeadersTests(unittest.TestCase):
    def test_headers_give_a_reply_everything_it_needs(self):
        with mock.patch.object(BridgeClient, "_imap", lambda self, *a, **k: FakeIMAP()):
            h = BridgeClient().headers("7")
        self.assertEqual(h["message_id"], "<abc123@example.com>")
        self.assertEqual(h["references"], "<root@example.com>")
        self.assertEqual(h["reply_to"], "pat.work@example.com")
        self.assertEqual(h["from"], "pat@example.com")
        self.assertEqual(h["subject"], "Question about the lab")
        self.assertIn("contact@example.org", h["recipients"])
        self.assertIn("x@example.com", h["recipients"])


class BuildMessageTests(unittest.TestCase):
    def test_non_ascii_display_name_and_subject_are_encoded_not_raw(self):
        from email import policy
        from email.parser import BytesParser
        from proton_agent_mail.server import build_message

        m = build_message("Ada Lovelace — Example Co <ada@example.org>", "pat@example.com", "Café — question", "Hi\n",
                          in_reply_to="<a@b>", references="<r@b> <a@b>")
        wire = m.as_bytes()
        head = wire.split(b"\n\n", 1)[0]
        self.assertTrue(all(b < 128 for b in head), "headers must be pure ASCII on the wire")
        back = BytesParser(policy=policy.default).parsebytes(wire)
        self.assertEqual(str(back["From"]), "Ada Lovelace — Example Co <ada@example.org>")
        self.assertEqual(str(back["Subject"]), "Café — question")
        self.assertEqual(str(back["In-Reply-To"]), "<a@b>")
        self.assertTrue(str(back["Message-ID"]).endswith("@example.org>"))


if __name__ == "__main__":
    unittest.main()

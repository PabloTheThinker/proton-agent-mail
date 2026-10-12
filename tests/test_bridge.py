"""Native Bridge client: one attempt per send, replies read directly, shared breaker."""

import os
import smtplib
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from proton_agent_mail import bridge
from proton_agent_mail.bridge import (
    BridgeClient,
    BridgeLockout,
    MailError,
    RecipientRefused,
    SendBreaker,
)

MSG = "From: a@example.com\r\nTo: b@example.com\r\nBcc: hidden@example.com\r\nSubject: x\r\n\r\nhi\r\n"


class FakeSMTP:
    """Stands in for smtplib.SMTP; behaviour is set per test on the class."""

    instances = 0
    on_send = None  # callable raising or returning
    sent = None

    def __init__(self, *a, **k):
        type(self).instances += 1

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def ehlo(self):
        pass

    def starttls(self, context=None):
        pass

    def login(self, u, p):
        pass

    def sendmail(self, sender, rcpts, wire):
        type(self).sent = (sender, rcpts, wire)
        if type(self).on_send:
            type(self).on_send()


class BridgeSendTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        self._env = dict(os.environ)
        os.environ.update(PROTON_AGENT_STATE=str(d), PROTON_AGENT_BREAKER=str(d / "breaker.json"))
        FakeSMTP.instances, FakeSMTP.on_send, FakeSMTP.sent = 0, None, None
        self.patches = [
            mock.patch.object(bridge.smtplib, "SMTP", FakeSMTP),
            mock.patch.object(bridge, "load_credentials", lambda: ("u", "p")),
        ]
        for p in self.patches:
            p.start()
        self.client = BridgeClient()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        os.environ.clear()
        os.environ.update(self._env)
        self.tmp.cleanup()

    def test_success_one_attempt_bcc_not_on_the_wire(self):
        self.client.send_raw(MSG)
        sender, rcpts, wire = FakeSMTP.sent
        self.assertEqual(sender, "a@example.com")
        self.assertEqual(sorted(rcpts), ["b@example.com", "hidden@example.com"])
        self.assertNotIn(b"hidden@example.com", wire, "Bcc header must be stripped")
        self.assertEqual(FakeSMTP.instances, 1)
        self.assertEqual(SendBreaker().load()["state"], "closed")

    def test_lockout_opens_breaker_and_next_send_never_touches_bridge(self):
        def refuse():
            raise smtplib.SMTPResponseException(554, b"Error: Too many failed send attempts.")

        FakeSMTP.on_send = refuse
        with self.assertRaises(BridgeLockout) as ctx:
            self.client.send_raw(MSG)
        self.assertGreaterEqual(ctx.exception.retry_after, 800)
        self.assertEqual(FakeSMTP.instances, 1, "exactly one attempt, no retry loop")
        with self.assertRaises(BridgeLockout):
            self.client.send_raw(MSG)
        self.assertEqual(FakeSMTP.instances, 1, "open breaker: Bridge is not contacted")

    def test_refused_recipient_is_remembered_and_not_retried(self):
        def refuse():
            raise smtplib.SMTPRecipientsRefused({"b@example.com": (550, b"no such address")})

        FakeSMTP.on_send = refuse
        with self.assertRaises(RecipientRefused) as ctx:
            self.client.send_raw(MSG)
        self.assertIn("b@example.com", ctx.exception.addrs)
        self.assertEqual(SendBreaker().load()["state"], "closed", "a bad address is not a lockout")
        with self.assertRaises(RecipientRefused):
            self.client.send_raw(MSG)
        self.assertEqual(FakeSMTP.instances, 1, "second attempt must not reach Bridge")

    def test_probe_after_backoff_closes_on_success(self):
        br = SendBreaker()
        br.fail("554", immediate=True)
        b = br.load()
        b["next_probe"] = int(time.time()) - 1
        br._save(b)
        self.client.send_raw(MSG)
        self.assertEqual(br.load()["state"], "closed")

    def test_single_timeout_does_not_open_two_do(self):
        def hang():
            raise TimeoutError("timed out")

        FakeSMTP.on_send = hang
        with self.assertRaises(MailError):
            self.client.send_raw(MSG)
        self.assertEqual(SendBreaker().load()["state"], "closed")
        with self.assertRaises(MailError):
            self.client.send_raw(MSG)
        self.assertEqual(SendBreaker().load()["state"], "open")

    def test_refuses_non_loopback_host(self):
        with self.assertRaises(MailError):
            BridgeClient(host="10.0.0.5")

    def test_errors_are_one_family(self):
        self.assertTrue(issubclass(BridgeLockout, MailError))
        self.assertTrue(issubclass(RecipientRefused, MailError))


if __name__ == "__main__":
    unittest.main()

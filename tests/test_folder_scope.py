"""PROTON_AGENT_FOLDERS: an agent can be handed a slice of a mailbox, and every route honours it."""

import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from proton_agent_mail.security import FolderForbidden, FolderScope
from proton_agent_mail.server import AgentHandler

TOKEN = "t" * 40


class FakeMail:
    """Records every call, so a test can prove a denied request never reached the mail client."""

    def __init__(self):
        self.calls = []

    def envelopes(self, n=20, folder="INBOX", query=None):
        self.calls.append(("envelopes", folder))
        return []

    def read(self, message_id, preview=False, folder="INBOX"):
        self.calls.append(("read", folder, preview))
        return "body"

    def headers(self, message_id, folder="INBOX"):
        self.calls.append(("headers", folder))
        return {"subject": "Hi", "reply_to": "", "from": "pat@example.com", "message_id": "<a@b>", "references": "", "recipients": []}

    def flag(self, message_id, flags, add=True, folder="INBOX"):
        self.calls.append(("flag", folder))

    def send_raw(self, rfc822):
        self.calls.append(("send_raw",))


class FakeAttachments:
    def __init__(self, mail):
        self.mail = mail

    def list_attachments(self, mid, folder="INBOX"):
        self.mail.calls.append(("att-list", folder))
        return []

    def fetch_and_scan(self, mid, *, folder="INBOX", indexes=None, trust_known=False):
        self.mail.calls.append(("att-fetch", folder))
        return {"message_id": mid, "folder": folder, "count": 0, "attachments": [], "usable": [], "blocked": []}


class UnitTests(unittest.TestCase):
    def test_unset_means_every_folder_and_inbox_default(self):
        s = FolderScope.from_env("")
        self.assertFalse(s.restricted)
        self.assertEqual(s.default, "INBOX")
        self.assertEqual(s.resolve("Archive"), "Archive")
        self.assertIsNone(s.advertise())

    def test_first_entry_is_the_default_and_order_is_kept(self):
        s = FolderScope.from_env(" Jobs , Receipts,Jobs ")
        self.assertEqual(s.folders, ("Jobs", "Receipts"))
        self.assertEqual(s.resolve(None), "Jobs")
        self.assertEqual(s.resolve(""), "Jobs")

    def test_outside_the_set_is_forbidden_and_matching_is_exact(self):
        s = FolderScope.from_env("Jobs")
        for bad in ("Archive", "jobs", "JOBS", "Sent", "Jobs2"):
            with self.assertRaises(FolderForbidden, msg=bad):
                s.resolve(bad)

    def test_a_malformed_name_is_still_refused_as_unsafe_before_scope_is_consulted(self):
        with self.assertRaises(RuntimeError):
            FolderScope.from_env("Jobs").resolve("Jobs/../Sent")

    def test_inbox_is_case_insensitive_only_for_inbox(self):
        s = FolderScope.from_env("inbox")
        self.assertEqual(s.folders, ("INBOX",))
        self.assertEqual(s.resolve("Inbox"), "INBOX")

    def test_malformed_scope_fails_at_startup(self):
        for raw in (",", " , ,", "Jobs,../etc", "Jobs;rm"):
            with self.assertRaises(RuntimeError, msg=raw):
                FolderScope.from_env(raw)


class HttpTests(unittest.TestCase):
    def start(self, folders="", read_only=False):
        self.mail = FakeMail()
        AgentHandler.token = TOKEN
        AgentHandler.mail = self.mail
        AgentHandler.attachments = FakeAttachments(self.mail)
        AgentHandler.scope = FolderScope.from_env(folders)
        AgentHandler.read_only = read_only
        AgentHandler.send_as = {}
        srv = ThreadingHTTPServer(("127.0.0.1", 0), AgentHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(lambda: (srv.shutdown(), srv.server_close()))
        self.base = f"http://127.0.0.1:{srv.server_address[1]}/inboxes/default"

    def call(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def test_unscoped_service_behaves_as_before(self):
        self.start()
        self.assertEqual(self.call("GET", "/messages")[0], 200)
        self.assertEqual(self.call("GET", "/messages?folder=Archive")[0], 200)
        self.assertEqual(self.mail.calls, [("envelopes", "INBOX"), ("envelopes", "Archive")])

    def test_scoped_service_defaults_to_the_first_folder(self):
        self.start("Jobs,Receipts")
        self.assertEqual(self.call("GET", "/messages")[0], 200)
        self.assertEqual(self.call("GET", "/messages?folder=Receipts")[0], 200)
        self.assertEqual(self.mail.calls, [("envelopes", "Jobs"), ("envelopes", "Receipts")])

    def test_every_route_refuses_a_folder_outside_the_scope_with_403_and_never_touches_mail(self):
        self.start("Jobs")
        denied = [
            ("GET", "/messages?folder=Archive", None),
            ("GET", "/messages/7?folder=Archive", None),
            ("GET", "/messages/7/attachments?folder=Archive", None),
            ("GET", "/threads?folder=Archive", None),
            ("POST", "/messages/7/attachments/fetch", {"folder": "Archive"}),
            ("POST", "/messages/7/reply", {"folder": "Archive", "text": "x"}),
            ("PATCH", "/messages/7", {"folder": "Archive", "add_labels": ["read"]}),
            ("PATCH", "/messages/7?folder=Archive", {"add_labels": ["read"]}),
        ]
        for method, path, body in denied:
            code, out = self.call(method, path, body)
            self.assertEqual(code, 403, f"{method} {path}")
            self.assertEqual(out["error"], "folder_forbidden")
            self.assertEqual(out["allowed_folders"], ["Jobs"])
        self.assertEqual(self.mail.calls, [], "a denied request must not reach the mail client")

    def test_a_bare_message_read_uses_the_scoped_default_not_inbox(self):
        self.start("Jobs")
        code, out = self.call("GET", "/messages/7")
        self.assertEqual((code, out["folder"]), (200, "Jobs"))
        self.assertEqual(self.mail.calls, [("read", "Jobs", True)])

    def test_reply_and_flags_stay_in_the_scoped_folder(self):
        self.start("Jobs")
        self.assertEqual(self.call("POST", "/messages/7/reply", {"text": "thanks"})[0], 200)
        self.assertEqual(self.call("PATCH", "/messages/7", {"add_labels": ["read"]})[0], 200)
        self.assertIn(("headers", "Jobs"), self.mail.calls)
        self.assertTrue(all(c[1] == "Jobs" for c in self.mail.calls if c[0] in {"headers", "flag"}), self.mail.calls)

    def test_inbox_advertises_its_scope(self):
        self.start("Jobs,Receipts")
        box = self.call("GET", "")[1]["inboxes"][0]
        self.assertEqual((box["folders"], box["default_folder"], box["read_only"]), (["Jobs", "Receipts"], "Jobs", False))
        self.start()
        self.assertIsNone(self.call("GET", "")[1]["inboxes"][0]["folders"])

    def test_read_only_blocks_every_write_but_not_reading(self):
        self.start(read_only=True)
        for method, path, body in (
            ("POST", "/messages/send", {"to": "a@b.com", "subject": "s", "text": "t"}),
            ("POST", "/messages", {"to": "a@b.com", "subject": "s", "text": "t"}),
            ("POST", "/messages/7/reply", {"text": "x"}),
            ("PATCH", "/messages/7", {"add_labels": ["read"]}),
            ("GET", "/messages/7?mark_read=1", None),
        ):
            code, out = self.call(method, path, body)
            self.assertEqual((code, out["error"]), (403, "read_only"), f"{method} {path}")
        self.assertEqual(self.mail.calls, [])
        self.assertEqual(self.call("GET", "/messages")[0], 200)
        self.assertEqual(self.call("GET", "/messages/7")[0], 200)
        self.assertEqual(self.call("POST", "/messages/7/attachments/fetch", {})[0], 200)


if __name__ == "__main__":
    unittest.main()

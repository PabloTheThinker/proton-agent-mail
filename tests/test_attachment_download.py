"""GET .../attachments/{n}: bytes only after the quarantine scan said clean."""

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from proton_agent_mail.security import FolderScope
from proton_agent_mail.server import AgentHandler

TOKEN = "t" * 40
PAYLOAD = b"%PDF-1.4 hello"


class FakeMail:
    def __init__(self):
        self.calls = []

    def envelopes(self, n=20, folder="INBOX", query=None):
        self.calls.append(("envelopes", folder))
        return []


class FakeAttachments:
    """Stands in for the quarantine: returns whatever scan outcome the test sets."""

    def __init__(self, mail, tmp):
        self.mail, self.tmp, self.outcome = mail, tmp, "clean"

    def fetch_and_scan(self, mid, *, folder="INBOX", indexes=None, trust_known=False):
        self.mail.calls.append(("fetch", mid, folder, tuple(indexes or [])))
        if indexes == [9]:
            return {"attachments": []}
        path = Path(self.tmp) / "clean.bin"
        path.write_bytes(PAYLOAD)
        if self.outcome == "clean":
            item = {"ok": True, "status": "clean", "path": str(path), "sha256": "ab" * 32, "filename": "report.pdf", "backend": "clamdscan", "size": len(PAYLOAD)}
        else:
            item = {"ok": False, "status": self.outcome, "path": None, "sha256": "cd" * 32, "filename": "evil.exe", "backend": "clamdscan",
                    "detail": "nope", "reasons": ["policy"], "size": 9}
        return {"attachments": [item]}


class DownloadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.mail = FakeMail()
        self.att = FakeAttachments(self.mail, self.tmp)
        AgentHandler.token, AgentHandler.mail, AgentHandler.attachments = TOKEN, self.mail, self.att
        AgentHandler.scope, AgentHandler.read_only, AgentHandler.send_as = FolderScope(), False, {}
        srv = ThreadingHTTPServer(("127.0.0.1", 0), AgentHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(lambda: (srv.shutdown(), srv.server_close()))
        self.base = f"http://127.0.0.1:{srv.server_address[1]}/inboxes/default"

    def get(self, path):
        req = urllib.request.Request(self.base + path, headers={"Authorization": f"Bearer {TOKEN}"})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read()

    def test_clean_attachment_is_served_as_inert_bytes_with_its_scan_result(self):
        code, h, body = self.get("/messages/7/attachments/0?folder=Archive")
        self.assertEqual((code, body), (200, PAYLOAD))
        self.assertEqual(h["Content-Type"], "application/octet-stream")
        self.assertEqual(h["X-Content-Type-Options"], "nosniff")
        self.assertEqual(h["Content-Disposition"], 'attachment; filename="report.pdf"')
        self.assertEqual(h["X-Attachment-Scan"], "clean; clamdscan")
        self.assertEqual(h["X-Attachment-Sha256"], "ab" * 32)
        self.assertEqual(self.mail.calls, [("fetch", "7", "Archive", (0,))])

    def test_a_blocked_attachment_is_never_served(self):
        for status, http in (("infected", 422), ("blocked_policy", 422), ("scan_error", 502), ("oversized", 413)):
            self.att.outcome = status
            code, _h, body = self.get("/messages/7/attachments/0")
            self.assertEqual(code, http, status)
            out = json.loads(body)
            self.assertEqual((out["error"], out["status"]), ("attachment_blocked", status))
            self.assertNotIn(PAYLOAD, body)

    def test_unknown_index_is_404(self):
        self.assertEqual(self.get("/messages/7/attachments/9")[0], 404)

    def test_the_folder_scope_applies_before_anything_is_fetched(self):
        AgentHandler.scope = FolderScope.from_env("Jobs")
        self.assertEqual(self.get("/messages/7/attachments/0?folder=Archive")[0], 403)
        self.assertEqual(self.mail.calls, [])
        self.assertEqual(self.get("/messages/7/attachments/0")[0], 200)
        self.assertEqual(self.mail.calls, [("fetch", "7", "Jobs", (0,))])

    def test_a_non_numeric_index_is_not_a_download(self):
        for bad in ("../x", "abc", "1.5", "-1"):
            self.assertNotEqual(self.get(f"/messages/7/attachments/{bad}")[0], 200, bad)
        self.assertEqual(self.mail.calls, [])


if __name__ == "__main__":
    unittest.main()

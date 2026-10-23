import json, os, sys, tempfile, threading, unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

TOK = "test-token-xyz"
CALLS = []
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _r(self):
        n = int(self.headers.get("Content-Length") or 0)
        CALLS.append((self.command, self.path, self.headers.get("Authorization"), self.rfile.read(n) if n else b""))
        if self.headers.get("Authorization") != "Bearer " + TOK:
            self.send_response(401); self.end_headers(); return
        body = json.dumps({"ok": True, "path": self.path}).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    do_GET = do_POST = _r
srv = HTTPServer(("127.0.0.1", 0), H); threading.Thread(target=srv.serve_forever, daemon=True).start()
tmp = tempfile.mkdtemp()
tf = os.path.join(tmp, "tok"); open(tf, "w").write(TOK); os.chmod(tf, 0o600)
os.environ.update(PAM_API_URL=f"http://127.0.0.1:{srv.server_port}", PROTON_AGENT_TOKEN_FILE=tf, PAM_DRAFT_DIR=os.path.join(tmp, "d"))
os.environ.pop("PROTON_AGENT_TOKEN", None)
from proton_agent_mail import mcp_server as server

def call(name, args):
    return server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}})["result"]

class T(unittest.TestCase):
    def setUp(self): CALLS.clear()
    def test_list_tools(self):
        names = {t["name"] for t in server.handle({"id": 1, "method": "tools/list"})["result"]["tools"]}
        self.assertEqual(names, {"list_messages", "read_message", "search", "create_draft", "send_message"})
    def test_list_auth_and_scope(self):
        r = call("list_messages", {"limit": 999}); self.assertFalse(r["isError"])
        m, p, auth, _ = CALLS[0]; self.assertIn("limit=50", p); self.assertIn("folder=INBOX", p); self.assertEqual(auth, "Bearer " + TOK)
    def test_folder_out_of_scope(self):
        r = call("read_message", {"id": "1", "folder": "Archive"}); self.assertTrue(r["isError"]); self.assertEqual(CALLS, [])
    def test_search(self):
        call("search", {"query": "invoice"}); self.assertIn("q=invoice", CALLS[0][1])
    def test_send_requires_confirm(self):
        for c in (None, False, "true", 1):
            a = {"to": "x@y.z", "subject": "s", "text": "t"}
            if c is not None: a["confirm"] = c
            self.assertTrue(call("send_message", a)["isError"])
        self.assertEqual(CALLS, [])
    def test_draft_then_send(self):
        r = call("create_draft", {"to": "x@y.z", "subject": "s", "text": "t"}); self.assertEqual(CALLS, [])
        did = json.loads(r["content"][0]["text"])["draft"]["id"]
        p = server._draft_path(did); self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)
        r = call("send_message", {"draft_id": did, "confirm": True}); self.assertFalse(r["isError"])
        self.assertTrue(CALLS[0][1].endswith("/messages/send")); self.assertEqual(json.loads(CALLS[0][3])["to"], "x@y.z")
        self.assertFalse(os.path.exists(p))
    def test_token_never_in_output(self):
        r = call("list_messages", {}); self.assertNotIn(TOK, json.dumps(r))
    def test_loose_token_perms_refused(self):
        os.chmod(tf, 0o644)
        try: self.assertTrue(call("list_messages", {})["isError"])
        finally: os.chmod(tf, 0o600)
    def test_nonloopback_refused(self):
        with self.assertRaises(SystemExit): server._check_loopback("http://10.0.0.5:18765")
    def test_bad_draft_id(self):
        self.assertTrue(call("send_message", {"draft_id": "../../etc/passwd", "confirm": True})["isError"])
if __name__ == "__main__": unittest.main()

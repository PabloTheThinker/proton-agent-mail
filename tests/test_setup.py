import unittest

import json
import os
import stat
import tempfile
from pathlib import Path
from unittest import mock

from proton_agent_mail.setup import parse_info, port_up, write_bridge_credentials


class SetupParseTests(unittest.TestCase):
    def test_parse_info_table(self):
        blob = """
        Configuration for account user@example.com
        Username: user@example.com
        Password: xK9fakeBridgeSecret
        IMAP: 127.0.0.1:1143
        SMTP: 127.0.0.1:1025
        """
        p = parse_info(blob)
        self.assertEqual(p["username"], "user@example.com")
        self.assertEqual(p["password"], "xK9fakeBridgeSecret")
        self.assertIn("@", p["email"])

    def test_port_loopback_closed_high(self):
        self.assertFalse(port_up(1))


class WriteCredentialsTests(unittest.TestCase):
    def test_bridge_login_is_written_0600_and_readable_by_the_client(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "cfg" / "bridge.json"
            with mock.patch.dict(os.environ, {"PROTON_AGENT_BRIDGE_FILE": str(target)}):
                path = write_bridge_credentials("user@example.com", "user@example.com", "bridge-pass")
                self.assertEqual(path, target)
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
                self.assertEqual(json.loads(target.read_text())["user"], "user@example.com")
                from proton_agent_mail.bridge import load_credentials

                self.assertEqual(load_credentials(), ("user@example.com", "bridge-pass"))


if __name__ == "__main__":
    unittest.main()

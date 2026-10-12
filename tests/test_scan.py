import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from proton_agent_mail.scan import (
    admit_file,
    extension_policy,
    safe_filename,
    ensure_dirs,
)


class ScanPolicyTests(unittest.TestCase):
    def test_safe_filename_strips_paths(self):
        self.assertEqual(safe_filename("../../etc/passwd"), "passwd")
        self.assertEqual(safe_filename("my photo.JPG"), "my_photo.JPG")

    def test_extension_block_exe(self):
        pol, reasons = extension_policy("invoice.pdf.exe")
        self.assertEqual(pol, "block")
        pol2, _ = extension_policy("malware.bat")
        self.assertEqual(pol2, "block")

    def test_extension_allow_images(self):
        self.assertEqual(extension_policy("x.png")[0], "allow")
        self.assertEqual(extension_policy("doc.PDF")[0], "allow")

    def test_admit_clean_with_mocked_av(self):
        with tempfile.TemporaryDirectory() as td:
            os.environ["PROTON_AGENT_QUARANTINE"] = td
            ensure_dirs()
            src = Path(td) / "in.jpg"
            src.write_bytes(b"\xff\xd8\xff\xd9fakejpeg")
            with mock.patch("proton_agent_mail.scan.run_av_scan", return_value=("clean", "mock", "OK")):
                res = admit_file(src, original_name="photo.jpg")
            self.assertTrue(res.ok)
            self.assertEqual(res.status, "clean")
            self.assertTrue(res.path)
            self.assertTrue(Path(str(res.path)).is_file())

    def test_admit_infected(self):
        with tempfile.TemporaryDirectory() as td:
            os.environ["PROTON_AGENT_QUARANTINE"] = td
            ensure_dirs()
            src = Path(td) / "bad.bin"
            src.write_bytes(b"eicar-like")
            with mock.patch(
                "proton_agent_mail.scan.run_av_scan",
                return_value=("infected", "mock", "EICAR FOUND"),
            ):
                res = admit_file(src, original_name="note.txt")
            self.assertFalse(res.ok)
            self.assertEqual(res.status, "infected")
            self.assertIsNone(res.path)
            self.assertTrue(res.quarantine_path and "blocked" in res.quarantine_path)

    def test_admit_blocked_extension(self):
        with tempfile.TemporaryDirectory() as td:
            os.environ["PROTON_AGENT_QUARANTINE"] = td
            ensure_dirs()
            src = Path(td) / "x.bin"
            src.write_bytes(b"MZ")
            res = admit_file(src, original_name="setup.exe")
            self.assertFalse(res.ok)
            self.assertEqual(res.status, "blocked_policy")


if __name__ == "__main__":
    unittest.main()

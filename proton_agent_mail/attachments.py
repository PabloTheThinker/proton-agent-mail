"""List / fetch / send email attachments via the Bridge client + MIME."""

from __future__ import annotations

import base64
import email
import email.policy
import email.utils
import mimetypes
import os
import re
import shutil
import tempfile
import time
from email.message import EmailMessage
from pathlib import Path
from typing import Any

from .bridge import BridgeClient, MailError
from .scan import admit_file, safe_filename
from .security import redact, sanitize_folder, sanitize_message_id

_PART_LINE = re.compile(
    r"""<#part\b([^>]*)>""",
    re.I,
)


def _guess_mime(name: str) -> tuple[str, str]:
    ctype, _ = mimetypes.guess_type(name)
    if not ctype:
        return "application", "octet-stream"
    main, _, sub = ctype.partition("/")
    return main or "application", sub or "octet-stream"


def list_from_read_text(text: str) -> list[dict[str, Any]]:
    """Parse read() part placeholders for attachment names."""
    found: list[dict[str, Any]] = []
    for i, m in enumerate(_PART_LINE.finditer(text or "")):
        attrs = m.group(1) or ""
        if "filename=" not in attrs and "name=" not in attrs:
            # skip pure type=text/html parts without file
            if "type=text/" in attrs.replace(" ", ""):
                continue
        fn = None
        for key in ("name", "filename"):
            mm = re.search(rf"""\b{key}=(?:"([^"]+)"|'([^']+)'|(\S+))""", attrs, re.I)
            if mm:
                fn = next(g for g in mm.groups() if g)
                break
        if not fn:
            continue
        # a placeholder may carry a local path — use the basename
        base = Path(fn).name
        ctype_m = re.search(r"""\btype=([A-Za-z0-9_./+-]+)""", attrs, re.I)
        found.append(
            {
                "index": len(found),
                "filename": safe_filename(base),
                "content_type": ctype_m.group(1) if ctype_m else None,
                "inline": "disposition=inline" in attrs.replace(" ", "").lower(),
            }
        )
    return found


def list_from_eml(eml_path: Path) -> list[dict[str, Any]]:
    raw = eml_path.read_bytes()
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    out: list[dict[str, Any]] = []
    idx = 0
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        disp = (part.get_content_disposition() or "").lower()
        filename = part.get_filename()
        ctype = part.get_content_type()
        # skip pure body text without filename unless attachment disposition
        if not filename and disp != "attachment":
            if ctype in {"text/plain", "text/html"} and disp in {"", "inline", None}:
                continue
        if not filename and disp != "attachment":
            continue
        name = safe_filename(filename or f"part-{idx}.bin")
        payload = part.get_payload(decode=True)
        if not isinstance(payload, (bytes, bytearray)):
            payload = b""
        out.append(
            {
                "index": idx,
                "filename": name,
                "content_type": ctype,
                "size": len(payload),
                "inline": disp == "inline",
            }
        )
        idx += 1
    return out


def extract_eml_parts(eml_path: Path, dest_dir: Path) -> list[dict[str, Any]]:
    dest_dir.mkdir(parents=True, exist_ok=True)
    raw = eml_path.read_bytes()
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    out: list[dict[str, Any]] = []
    idx = 0
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        disp = (part.get_content_disposition() or "").lower()
        filename = part.get_filename()
        ctype = part.get_content_type()
        if not filename and disp != "attachment":
            if ctype in {"text/plain", "text/html"} and disp in {"", "inline", None}:
                continue
        if not filename and disp != "attachment":
            continue
        name = safe_filename(filename or f"part-{idx}.bin")
        payload = part.get_payload(decode=True)
        if not isinstance(payload, (bytes, bytearray)):
            payload = b""
        path = dest_dir / f"{idx:02d}_{name}"
        path.write_bytes(bytes(payload))
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        out.append(
            {
                "index": idx,
                "filename": name,
                "content_type": ctype,
                "size": len(payload),
                "path": str(path),
                "inline": disp == "inline",
            }
        )
        idx += 1
    return out


class AttachmentService:
    def __init__(self, client: BridgeClient | None = None) -> None:
        self.him = client or BridgeClient()

    def list_attachments(self, message_id: str, folder: str = "INBOX") -> list[dict[str, Any]]:
        mid = sanitize_message_id(message_id)
        folder = sanitize_folder(folder)
        # Prefer full eml parse (accurate sizes)
        with tempfile.TemporaryDirectory(prefix="pam-eml-") as td:
            eml = Path(td) / f"{mid}.eml"
            try:
                self.him.export_full(mid, eml, folder=folder)
                items = list_from_eml(eml)
                if items:
                    return items
            except MailError:
                pass
        # Fallback: read text placeholders
        text = self.him.read(mid, folder=folder)
        return list_from_read_text(text)

    def fetch_and_scan(
        self,
        message_id: str,
        *,
        folder: str = "INBOX",
        indexes: list[int] | None = None,
        trust_known: bool = False,
    ) -> dict[str, Any]:
        mid = sanitize_message_id(message_id)
        folder = sanitize_folder(folder)
        with tempfile.TemporaryDirectory(prefix="pam-fetch-") as td:
            tdir = Path(td)
            eml = tdir / f"{mid}.eml"
            parts_dir = tdir / "parts"
            try:
                self.him.export_full(mid, eml, folder=folder)
                parts = extract_eml_parts(eml, parts_dir)
            except MailError:
                # attachment download fallback
                dl = tdir / "dl"
                dl.mkdir()
                self.him.download_attachments(mid, dl, folder=folder)
                parts = []
                for i, p in enumerate(sorted(dl.iterdir())):
                    if p.is_file():
                        parts.append(
                            {
                                "index": i,
                                "filename": safe_filename(p.name),
                                "content_type": None,
                                "size": p.stat().st_size,
                                "path": str(p),
                                "inline": False,
                            }
                        )

            if indexes is not None:
                want = set(indexes)
                parts = [p for p in parts if p["index"] in want]

            results = []
            for p in parts:
                src = Path(p["path"])
                scanned = admit_file(
                    src,
                    original_name=p["filename"],
                    message_id=mid,
                    attachment_index=p["index"],
                    trust_known=trust_known,
                )
                results.append(scanned.to_dict())

            return {
                "message_id": mid,
                "folder": folder,
                "count": len(results),
                "attachments": results,
                "usable": [r for r in results if r.get("ok")],
                "blocked": [r for r in results if not r.get("ok")],
            }

    def send_with_attachments(
        self,
        *,
        from_addr: str,
        to: str,
        subject: str,
        text: str,
        files: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """files: [{filename, path}] or [{filename, content_b64}] — scanned if path outside clean/."""
        if not to or not subject:
            raise MailError("to and subject required")
        msg = EmailMessage()
        msg["From"] = from_addr
        msg["To"] = to
        msg["Subject"] = subject
        msg["Date"] = email.utils.formatdate(localtime=True)
        msg["Message-ID"] = email.utils.make_msgid(domain="localhost")
        msg.set_content(text or "")

        attached_meta = []
        max_b = int(os.environ.get("PROTON_AGENT_ATTACH_MAX_BYTES", str(25 * 1024 * 1024)))
        total = 0
        for item in files or []:
            fname = safe_filename(item.get("filename") or "file.bin")
            path = item.get("path")
            data: bytes | None = None
            if path:
                p = Path(str(path)).expanduser()
                if not p.is_file():
                    raise MailError(f"attachment missing: {fname}")
                # Outbound: still scan local files before send (defense in depth)
                scanned = admit_file(p, original_name=fname, trust_known=True)
                if not scanned.ok or not scanned.path:
                    raise MailError(
                        f"attachment refused ({scanned.status}): {fname} — {scanned.detail}"
                    )
                data = Path(scanned.path).read_bytes()
                attached_meta.append(scanned.to_dict())
            elif item.get("content_b64"):
                try:
                    data = base64.b64decode(item["content_b64"], validate=False)
                except Exception as e:
                    raise MailError(f"bad content_b64 for {fname}") from e
                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    tmp.write(data)
                    tmp_path = Path(tmp.name)
                try:
                    scanned = admit_file(tmp_path, original_name=fname, trust_known=True)
                    if not scanned.ok or not scanned.path:
                        raise MailError(
                            f"attachment refused ({scanned.status}): {fname} — {scanned.detail}"
                        )
                    data = Path(scanned.path).read_bytes()
                    attached_meta.append(scanned.to_dict())
                finally:
                    try:
                        tmp_path.unlink(missing_ok=True)
                    except OSError:
                        pass
            else:
                raise MailError(f"attachment {fname} needs path or content_b64")

            total += len(data)
            if total > max_b:
                raise MailError(f"attachments exceed max {max_b} bytes")
            main, sub = _guess_mime(fname)
            msg.add_attachment(data, maintype=main, subtype=sub, filename=fname)

        raw = msg.as_string()
        self.him.send_raw(raw)
        return {
            "ok": True,
            "message_id": msg["Message-ID"],
            "attachments": attached_meta,
            "bytes": total,
        }

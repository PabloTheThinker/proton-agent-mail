"""Hardening: token compare, version gate, bind policy, log redaction."""

from __future__ import annotations

import hmac
import os
import re
import secrets
import shutil
import subprocess
from pathlib import Path

SECRET_RE = re.compile(
    r"(auth\.raw\s*=\s*).+|"
    r"password['\"]?\s*[:=]\s*['\"]?[^'\"\s]+|"
    r"Bearer\s+[A-Za-z0-9._\-]+|"
    r"(sk_live|sk|pk|gho|ghp|github_pat)_[A-Za-z0-9_]+|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
    re.I,
)


def redact(text: str) -> str:
    return SECRET_RE.sub("[redacted]", text or "")


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_ok(provided: str | None, expected: str) -> bool:
    if not provided or not expected:
        return False
    a = provided.encode()
    b = expected.encode()
    if len(a) != len(b):
        return False
    return hmac.compare_digest(a, b)


def extract_bearer(header: str | None) -> str | None:
    if not header:
        return None
    parts = header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip() or None


def default_bind() -> str:
    raw = os.environ.get("PROTON_AGENT_BIND", "127.0.0.1")
    if raw not in {"127.0.0.1", "::1"} and os.environ.get("PROTON_AGENT_ALLOW_LAN") != "1":
        raise RuntimeError(
            "refusing to bind non-loopback without PROTON_AGENT_ALLOW_LAN=1"
        )
    return raw


def load_token() -> str:
    env = os.environ.get("PROTON_AGENT_TOKEN", "").strip()
    if env:
        return env
    path = os.environ.get("PROTON_AGENT_TOKEN_FILE", "")
    if path:
        p = Path(path)
        if not p.is_file():
            raise RuntimeError("PROTON_AGENT_TOKEN_FILE not found")
        mode = p.stat().st_mode & 0o777
        if mode & 0o077:
            raise RuntimeError("token file must be mode 0600 or tighter (group/other bits set)")
        tok = p.read_text(encoding="utf-8").strip()
        if tok:
            return tok
    raise RuntimeError(
        "set PROTON_AGENT_TOKEN or PROTON_AGENT_TOKEN_FILE — refusing empty token"
    )


_FOLDER_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$")
_ID_OK = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def sanitize_folder(name: str) -> str:
    n = (name or "INBOX").strip() or "INBOX"
    if not _FOLDER_OK.match(n):
        raise RuntimeError("refusing unsafe folder name")
    return n


def sanitize_message_id(mid: str) -> str:
    if not mid or not _ID_OK.match(mid):
        raise RuntimeError("refusing unsafe message id")
    return mid


def assert_bridge_loopback() -> None:
    """Refuse to start if Bridge IMAP/SMTP is on a public interface."""
    try:
        out = subprocess.check_output(
            ["ss", "-ltn"], text=True, timeout=5, stderr=subprocess.DEVNULL
        )
    except (OSError, subprocess.SubprocessError):
        return
    for port in ("1143", "1025"):
        for line in out.splitlines():
            if f":{port} " not in line and not line.rstrip().endswith(f":{port}"):
                continue
            if "127.0.0.1:" + port not in line and "[::1]:" + port not in line:
                raise RuntimeError(
                    f"Proton Bridge port {port} is not loopback-only — "
                    "fix Bridge to 127.0.0.1 before serving"
                )


def assert_config_private(path: Path) -> None:
    if not path.is_file():
        return
    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        raise RuntimeError(f"{path} must be mode 0600 or tighter")


class FolderForbidden(Exception):
    """A folder outside PROTON_AGENT_FOLDERS was requested (HTTP 403, not 404, so logs show the boundary)."""


def _canon_folder(name: str) -> str:
    n = sanitize_folder(name)
    # IMAP folder names are case-sensitive, except INBOX. Everything else is matched exactly.
    return "INBOX" if n.upper() == "INBOX" else n


class FolderScope:
    """Which mailbox folders an agent may touch.

    ``PROTON_AGENT_FOLDERS=Jobs,Receipts`` pins the readable set. Unset means every folder, as before.
    The first entry is the default folder, so a scoped deployment does not need ``?folder=`` on every call
    (and a bare call never silently falls back to INBOX when INBOX is out of scope).
    """

    def __init__(self, folders: tuple[str, ...] = ()) -> None:
        self.folders = folders

    @classmethod
    def from_env(cls, raw: str | None = None) -> "FolderScope":
        raw = os.environ.get("PROTON_AGENT_FOLDERS") if raw is None else raw
        if raw is None or raw.strip() == "":
            return cls()
        seen: list[str] = []
        for part in raw.split(","):
            if not part.strip():
                continue
            name = _canon_folder(part.strip())
            if name not in seen:
                seen.append(name)
        if not seen:
            raise RuntimeError("PROTON_AGENT_FOLDERS is set but names no folder")
        return cls(tuple(seen))

    @property
    def restricted(self) -> bool:
        return bool(self.folders)

    @property
    def default(self) -> str:
        return self.folders[0] if self.folders else "INBOX"

    def resolve(self, requested: str | None) -> str:
        """The folder a request may use: the default when none was asked for, else the (allowed) one asked for."""
        if requested is None or not str(requested).strip():
            return self.default
        name = _canon_folder(str(requested))
        if self.restricted and name not in self.folders:
            raise FolderForbidden(f"folder {name!r} is outside this agent's scope")
        return name

    def advertise(self) -> list[str] | None:
        return list(self.folders) if self.folders else None

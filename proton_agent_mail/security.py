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

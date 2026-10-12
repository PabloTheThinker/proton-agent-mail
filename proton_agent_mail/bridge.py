"""Native Proton Bridge client: IMAP + SMTP on loopback, no subprocess, no third-party mail client.

Same verbs the server already uses (envelopes, read, export_full, download_attachments,
flag, folders, send_raw). Design rules, each learned the hard way:

* One send is one SMTP attempt. smtplib never reconnects on its own, so a refusal cannot
  turn into a retry storm (the earlier Himalaya-based client reconnected ~25x/second on a refusal,
  and Bridge answers a burst of failed sends with ``554 Too many failed send attempts``,
  which then blocks every sender for minutes).
* Bridge's reply is read directly. A lockout (554 "Too many failed send attempts") opens a
  shared circuit breaker; a refused recipient is remembered so it is never retried blindly.
* Loopback only. Bridge's certificate is self-signed, so STARTTLS runs without
  verification, and the client refuses any non-loopback host.
"""

from __future__ import annotations

import email
import imaplib
import json
import os
import re
import smtplib
import ssl
import time
from datetime import timezone
from email import policy
from email.header import decode_header, make_header
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from pathlib import Path
from typing import Any

from .security import redact, sanitize_folder, sanitize_message_id

LOOPBACK = {"127.0.0.1", "::1", "localhost"}
_LOCKOUT = "too many failed send attempts"
_BACKOFF = [900, 1800, 3600, 7200, 14400]  # 15m, 30m, 1h, 2h, 4h cap
_REFUSED_TTL = 24 * 3600


class MailError(RuntimeError):
    """Any Bridge-side failure (kept as a base so callers catch one type)."""


class BridgeLockout(MailError):
    """Bridge is refusing sends, or our breaker is open. Do not retry; wait until retry_at."""

    def __init__(self, retry_at: int, why: str = "") -> None:
        self.retry_at = retry_at
        self.retry_after = max(0, retry_at - int(time.time()))
        super().__init__(f"bridge send lockout; retry in {self.retry_after}s" + (f" ({why})" if why else ""))


class RecipientRefused(MailError):
    """Bridge/Proton refused a recipient. Permanent for now: fix the address, do not retry."""

    def __init__(self, addrs: list[str], reply: str) -> None:
        self.addrs = addrs
        super().__init__(f"recipient refused: {', '.join(addrs)} ({reply[:120]})")


def _state_dir() -> Path:
    return Path(os.environ.get("PROTON_AGENT_STATE") or Path.home() / ".local/state/proton-agent-mail")


class SendBreaker:
    """File-backed circuit breaker for the SMTP side. One file shared by every sender on the host.

    closed -> open on a lockout (or two timeouts in a row) -> half-open once the backoff has
    passed: exactly one probe is allowed through, success closes it, failure re-opens it longer.
    """

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or Path(os.environ.get("PROTON_AGENT_BREAKER") or _state_dir() / "send-breaker.json")

    def load(self) -> dict[str, Any]:
        try:
            return json.loads(self.path.read_text())
        except Exception:
            return {"state": "closed", "fails": 0, "next_probe": 0, "last_error": "", "opened": 0}

    def _save(self, b: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(b, indent=2))
        tmp.replace(self.path)

    def check(self) -> None:
        b = self.load()
        if b["state"] == "closed":
            return
        if time.time() >= b["next_probe"]:
            b.update(state="half-open", next_probe=int(time.time()) + 300)
            self._save(b)
            return
        raise BridgeLockout(int(b["next_probe"]), b.get("last_error", ""))

    def ok(self) -> None:
        self._save({"state": "closed", "fails": 0, "next_probe": 0, "last_error": "", "opened": 0})

    def fail(self, why: str, immediate: bool) -> int:
        b = self.load()
        b["fails"] = b.get("fails", 0) + 1
        if immediate or b["fails"] >= 2:
            wait = _BACKOFF[min(b["fails"] - 1, len(_BACKOFF) - 1)]
            b.update(state="open", next_probe=int(time.time()) + wait, last_error=why[:200], opened=b.get("opened") or int(time.time()))
        self._save(b)
        return int(b["next_probe"])


class RefusedRecipients:
    """Remember recipients Bridge refused, so no sender asks twice (each refusal counts toward a lockout)."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or _state_dir() / "refused-recipients.json"

    def _load(self) -> dict[str, Any]:
        try:
            return json.loads(self.path.read_text())
        except Exception:
            return {}

    def check(self, addrs: list[str]) -> None:
        data, now = self._load(), time.time()
        hit = [a for a in addrs if now - data.get(a.lower(), {}).get("ts", 0) < _REFUSED_TTL]
        if hit:
            raise RecipientRefused(hit, "previously refused by Bridge; not retried (clear with `forget`)")

    def add(self, addrs: list[str], reply: str) -> None:
        data = self._load()
        for a in addrs:
            data[a.lower()] = {"ts": int(time.time()), "reply": reply[:160]}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=2))

    def forget(self, addr: str) -> None:
        data = self._load()
        data.pop(addr.lower(), None)
        self.path.write_text(json.dumps(data, indent=2))


def _read_himalaya_config() -> tuple[str, str] | None:
    """Migration helper: reuse the login already stored for himalaya. Never logged."""
    p = Path.home() / ".config/himalaya/config.toml"
    if not p.is_file():
        return None
    text = p.read_text()
    user = re.search(r'backend\.login\s*=\s*"([^"]+)"', text)
    pw = re.search(r'backend\.auth\.raw\s*=\s*"([^"]+)"', text)
    return (user.group(1), pw.group(1)) if user and pw else None


def load_credentials() -> tuple[str, str]:
    """Bridge username + bridge-specific password. Order: env, 0600 json file, himalaya config."""
    user = os.environ.get("PROTON_AGENT_BRIDGE_USER")
    pw_file = os.environ.get("PROTON_AGENT_BRIDGE_PASS_FILE")
    if user and pw_file and Path(pw_file).is_file():
        return user, Path(pw_file).read_text().strip()
    if user and os.environ.get("PROTON_AGENT_BRIDGE_PASS"):
        return user, os.environ["PROTON_AGENT_BRIDGE_PASS"]
    cfg = Path(os.environ.get("PROTON_AGENT_BRIDGE_FILE") or Path.home() / ".config/proton-agent-mail/bridge.json")
    if cfg.is_file():
        d = json.loads(cfg.read_text())
        return d["user"], d["password"]
    legacy = _read_himalaya_config()
    if legacy:
        return legacy
    raise MailError("no Bridge credentials: set PROTON_AGENT_BRIDGE_FILE (json {user,password}, mode 600)")


def _decode(v: str | None) -> str:
    try:
        return str(make_header(decode_header(v or "")))
    except Exception:
        return v or ""


_FLAG = {"seen": "\\Seen", "answered": "\\Answered", "flagged": "\\Flagged", "deleted": "\\Deleted", "draft": "\\Draft"}


class BridgeClient:
    def __init__(self, host: str | None = None, imap_port: int | None = None, smtp_port: int | None = None) -> None:
        self.host = host or os.environ.get("PROTON_BRIDGE_HOST", "127.0.0.1")
        if self.host not in LOOPBACK:
            raise MailError(f"refusing non-loopback Bridge host {self.host!r}")
        self.imap_port = imap_port or int(os.environ.get("PROTON_BRIDGE_IMAP_PORT", "1143"))
        self.smtp_port = smtp_port or int(os.environ.get("PROTON_BRIDGE_SMTP_PORT", "1025"))
        self.version = (1, 0, 0)  # health payload compatibility
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE  # self-signed Bridge cert, loopback only

    # ---- IMAP -------------------------------------------------------------
    def _imap(self, folder: str = "INBOX", readonly: bool = True) -> imaplib.IMAP4:
        user, pw = load_credentials()
        try:
            c = imaplib.IMAP4(self.host, self.imap_port, timeout=20)
            c.starttls(ssl_context=self._ctx)
            c.login(user, pw)
            typ, _ = c.select(f'"{sanitize_folder(folder)}"', readonly=readonly)
            if typ != "OK":
                raise MailError(f"cannot open folder {folder}")
            return c
        except (imaplib.IMAP4.error, OSError) as e:
            raise MailError(redact(f"imap: {e}")[:200]) from e

    @staticmethod
    def _uid(mid: str) -> str:
        m = sanitize_message_id(mid)
        if not m.isdigit():
            raise MailError("message id must be a numeric UID")
        return m

    def envelopes(self, n: int = 20, folder: str = "INBOX", query: list[str] | None = None) -> list[dict[str, Any]]:
        c = self._imap(folder)
        try:
            crit = ["TEXT", '"' + " ".join(query).replace('"', "") + '"'] if query else ["ALL"]
            typ, data = c.uid("SEARCH", *crit)
            uids = (data[0] or b"").split()[-max(1, n):]
            if typ != "OK" or not uids:
                return []
            typ, rows = c.uid(
                "FETCH", b",".join(uids).decode(),
                "(UID FLAGS BODYSTRUCTURE BODY.PEEK[HEADER.FIELDS (FROM TO CC DELIVERED-TO X-ORIGINAL-TO SUBJECT DATE)])",
            )
            out: list[dict[str, Any]] = []
            # Bridge answers: (meta, header-literal) then a trailing b" UID n)". Pair them up.
            pending: tuple[bytes, bytes] | None = None
            for item in list(rows) + [b""]:
                if isinstance(item, tuple):
                    pending = (item[0], item[1])
                    tail = item[0]
                else:
                    tail = item if isinstance(item, bytes) else b""
                if pending is None:
                    continue
                meta = pending[0].decode(errors="replace")
                uid = re.search(r"UID (\d+)", tail.decode(errors="replace")) or re.search(r"UID (\d+)", meta)
                if not uid and isinstance(item, tuple):
                    continue  # wait for the trailing UID bytes
                if not uid:
                    pending = None
                    continue
                flags = re.search(r"FLAGS \(([^)]*)\)", meta)
                hdr = email.message_from_bytes(pending[1], policy=policy.default)
                name, addr = parseaddr(_decode(str(hdr.get("From", ""))))
                to_name, to_addr = parseaddr(_decode(str(hdr.get("To", ""))))
                date = ""
                try:
                    date = parsedate_to_datetime(str(hdr.get("Date"))).strftime("%Y-%m-%d %H:%M%z")
                    date = date[:-2] + ":" + date[-2:] if re.search(r"[+-]\d{4}$", date) else date
                except Exception:
                    pass
                recips = sorted({a.lower() for k in ("To", "Cc", "Delivered-To", "X-Original-To")
                                 for _, a in getaddresses([str(hdr.get(k, ""))]) if a})
                out.append({
                    "id": uid.group(1),
                    "recipients": recips,
                    "flags": [f.lstrip("\\") for f in (flags.group(1).split() if flags else [])],
                    "subject": _decode(str(hdr.get("Subject", ""))),
                    "from": {"name": name or None, "addr": addr},
                    "to": {"name": to_name or None, "addr": to_addr},
                    "date": date,
                    "has_attachment": bool(re.search(r'"attachment"|"name"|"filename"', meta, re.I)),
                })
                pending = None
            out.sort(key=lambda r: int(r["id"]), reverse=True)  # newest first
            return out
        except imaplib.IMAP4.error as e:
            raise MailError(redact(f"imap: {e}")[:200]) from e
        finally:
            _logout(c)

    def _fetch_raw(self, mid: str, folder: str, peek: bool) -> bytes:
        uid = self._uid(mid)
        c = self._imap(folder, readonly=peek)
        try:
            typ, rows = c.uid("FETCH", uid, "(BODY.PEEK[])" if peek else "(BODY[])")
            for item in rows or []:
                if isinstance(item, tuple):
                    return item[1]
            raise MailError(f"message {uid} not found in {folder}")
        except imaplib.IMAP4.error as e:
            raise MailError(redact(f"imap: {e}")[:200]) from e
        finally:
            _logout(c)

    def read(self, message_id: str, preview: bool = False, folder: str = "INBOX") -> str:
        """Plain text with headers on top. preview=True leaves it unread (AgentMail semantics)."""
        raw = self._fetch_raw(message_id, folder, peek=True)
        if not preview:
            self.flag(message_id, ["seen"], add=True, folder=folder)
        msg = email.message_from_bytes(raw, policy=policy.default)
        head = "".join(f"{k}: {_decode(str(msg.get(k, '')))}\n" for k in ("From", "To", "Cc", "Subject", "Date") if msg.get(k))
        body = msg.get_body(preferencelist=("plain", "html"))
        text = body.get_content() if body else ""
        if body is not None and body.get_content_type() == "text/html":
            text = re.sub(r"<[^>]+>", " ", re.sub(r"(?is)<(script|style).*?</\1>", " ", text))
            text = re.sub(r"[ \t]+", " ", text)
        notes = "".join(f'\n<#part filename="{Path(p.get_filename() or "attachment").name}" type="{p.get_content_type()}"><#/part>'
                        for p in msg.iter_attachments())
        return f"{head}\n{text.strip()}{notes}\n"

    def export_full(self, message_id: str, dest_eml: Path, folder: str = "INBOX") -> Path:
        dest_eml = Path(dest_eml)
        dest_eml.parent.mkdir(parents=True, exist_ok=True)
        dest_eml.write_bytes(self._fetch_raw(message_id, folder, peek=True))
        return dest_eml

    def download_attachments(self, message_id: str, downloads_dir: Path, folder: str = "INBOX") -> Path:
        downloads_dir = Path(downloads_dir)
        downloads_dir.mkdir(parents=True, exist_ok=True)
        msg = email.message_from_bytes(self._fetch_raw(message_id, folder, peek=True), policy=policy.default)
        for i, part in enumerate(msg.iter_attachments()):
            name = re.sub(r"[^\w.\- ]", "_", Path(part.get_filename() or f"attachment-{i}").name)[:120]
            (downloads_dir / name).write_bytes(bytes(part.get_payload(decode=True) or b""))
        return downloads_dir

    def flag(self, message_id: str, flags: list[str], add: bool = True, folder: str = "INBOX") -> None:
        uid = self._uid(message_id)
        names = [_FLAG[f.lstrip("\\").lower()] for f in flags if f.lstrip("\\").lower() in _FLAG]
        if not names:
            return
        c = self._imap(folder, readonly=False)
        try:
            c.uid("STORE", uid, "+FLAGS.SILENT" if add else "-FLAGS.SILENT", "(" + " ".join(names) + ")")
        except imaplib.IMAP4.error as e:
            raise MailError(redact(f"imap: {e}")[:200]) from e
        finally:
            _logout(c)

    def headers(self, message_id: str, folder: str = "INBOX") -> dict[str, Any]:
        """Real RFC822 headers of one message: what a correct reply needs (Message-ID, References, Reply-To, recipients)."""
        uid = self._uid(message_id)
        c = self._imap(folder)
        try:
            typ, rows = c.uid("FETCH", uid, "(BODY.PEEK[HEADER])")
            raw = next((r[1] for r in rows or [] if isinstance(r, tuple)), None)
            if raw is None:
                raise MailError(f"message {uid} not found in {folder}")
        except imaplib.IMAP4.error as e:
            raise MailError(redact(f"imap: {e}")[:200]) from e
        finally:
            _logout(c)
        m = email.message_from_bytes(raw, policy=policy.default)

        def many(*keys: str) -> list[str]:
            return sorted({a.lower() for k in keys for _, a in getaddresses([str(m.get(k, ""))]) if a})

        return {
            "message_id": str(m.get("Message-ID", "")).strip(),
            "references": str(m.get("References", "")).strip(),
            "subject": _decode(str(m.get("Subject", ""))),
            "from": parseaddr(str(m.get("From", "")))[1].lower(),
            "reply_to": parseaddr(str(m.get("Reply-To", "")))[1].lower(),
            "to": many("To"),
            "recipients": many("To", "Cc", "Delivered-To", "X-Original-To"),
        }

    def trash(self, message_ids: list[str], folder: str = "INBOX") -> int:
        """Move explicit message ids to Trash (copy first, then remove). Recoverable; no wildcards."""
        uids = [self._uid(m) for m in message_ids]
        if not uids:
            return 0
        s = ",".join(uids)
        c = self._imap(folder, readonly=False)
        try:
            typ, _ = c.uid("COPY", s, '"Trash"')
            if typ != "OK":
                raise MailError("could not copy to Trash; nothing was removed")
            c.uid("STORE", s, "+FLAGS.SILENT", "(\\Deleted)")
            c.expunge()
        except imaplib.IMAP4.error as e:
            raise MailError(redact(f"imap: {e}")[:200]) from e
        finally:
            _logout(c)
        return len(uids)

    def folders(self) -> str:
        c = self._imap()
        try:
            typ, rows = c.list()
            return "\n".join(r.decode(errors="replace") for r in rows or [] if isinstance(r, bytes))
        finally:
            _logout(c)

    # ---- SMTP -------------------------------------------------------------
    def send_raw(self, rfc822: str | bytes) -> None:
        """Send one RFC822 message. Exactly one attempt; the reply decides what happens next."""
        breaker, refused = SendBreaker(), RefusedRecipients()
        breaker.check()  # open breaker: raise without touching Bridge at all
        data = rfc822.encode() if isinstance(rfc822, str) else rfc822
        msg = email.message_from_bytes(data, policy=policy.default)
        sender = parseaddr(str(msg.get("From", "")))[1]
        rcpts = [a for _, a in getaddresses([str(v) for k in ("To", "Cc", "Bcc") for v in msg.get_all(k, [])]) if a]
        if not sender or not rcpts:
            raise MailError("message needs From and at least one recipient")
        refused.check(rcpts)
        del msg["Bcc"]
        wire = msg.as_bytes(policy=policy.SMTP)
        user, pw = load_credentials()
        try:
            with smtplib.SMTP(self.host, self.smtp_port, timeout=40) as s:
                s.ehlo()
                s.starttls(context=self._ctx)
                s.ehlo()
                s.login(user, pw)
                s.sendmail(sender, rcpts, wire)
        except smtplib.SMTPRecipientsRefused as e:
            bad = list(e.recipients)
            reply = " ".join(f"{c} {m.decode(errors='replace') if isinstance(m, bytes) else m}" for c, m in e.recipients.values())
            if _LOCKOUT in reply.lower():
                raise BridgeLockout(breaker.fail("554 too many failed send attempts", True), "554 from Bridge") from e
            refused.add(bad, reply)
            raise RecipientRefused(bad, reply) from e
        except smtplib.SMTPResponseException as e:
            text = f"{e.smtp_code} {e.smtp_error.decode(errors='replace') if isinstance(e.smtp_error, bytes) else e.smtp_error}"
            if _LOCKOUT in text.lower():
                raise BridgeLockout(breaker.fail("554 too many failed send attempts", True), "554 from Bridge") from e
            raise MailError(redact(f"smtp: {text}")[:200]) from e
        except (smtplib.SMTPException, OSError, TimeoutError) as e:
            breaker.fail(f"smtp: {type(e).__name__}", False)
            raise MailError(redact(f"smtp: {e}")[:200]) from e
        breaker.ok()


def _logout(c: imaplib.IMAP4) -> None:
    try:
        c.logout()
    except Exception:
        pass

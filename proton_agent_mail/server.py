"""AgentMail-shaped HTTP API over Proton Bridge (stdlib only).

Compatible surface (hosted AgentMail verbs on loopback):
  GET  /health
  GET  /v0/inboxes | /inboxes
  GET  /v0/inboxes/{id}/messages | /inboxes/{id}/messages
  GET  /v0/inboxes/{id}/messages/{mid}
  POST /v0/inboxes/{id}/messages/send | /messages/send | POST .../messages
  POST /v0/inboxes/{id}/messages/{mid}/reply
  GET  /v0/inboxes/{id}/threads
  GET  /v0/inboxes/{id}/events?after=&wait=   (message.received long-poll)
  PATCH /v0/inboxes/{id}/messages/{mid}      (add_labels/remove_labels)
  webhook + local hook on new mail (see events.py)
  attachments + quarantine (house extensions)
"""

from __future__ import annotations

import email.message
import email.utils
import json
import os
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from .attachments import AttachmentService
from .events import EventBus, from_env as events_from_env
from .bridge import BridgeClient, BridgeLockout, MailError, RecipientRefused, SendBreaker
from .scan import default_quarantine_root, ensure_dirs
from .security import (
    FolderForbidden,
    FolderScope,
    assert_bridge_loopback,
    assert_config_private,
    default_bind,
    extract_bearer,
    load_token,
    redact,
    sanitize_message_id,
    token_ok,
)

API_VERSION = "0.6.0"

LABEL_TO_FLAG = {"read": ("seen", True), "unread": ("seen", False), "replied": ("answered", True), "starred": ("flagged", True), "flagged": ("flagged", True)}


def build_message(from_header: str, to: str, subject: str, text: str, cc: str = "",
                  in_reply_to: str = "", references: str = "") -> email.message.EmailMessage:
    """Plain-text message with correctly encoded headers (RFC 2047), so a display name or subject with
    non-ASCII characters (an em dash, an accent) is not sent as raw bytes, which Bridge rejects."""
    msg = email.message.EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = from_header, to, subject
    if cc:
        msg["Cc"] = cc
    msg["Date"] = email.utils.formatdate(localtime=True)
    domain = (email.utils.parseaddr(from_header)[1].rsplit("@", 1) + ["localhost"])[1] if "@" in from_header else "localhost"
    msg["Message-ID"] = email.utils.make_msgid(domain=domain)
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
        msg["References"] = references or in_reply_to
    msg.set_content(text)
    return msg


def parse_send_as(raw: str) -> dict[str, str]:
    """PROTON_AGENT_SEND_AS: 'Name <a@x>;Name <b@x>' -> {address: 'Name <a@x>'}. First entry is the default."""
    out: dict[str, str] = {}
    for part in (raw or "").split(";"):
        name, addr = email.utils.parseaddr(part.strip())
        if addr:
            out[addr.lower()] = f"{name} <{addr}>" if name else addr
    return out


def _json(handler: BaseHTTPRequestHandler, code: int, payload: Any, headers: dict[str, str] | None = None) -> None:
    body = json.dumps(payload).encode()
    handler.send_response(code)
    for hk, hv in (headers or {}).items():
        handler.send_header(hk, hv)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("X-Proton-Agent-Mail", API_VERSION)
    handler.end_headers()
    handler.wfile.write(body)


def _bytes(handler: BaseHTTPRequestHandler, data: bytes, filename: str, meta: dict[str, str]) -> None:
    """Serve attachment bytes. The content type is always octet-stream: the declared type came from the sender."""
    handler.send_response(200)
    handler.send_header("Content-Type", "application/octet-stream")
    handler.send_header("Content-Length", str(len(data)))
    handler.send_header("Content-Disposition", f'attachment; filename="{filename}"')  # filename is safe_filename()'d
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("X-Proton-Agent-Mail", API_VERSION)
    for k, v in meta.items():
        handler.send_header(k, v)
    handler.end_headers()
    handler.wfile.write(data)


# scan status -> HTTP status for a refused attachment
_REFUSED_STATUS = {"oversized": 413, "infected": 422, "blocked_policy": 422, "scan_error": 502}


def _norm_path(path: str) -> str:
    """Strip optional /v0|/v1 AgentMail-style prefix; collapse //. """
    p = path or "/"
    if p.startswith("/v0/"):
        p = p[3:]
    elif p.startswith("/v1/"):
        p = p[3:]
    elif p in {"/v0", "/v1"}:
        p = "/"
    while "//" in p:
        p = p.replace("//", "/")
    if len(p) > 1 and p.endswith("/"):
        p = p[:-1]
    return p or "/"


def _first_addr(to: Any) -> str:
    if isinstance(to, list):
        if not to:
            return ""
        to = to[0]
    if isinstance(to, dict):
        return str(to.get("email") or to.get("addr") or to.get("address") or "")
    return str(to or "").strip()


def _normalize_envelopes(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Shape closer to AgentMail message list rows."""
    out: list[dict[str, Any]] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        fr = it.get("from")
        if isinstance(fr, dict):
            from_email = fr.get("addr") or fr.get("email") or ""
            from_name = fr.get("name") or ""
        else:
            from_email, from_name = str(fr or ""), ""
        flags = it.get("flags") or []
        seen = any(str(f).lstrip("\\").lower() == "seen" for f in flags)
        row = dict(it)
        row.setdefault("message_id", it.get("id"))
        row.setdefault("from_email", from_email)
        row.setdefault("from_name", from_name)
        row.setdefault("unread", not seen)
        row.setdefault("has_attachments", bool(it.get("has_attachment")))
        out.append(row)
    return out


class AgentHandler(BaseHTTPRequestHandler):
    server_version = f"proton-agent-mail/{API_VERSION}"
    token = ""
    mail: BridgeClient
    attachments: AttachmentService
    events: EventBus
    inbox_id = "default"
    from_addr = "agent@localhost"
    send_as: dict[str, str] = {}
    scope: FolderScope = FolderScope()
    read_only: bool = False

    def log_message(self, fmt: str, *args: Any) -> None:
        msg = redact(fmt % args)
        sys_stderr = __import__("sys").stderr
        print(f"{self.address_string()} {msg}", file=sys_stderr)

    def _auth(self) -> bool:
        got = extract_bearer(self.headers.get("Authorization"))
        if token_ok(got, self.token):
            return True
        _json(self, 401, {"error": "unauthorized"})
        return False

    def _read_json(self, max_bytes: int) -> tuple[dict[str, Any] | None, str | None]:
        length = int(self.headers.get("Content-Length") or 0)
        if length > max_bytes:
            return None, "payload too large"
        raw = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(raw.decode() or "{}")
        except json.JSONDecodeError:
            return None, "invalid json"
        if not isinstance(data, dict):
            return None, "invalid json"
        return data, None

    def _folder(self, requested: str | None) -> str:
        return self.scope.resolve(requested)

    def _deny_read_only(self, what: str) -> bool:
        if self.read_only:
            _json(self, 403, {"error": "read_only", "message": f"{what} is disabled: this service is read-only"})
            return True
        return False

    def _folder_denied(self, e: FolderForbidden) -> None:
        _json(self, 403, {"error": "folder_forbidden", "message": str(e), "allowed_folders": self.scope.advertise()})

    def _inbox_payload(self) -> dict[str, Any]:
        return {
            "inboxes": [
                {
                    "email": self.from_addr,
                    "display_name": "ILO Proton",
                    "inbox_id": self.inbox_id,
                    "provider": "proton-bridge",
                    "agentmail_compatible": True,
                    "folders": self.scope.advertise(),  # None = every folder
                    "default_folder": self.scope.default,
                    "read_only": self.read_only,
                }
            ]
        }

    def _resolve_from(self, requested: str, original_recipients: list[str] | None = None) -> str:
        """From header for one message. Only addresses in PROTON_AGENT_SEND_AS may ever be used.

        requested: explicit `from` (must be allowed). Otherwise, when answering a message, the address
        it was written to (if allowed, preferring a non-default one); otherwise the default sender.
        """
        allowed = self.send_as
        if not allowed:
            if requested:
                raise ValueError("from is not configured on this service (set PROTON_AGENT_SEND_AS)")
            return self.from_addr
        default = next(iter(allowed.values()))
        if requested:
            addr = email.utils.parseaddr(requested)[1].lower()
            if addr not in allowed:
                raise ValueError(f"from {addr or requested!r} is not an allowed sender")
            return allowed[addr]
        if original_recipients:
            hits = [a for a in original_recipients if a.lower() in allowed]
            others = [a for a in hits if allowed[a.lower()] != default]
            if others or hits:
                return allowed[(others or hits)[0].lower()]
        return default

    def _send_message(self, data: dict[str, Any], original_recipients: list[str] | None = None) -> dict[str, Any]:
        from_header = self._resolve_from(str(data.get("from") or ""), original_recipients)
        to = _first_addr(data.get("to"))
        cc = data.get("cc")
        if isinstance(cc, list):
            cc_s = ", ".join(_first_addr(x) for x in cc if _first_addr(x))
        else:
            cc_s = _first_addr(cc) if cc else ""
        subject = str(data.get("subject") or "")
        text = str(data.get("text") or data.get("body") or "")
        files = data.get("attachments") or data.get("files") or []
        in_reply_to = data.get("in_reply_to") or data.get("reply_to_message_id") or ""
        if not to or not subject:
            raise ValueError("to and subject required")

        if files:
            if not isinstance(files, list):
                raise ValueError("attachments must be a list")
            # Attachment path does not yet carry In-Reply-To; plain path does.
            result = self.attachments.send_with_attachments(
                from_addr=from_header,
                to=str(to),
                subject=str(subject),
                text=str(text),
                files=files,
            )
            return result

        msg = build_message(from_header, str(to), subject, text, cc_s, in_reply_to, data.get("references") or "")
        mid = str(msg["Message-ID"])
        self.mail.send_raw(msg.as_bytes())
        return {
            "ok": True,
            "message_id": mid,
            "from": from_header,
            "to": to,
            "subject": subject,
            "in_reply_to": in_reply_to or None,
        }

    def do_GET(self) -> None:  # noqa: N802
        path = _norm_path(urlparse(self.path).path)
        if path == "/health":
            qroot = str(default_quarantine_root())
            _json(
                self,
                200,
                {
                    "ok": True,
                    "backend": "bridge-native (imap+smtp)",
                    "send_breaker": SendBreaker().load()["state"],
                    "inbox": self.inbox_id,
                    "attachments": True,
                    "folder_scope": self.scope.advertise(),
                    "read_only": self.read_only,
                    "quarantine": qroot,
                    "version": API_VERSION,
                    "agentmail_compatible": True,
                    "events": self.events.status(),
                    "paths": {
                        "list": f"/inboxes/{self.inbox_id}/messages",
                        "send": f"/inboxes/{self.inbox_id}/messages/send",
                        "send_alias": f"/inboxes/{self.inbox_id}/messages",
                        "v0_prefix": True,
                        "events": f"/inboxes/{self.inbox_id}/events?after=<event_id>&wait=<secs>",
                        "labels": f"PATCH /inboxes/{self.inbox_id}/messages/<id> {{add_labels, remove_labels}}",
                    },
                },
            )
            return
        if not self._auth():
            return
        qs = parse_qs(urlparse(self.path).query)
        try:
            if path in {"/inboxes", f"/inboxes/{self.inbox_id}", "/"}:
                _json(self, 200, self._inbox_payload())
                return
            if path == f"/inboxes/{self.inbox_id}/events":
                after = (qs.get("after") or [""])[0].strip() or None
                wait = float((qs.get("wait") or ["0"])[0] or 0)
                limit = max(1, min(int((qs.get("limit") or ["50"])[0]), 200))
                evs = self.events.since(after, wait=max(0.0, min(wait, 60.0)), limit=limit)
                _json(self, 200, {"count": len(evs), "events": evs, "inbox_id": self.inbox_id,
                                  "next_after": evs[-1]["event_id"] if evs else after})
                return
            if path == f"/inboxes/{self.inbox_id}/messages":
                n = int((qs.get("limit") or qs.get("page_size") or ["20"])[0])
                n = max(1, min(n, 50))
                folder = self._folder((qs.get("folder") or [""])[0])
                items = _normalize_envelopes(self.mail.envelopes(n=n, folder=folder))
                # optional filters (agent-side convenience)
                unread_only = (qs.get("unread") or [""])[0].lower() in {"1", "true", "yes"}
                q = (qs.get("q") or qs.get("query") or [""])[0].strip().lower()
                if unread_only:
                    items = [i for i in items if i.get("unread")]
                if q:
                    items = [
                        i
                        for i in items
                        if q in (i.get("subject") or "").lower()
                        or q in (i.get("from_email") or "").lower()
                        or q in (i.get("from_name") or "").lower()
                    ]
                _json(
                    self,
                    200,
                    {
                        "count": len(items),
                        "messages": items,
                        "inbox_id": self.inbox_id,
                    },
                )
                return
            # /messages/{id}/attachments
            prefix_att = f"/inboxes/{self.inbox_id}/messages/"
            if path.startswith(prefix_att) and path.endswith("/attachments"):
                mid = path[len(prefix_att) : -len("/attachments")]
                mid = mid.strip("/")
                folder = self._folder((qs.get("folder") or [""])[0])
                items = self.attachments.list_attachments(mid, folder=folder)
                _json(
                    self,
                    200,
                    {"message_id": mid, "folder": folder, "count": len(items), "attachments": items},
                )
                return
            m_att = re.fullmatch(r"(?P<mid>[^/]+)/attachments/(?P<n>\d{1,4})", path[len(prefix_att) :]) if path.startswith(prefix_att) else None
            if m_att:
                # Bytes of ONE attachment, only after it passed the quarantine scan. The agent never needs
                # filesystem access, and a blocked file is never served.
                mid = sanitize_message_id(m_att["mid"])
                folder = self._folder((qs.get("folder") or [""])[0])
                result = self.attachments.fetch_and_scan(mid, folder=folder, indexes=[int(m_att["n"])])
                if not result["attachments"]:
                    _json(self, 404, {"error": "no such attachment", "message_id": mid, "index": int(m_att["n"])})
                    return
                item = result["attachments"][0]
                if not item.get("ok") or not item.get("path"):
                    _json(self, _REFUSED_STATUS.get(item.get("status"), 422),
                          {"error": "attachment_blocked", "status": item.get("status"), "detail": item.get("detail"),
                           "filename": item.get("filename"), "reasons": item.get("reasons", [])})
                    return
                _bytes(self, Path(item["path"]).read_bytes(), item["filename"],
                       {"X-Attachment-Sha256": str(item.get("sha256")), "X-Attachment-Scan": f"{item.get('status')}; {item.get('backend')}"})
                return
            if path.startswith(prefix_att):
                mid = path[len(prefix_att) :]
                if mid.endswith("/reply"):
                    _json(self, 405, {"error": "use POST for reply"})
                    return
                mid = mid.strip("/")
                # reject nested junk
                if "/" in mid or mid in {"attachments", "send", "reply"}:
                    _json(self, 404, {"error": "not found"})
                    return
                # AgentMail semantics: GET does not change read state unless mark_read=1
                mark = (qs.get("mark_read") or [""])[0].lower() in {"1", "true", "yes"}
                if mark and self._deny_read_only("mark_read"):
                    return
                folder = self._folder((qs.get("folder") or [""])[0])
                text = self.mail.read(sanitize_message_id(mid), preview=not mark, folder=folder)
                _json(
                    self,
                    200,
                    {
                        "message_id": mid,
                        "folder": folder,
                        "marked_read": mark,
                        "inbox_id": self.inbox_id,
                        "text": text,
                        "text_preview": "\n".join(text.splitlines()[:24]),
                    },
                )
                return
            if path == f"/inboxes/{self.inbox_id}/threads":
                n = int((qs.get("limit") or ["20"])[0])
                n = max(1, min(n, 50))
                folder = self._folder((qs.get("folder") or [""])[0])
                items = _normalize_envelopes(self.mail.envelopes(n=n, folder=folder))
                _json(
                    self,
                    200,
                    {
                        "count": len(items),
                        "threads": [
                            {
                                "thread_id": i.get("id"),
                                "message_id": i.get("id"),
                                "subject": i.get("subject"),
                                "from": i.get("from"),
                                "from_email": i.get("from_email"),
                                "unread": i.get("unread"),
                                "snippet": (i.get("subject") or "")[:120],
                            }
                            for i in items
                        ],
                        "inbox_id": self.inbox_id,
                    },
                )
                return
            if path == "/quarantine/status":
                d = ensure_dirs()
                _json(
                    self,
                    200,
                    {
                        "root": str(d["root"]),
                        "incoming": str(d["incoming"]),
                        "clean": str(d["clean"]),
                        "blocked": str(d["blocked"]),
                        "scan": os.environ.get("PROTON_AGENT_SCAN", "auto"),
                    },
                )
                return
        except FolderForbidden as e:
            self._folder_denied(e)
            return
        except BridgeLockout as e:
            _json(self, 503, {"error": "bridge_lockout", "message": str(e), "retry_after": e.retry_after}, {"Retry-After": str(e.retry_after)})
        except RecipientRefused as e:
            _json(self, 422, {"error": "recipient_refused", "message": str(e), "recipients": e.addrs})
        except MailError as e:
            _json(self, 502, {"error": str(e)})
            return
        except RuntimeError as e:
            _json(self, 400, {"error": str(e)})
            return
        except ValueError as e:
            _json(self, 400, {"error": str(e)})
            return
        _json(self, 404, {"error": "not found", "path": path})

    def do_POST(self) -> None:  # noqa: N802
        if not self._auth():
            return
        path = _norm_path(urlparse(self.path).path)
        # send may include base64 — allow up to ~20MB JSON
        max_body = 22 * 1024 * 1024
        data, err = self._read_json(max_body)
        if err:
            _json(self, 413 if "large" in err else 400, {"error": err})
            return
        assert data is not None

        try:
            prefix = f"/inboxes/{self.inbox_id}/messages/"
            if path.endswith("/attachments/fetch") and path.startswith(prefix):
                mid = path[len(prefix) : -len("/attachments/fetch")].strip("/")
                folder = self._folder(data.get("folder"))
                indexes = data.get("indexes")
                if indexes is not None and not isinstance(indexes, list):
                    _json(self, 400, {"error": "indexes must be a list of ints"})
                    return
                if isinstance(indexes, list):
                    indexes = [int(x) for x in indexes]
                trust = bool(data.get("trust_known"))
                result = self.attachments.fetch_and_scan(
                    mid, folder=folder, indexes=indexes, trust_known=trust
                )
                _json(self, 200, result)
                return

            # AgentMail-style reply
            if path.startswith(prefix) and path.endswith("/reply"):
                if self._deny_read_only("reply"):
                    return
                mid = path[len(prefix) : -len("/reply")].strip("/")
                folder = self._folder(data.get("folder"))
                text = str(data.get("text") or data.get("body") or "")
                # real headers of the original: who it was written to, its Message-ID, its thread
                oh = self.mail.headers(sanitize_message_id(mid), folder=folder)
                subj = str(data.get("subject") or "")
                if not subj:
                    base = oh["subject"] or "your message"
                    subj = base if base.lower().startswith("re:") else f"Re: {base}"
                to = _first_addr(data.get("to")) or oh["reply_to"] or oh["from"]
                if not to:
                    _json(self, 400, {"error": "could not resolve reply to; pass to="})
                    return
                msgid = oh["message_id"]
                payload = {
                    "to": to,
                    "from": data.get("from") or "",
                    "subject": subj,
                    "text": text,
                    "in_reply_to": msgid or mid,
                    "references": (f"{oh['references']} {msgid}".strip() if msgid else ""),
                    "attachments": data.get("attachments") or [],
                }
                result = self._send_message(payload, original_recipients=oh["recipients"])
                result["replied_to"] = mid
                try:  # AgentMail parity: replied thread is labelled
                    self.mail.flag(mid, ["answered", "seen"], add=True, folder=folder)
                except MailError:
                    pass
                _json(self, 200, result)
                return

            # Send paths: .../messages/send  OR  POST .../messages  (AgentMail create/send)
            send_paths = {
                f"/inboxes/{self.inbox_id}/messages/send",
                f"/inboxes/{self.inbox_id}/messages",
            }
            if path not in send_paths:
                _json(self, 404, {"error": "not found", "path": path})
                return
            if self._deny_read_only("send"):
                return

            result = self._send_message(data)
            _json(self, 200, result)
        except FolderForbidden as e:
            self._folder_denied(e)
        except BridgeLockout as e:
            _json(self, 503, {"error": "bridge_lockout", "message": str(e), "retry_after": e.retry_after}, {"Retry-After": str(e.retry_after)})
        except RecipientRefused as e:
            _json(self, 422, {"error": "recipient_refused", "message": str(e), "recipients": e.addrs})
        except MailError as e:
            _json(self, 502, {"error": str(e)})
        except RuntimeError as e:
            _json(self, 400, {"error": str(e)})
        except ValueError as e:
            _json(self, 400, {"error": str(e)})


    def do_PATCH(self) -> None:  # noqa: N802
        """AgentMail update-message: {add_labels:[...], remove_labels:[...]}.

        Labels map to IMAP flags: read/unread → seen, replied → answered,
        starred|flagged → flagged. Unknown labels are ignored (reported back).
        """
        if not self._auth():
            return
        if self._deny_read_only("label changes"):
            return
        path = _norm_path(urlparse(self.path).path)
        prefix = f"/inboxes/{self.inbox_id}/messages/"
        if not path.startswith(prefix):
            _json(self, 404, {"error": "not found", "path": path})
            return
        mid = path[len(prefix):].strip("/")
        if not mid or "/" in mid:
            _json(self, 404, {"error": "not found"})
            return
        data, err = self._read_json(64 * 1024)
        if err:
            _json(self, 400, {"error": err})
            return
        assert data is not None
        applied, ignored = [], []
        try:
            mid = sanitize_message_id(mid)
            folder = self._folder(data.get("folder") or (parse_qs(urlparse(self.path).query).get("folder") or [""])[0])
            for key, sign in (("add_labels", True), ("remove_labels", False)):
                for lab in data.get(key) or []:
                    m = LABEL_TO_FLAG.get(str(lab).lower())
                    if not m:
                        ignored.append(lab)
                        continue
                    flag, pos = m
                    add = pos if sign else not pos
                    self.mail.flag(mid, [flag], add=add, folder=folder)
                    applied.append({"label": lab, "flag": flag, "set": add})
        except FolderForbidden as e:
            self._folder_denied(e)
            return
        except BridgeLockout as e:
            _json(self, 503, {"error": "bridge_lockout", "message": str(e), "retry_after": e.retry_after}, {"Retry-After": str(e.retry_after)})
        except RecipientRefused as e:
            _json(self, 422, {"error": "recipient_refused", "message": str(e), "recipients": e.addrs})
        except MailError as e:
            _json(self, 502, {"error": str(e)})
            return
        except (RuntimeError, ValueError) as e:
            _json(self, 400, {"error": str(e)})
            return
        _json(self, 200, {"ok": True, "message_id": mid, "folder": folder, "applied": applied, "ignored": ignored})


def serve(host: str | None = None, port: int | None = None) -> None:
    assert_bridge_loopback()
    for cfg in (
        Path(os.environ.get("PROTON_AGENT_BRIDGE_FILE") or Path.home() / ".config/proton-agent-mail/bridge.json"),
        Path.home() / ".config" / "himalaya" / "config.toml",  # legacy credential file, checked only if it still exists
    ):
        assert_config_private(cfg)
    token = load_token()
    him = BridgeClient()
    host = host or default_bind()
    port = int(port or os.environ.get("PROTON_AGENT_PORT", "18765"))
    AgentHandler.token = token
    AgentHandler.mail = him
    AgentHandler.attachments = AttachmentService(him)
    AgentHandler.inbox_id = os.environ.get("PROTON_AGENT_INBOX", "default")
    AgentHandler.from_addr = os.environ.get("PROTON_AGENT_FROM", "agent@localhost")
    AgentHandler.send_as = parse_send_as(os.environ.get("PROTON_AGENT_SEND_AS", ""))
    AgentHandler.scope = FolderScope.from_env()  # a malformed scope stops the service here, before it listens
    AgentHandler.read_only = os.environ.get("PROTON_AGENT_READONLY", "").lower() in {"1", "true", "yes"}
    watch_folder = AgentHandler.scope.default  # the new-mail watcher must stay inside the scope too
    AgentHandler.events = events_from_env(
        lambda: _normalize_envelopes(him.envelopes(n=40, folder=watch_folder)), AgentHandler.inbox_id
    )
    AgentHandler.events.start()
    ensure_dirs()  # create quarantine tree on boot
    httpd = ThreadingHTTPServer((host, port), AgentHandler)
    print(
        f"proton-agent-mail {API_VERSION} on {host}:{port} "
        f"inbox={AgentHandler.inbox_id} agentmail=on attachments=on "
        f"events={'watch' if AgentHandler.events.interval > 0 else 'off'} "
        f"folders={','.join(AgentHandler.scope.folders) or 'all'} read_only={AgentHandler.read_only}",
        flush=True,
    )
    httpd.serve_forever()

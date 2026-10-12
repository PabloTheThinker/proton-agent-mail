"""AgentMail-style events for Proton Bridge: watch → message.received.

AgentMail pushes `message.received` via webhooks / websockets. Proton Bridge has
no push, so a background watcher polls envelopes and turns *new ids* into events.

Delivery (all optional, all opt-in by env):
  * in-memory ring + JSONL log  → GET /inboxes/{id}/events?after=<event_id>&wait=<s>
  * webhook                     → POST PROTON_AGENT_WEBHOOK_URL (HMAC-SHA256 signed)
  * local hook command          → PROTON_AGENT_ON_NEW (argv, no shell; gets NO mail data)

Security notes:
  * Event payloads carry envelope metadata only (id, from, subject, date, flags) —
    never bodies. Subjects that look like one-time codes are masked.
  * The hook command receives nothing from the mail (no args/stdin), so a hostile
    subject cannot inject into it.
  * Webhook URL must be http(s); body signed with X-Proton-Agent-Signature.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import shlex
import subprocess
import threading
import time
import urllib.request
import uuid
from collections import deque
from pathlib import Path
from typing import Any, Callable

OTP_RE = re.compile(r"(?i)(code|otp|verification|verify|one[- ]time|2fa|login)\D{0,20}\d{4,8}")


def mask_subject(subj: str) -> str:
    s = str(subj or "")
    if OTP_RE.search(s):
        return re.sub(r"\d{4,8}", "••••", s)
    return s


def _state_dir() -> Path:
    base = os.environ.get("PROTON_AGENT_STATE") or str(Path.home() / ".local/state/proton-agent-mail")
    p = Path(base)
    p.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(p, 0o700)
    except OSError:
        pass
    return p


class EventBus:
    """Watch the inbox, emit message.received events, fan out to sinks."""

    def __init__(
        self,
        list_envelopes: Callable[[], list[dict[str, Any]]],
        inbox_id: str = "default",
        interval: float = 0.0,
        webhook_url: str = "",
        webhook_secret: str = "",
        on_new: str = "",
        ring: int = 200,
    ) -> None:
        self.list_envelopes = list_envelopes
        self.inbox_id = inbox_id
        self.interval = float(interval or 0)
        self.webhook_url = webhook_url.strip()
        if self.webhook_url and not self.webhook_url.startswith(("http://", "https://")):
            raise ValueError("PROTON_AGENT_WEBHOOK_URL must be http(s)")
        self.webhook_secret = webhook_secret
        self.on_new = shlex.split(on_new) if on_new else []
        self.events: deque[dict[str, Any]] = deque(maxlen=ring)
        self.cond = threading.Condition()
        self.state_dir = _state_dir()
        self.seen_path = self.state_dir / f"seen-{inbox_id}.json"
        self.log_path = self.state_dir / f"events-{inbox_id}.jsonl"
        self.seen: set[str] = set()
        self.baselined = False
        self.last_poll: str | None = None
        self.last_error: str | None = None
        self._load()

    # ---------- state ----------
    def _load(self) -> None:
        try:
            d = json.loads(self.seen_path.read_text(encoding="utf-8"))
            self.seen = set(str(x) for x in d.get("seen") or [])
            self.baselined = bool(d.get("baselined"))
        except (OSError, json.JSONDecodeError):
            pass
        try:
            lines = self.log_path.read_text(encoding="utf-8").splitlines()[-(self.events.maxlen or 200):]
            for ln in lines:
                self.events.append(json.loads(ln))
        except (OSError, json.JSONDecodeError):
            pass

    def _save(self) -> None:
        keep = sorted(self.seen, key=lambda x: int(x) if x.isdigit() else 0)[-2000:]
        tmp = self.seen_path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"seen": keep, "baselined": True}), encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(self.seen_path)

    # ---------- events ----------
    def _event(self, env: dict[str, Any]) -> dict[str, Any]:
        msg = {
            "inbox_id": self.inbox_id,
            "message_id": str(env.get("id")),
            "from_email": env.get("from_email") or "",
            "from_name": env.get("from_name") or "",
            "subject": mask_subject(env.get("subject") or ""),
            "date": env.get("date"),
            "unread": env.get("unread"),
            "has_attachments": env.get("has_attachments"),
        }
        return {
            "type": "event",
            "event_type": "message.received",
            "event_id": f"evt_{int(time.time()*1000)}_{uuid.uuid4().hex[:8]}",
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "message": msg,
        }

    def poll_once(self) -> list[dict[str, Any]]:
        items = self.list_envelopes()
        self.last_poll = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        ids = [str(i.get("id")) for i in items if i.get("id") is not None]
        if not self.baselined:
            self.seen.update(ids)
            self.baselined = True
            self._save()
            return []
        fresh = [i for i in items if str(i.get("id")) not in self.seen]
        fresh.sort(key=lambda i: int(i["id"]) if str(i.get("id")).isdigit() else 0)
        out = []
        for env in fresh:
            self.seen.add(str(env.get("id")))
            ev = self._event(env)
            out.append(ev)
        if out:
            self._save()
            with self.log_path.open("a", encoding="utf-8") as f:
                for ev in out:
                    f.write(json.dumps(ev, ensure_ascii=False) + "\n")
            os.chmod(self.log_path, 0o600)
            with self.cond:
                self.events.extend(out)
                self.cond.notify_all()
            for ev in out:
                self._webhook(ev)
            self._hook()
        return out

    def _webhook(self, ev: dict[str, Any]) -> None:
        if not self.webhook_url:
            return
        body = json.dumps(ev).encode()
        headers = {"Content-Type": "application/json", "User-Agent": "proton-agent-mail-events"}
        if self.webhook_secret:
            sig = hmac.new(self.webhook_secret.encode(), body, hashlib.sha256).hexdigest()
            headers["X-Proton-Agent-Signature"] = f"sha256={sig}"
        req = urllib.request.Request(self.webhook_url, data=body, headers=headers, method="POST")
        for attempt in range(3):
            try:
                with urllib.request.urlopen(req, timeout=10):
                    return
            except Exception as e:  # noqa: BLE001 — never kill the watcher
                self.last_error = f"webhook: {type(e).__name__}"
                time.sleep(2 ** attempt)

    def _hook(self) -> None:
        if not self.on_new:
            return
        try:
            subprocess.Popen(
                self.on_new,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError as e:
            self.last_error = f"hook: {type(e).__name__}"

    def since(self, after: str | None, wait: float = 0.0, limit: int = 50) -> list[dict[str, Any]]:
        def pick() -> list[dict[str, Any]]:
            evs = list(self.events)
            if after:
                idx = next((n for n, e in enumerate(evs) if e.get("event_id") == after), None)
                evs = evs[idx + 1 :] if idx is not None else evs
            return evs[-limit:]

        got = pick()
        if got or wait <= 0:
            return got
        deadline = time.time() + min(wait, 60)
        with self.cond:
            while time.time() < deadline:
                self.cond.wait(timeout=max(0.1, deadline - time.time()))
                got = pick()
                if got:
                    break
        return got

    def status(self) -> dict[str, Any]:
        return {
            "watching": self.interval > 0,
            "interval_s": self.interval,
            "last_poll": self.last_poll,
            "last_error": self.last_error,
            "webhook": bool(self.webhook_url),
            "hook": bool(self.on_new),
            "events_buffered": len(self.events),
        }

    # ---------- loop ----------
    def start(self) -> None:
        if self.interval <= 0:
            return

        def loop() -> None:
            while True:
                try:
                    self.poll_once()
                    if (self.last_error or "").startswith("poll"):
                        self.last_error = None
                except Exception as e:  # noqa: BLE001
                    self.last_error = f"poll: {type(e).__name__}"
                time.sleep(self.interval)

        threading.Thread(target=loop, name="proton-agent-events", daemon=True).start()


def from_env(list_envelopes: Callable[[], list[dict[str, Any]]], inbox_id: str) -> EventBus:
    return EventBus(
        list_envelopes,
        inbox_id=inbox_id,
        interval=float(os.environ.get("PROTON_AGENT_WATCH_SECS", "0") or 0),
        webhook_url=os.environ.get("PROTON_AGENT_WEBHOOK_URL", ""),
        webhook_secret=os.environ.get("PROTON_AGENT_WEBHOOK_SECRET", ""),
        on_new=os.environ.get("PROTON_AGENT_ON_NEW", ""),
    )

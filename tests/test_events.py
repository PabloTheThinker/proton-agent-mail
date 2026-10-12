"""Tests for events.py — message.received watcher (no Bridge needed)."""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from proton_agent_mail import events as ev


@pytest.fixture(autouse=True)
def _state(tmp_path, monkeypatch):
    monkeypatch.setenv("PROTON_AGENT_STATE", str(tmp_path))


def _box(ids):
    return lambda: [{"id": str(i), "from_email": f"a{i}@x.test", "subject": f"s{i}", "unread": True} for i in ids]


def test_baseline_then_new_only():
    inbox = [1, 2, 3]
    bus = ev.EventBus(lambda: _box(inbox)())
    assert bus.poll_once() == []  # baseline: no storm
    inbox.append(4)
    out = bus.poll_once()
    assert [e["message"]["message_id"] for e in out] == ["4"]
    assert out[0]["event_type"] == "message.received"
    assert bus.poll_once() == []  # idempotent


def test_state_survives_restart():
    inbox = [1, 2]
    ev.EventBus(lambda: _box(inbox)()).poll_once()
    inbox.append(3)
    bus2 = ev.EventBus(lambda: _box(inbox)())
    assert [e["message"]["message_id"] for e in bus2.poll_once()] == ["3"]
    # log replayed into ring on the next boot
    bus3 = ev.EventBus(lambda: _box(inbox)())
    assert len(bus3.since(None)) == 1


def test_since_cursor_and_longpoll():
    inbox = [1]
    bus = ev.EventBus(lambda: _box(inbox)())
    bus.poll_once()
    inbox.append(2)
    first = bus.poll_once()[0]["event_id"]
    assert bus.since(first) == []

    def later():
        time.sleep(0.3)
        inbox.append(3)
        bus.poll_once()

    threading.Thread(target=later).start()
    t0 = time.time()
    got = bus.since(first, wait=5)
    assert [e["message"]["message_id"] for e in got] == ["3"]
    assert time.time() - t0 < 3


def test_otp_subjects_masked_and_no_body():
    bus = ev.EventBus(lambda: [])
    e = bus._event({"id": "9", "subject": "Your login code is 482913", "text": "SECRET BODY"})
    assert "482913" not in json.dumps(e)
    assert "SECRET BODY" not in json.dumps(e)


def test_webhook_signed():
    got = {}

    class H(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            body = self.rfile.read(int(self.headers["Content-Length"]))
            got["sig"] = self.headers.get("X-Proton-Agent-Signature")
            got["body"] = body
            self.send_response(204)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.handle_request, daemon=True).start()
    inbox = [1]
    bus = ev.EventBus(lambda: _box(inbox)(), webhook_url=f"http://127.0.0.1:{srv.server_port}/h", webhook_secret="s3")
    bus.poll_once()
    inbox.append(2)
    bus.poll_once()
    want = "sha256=" + hmac.new(b"s3", got["body"], hashlib.sha256).hexdigest()
    assert got["sig"] == want
    srv.server_close()


def test_rejects_non_http_webhook():
    with pytest.raises(ValueError):
        ev.EventBus(lambda: [], webhook_url="file:///etc/passwd")


def test_hook_gets_no_mail_data(tmp_path):
    marker = tmp_path / "fired"
    inbox = [1]
    bus = ev.EventBus(lambda: _box(inbox)(), on_new=f"touch {marker}")
    bus.poll_once()
    inbox.append(2)
    bus.poll_once()
    for _ in range(30):
        if marker.exists():
            break
        time.sleep(0.05)
    assert marker.exists()
    assert bus.on_new == ["touch", str(marker)]  # argv, no shell, no mail fields

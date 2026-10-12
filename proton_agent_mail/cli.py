"""CLI: proton-agent-mail {serve,health,list,read,send,attachments,fetch,token,setup}"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

from . import __version__
from .security import default_bind, load_token, new_token


def _url() -> tuple[str, str]:
    host = os.environ.get("PROTON_AGENT_BIND", "127.0.0.1")
    port = os.environ.get("PROTON_AGENT_PORT", "18765")
    inbox = os.environ.get("PROTON_AGENT_INBOX", "default")
    return f"http://{host}:{port}", inbox


def _req(method: str, path: str, body: dict | None = None, auth: bool = True, timeout: int = 120) -> dict:
    base, _ = _url()
    data = None if body is None else json.dumps(body).encode()
    headers = {"Content-Type": "application/json", "User-Agent": f"proton-agent-mail/{__version__}"}
    if auth:
        headers["Authorization"] = f"Bearer {load_token()}"
    req = urllib.request.Request(base + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        err = e.read().decode()[:400]
        raise SystemExit(f"HTTP {e.code}: {err}") from e


def main() -> None:
    p = argparse.ArgumentParser(prog="proton-agent-mail")
    p.add_argument("--version", action="version", version=f"proton-agent-mail {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("serve")
    sub.add_parser("health")
    sub.add_parser("token")
    lst = sub.add_parser("list")
    lst.add_argument("--limit", type=int, default=15)
    rd = sub.add_parser("read")
    rd.add_argument("id")
    rd.add_argument("--mark-read", action="store_true", help="also flag as read (default leaves unread)")
    evp = sub.add_parser("events", help="message.received events (long-poll)")
    evp.add_argument("--after", default="")
    evp.add_argument("--wait", type=float, default=0)
    evp.add_argument("--follow", action="store_true", help="stream forever, one JSON line per event")
    mk = sub.add_parser("mark", help="add/remove labels: read unread replied starred")
    mk.add_argument("id")
    mk.add_argument("--add", action="append", default=[])
    mk.add_argument("--remove", action="append", default=[])
    sd = sub.add_parser("send")
    sd.add_argument("--to", required=True)
    sd.add_argument("--subject", required=True)
    sd.add_argument("--body", default="")
    sd.add_argument(
        "--file",
        action="append",
        default=[],
        help="Attachment path (repeatable). Scanned before send.",
    )
    att = sub.add_parser("attachments", help="List attachments on a message")
    att.add_argument("id")
    att.add_argument("--folder", default="INBOX")
    ft = sub.add_parser("fetch", help="Download attachments into quarantine, scan, promote clean")
    ft.add_argument("id")
    ft.add_argument("--folder", default="INBOX")
    ft.add_argument("--index", action="append", type=int, default=None)
    sub.add_parser("setup")
    th = sub.add_parser("threads")
    th.add_argument("--limit", type=int, default=15)
    rp = sub.add_parser("reply")
    rp.add_argument("id")
    rp.add_argument("--to", default="")
    rp.add_argument("--subject", default="")
    rp.add_argument("--body", default="")
    args = p.parse_args()

    if args.cmd == "token":
        print(new_token())
        return
    if args.cmd == "setup":
        from .setup import setup

        setup(watch=True)
        return
    if args.cmd == "serve":
        from .server import serve

        serve()
        return
    if args.cmd == "health":
        print(json.dumps(_req("GET", "/health", auth=False), indent=2))
        return
    _, inbox = _url()
    if args.cmd == "list":
        print(json.dumps(_req("GET", f"/inboxes/{inbox}/messages?limit={args.limit}"), indent=2))
        return
    if args.cmd == "read":
        q = f"/inboxes/{inbox}/messages/{args.id}" + ("?mark_read=1" if args.mark_read else "")
        print(json.dumps(_req("GET", q), indent=2))
        return
    if args.cmd == "events":
        after = args.after
        while True:
            q = f"/inboxes/{inbox}/events?wait={55 if args.follow else args.wait}"
            if after:
                q += f"&after={after}"
            d = _req("GET", q, timeout=70)
            if not args.follow:
                print(json.dumps(d, indent=2))
                return
            for e in d.get("events") or []:
                print(json.dumps(e), flush=True)
            after = d.get("next_after") or after
    if args.cmd == "mark":
        print(json.dumps(_req("PATCH", f"/inboxes/{inbox}/messages/{args.id}",
                              {"add_labels": args.add, "remove_labels": args.remove}), indent=2))
        return
    if args.cmd == "threads":
        print(json.dumps(_req("GET", f"/inboxes/{inbox}/threads?limit={args.limit}"), indent=2))
        return
    if args.cmd == "reply":
        body = {"text": args.body}
        if args.to:
            body["to"] = args.to
        if args.subject:
            body["subject"] = args.subject
        print(
            json.dumps(
                _req("POST", f"/inboxes/{inbox}/messages/{args.id}/reply", body, timeout=180),
                indent=2,
            )
        )
        return
    if args.cmd == "attachments":
        q = f"/inboxes/{inbox}/messages/{args.id}/attachments"
        if args.folder != "INBOX":
            q += f"?folder={args.folder}"
        print(json.dumps(_req("GET", q), indent=2))
        return
    if args.cmd == "fetch":
        body: dict = {"folder": args.folder}
        if args.index:
            body["indexes"] = args.index
        print(
            json.dumps(
                _req(
                    "POST",
                    f"/inboxes/{inbox}/messages/{args.id}/attachments/fetch",
                    body,
                    timeout=300,
                ),
                indent=2,
            )
        )
        return
    if args.cmd == "send":
        payload: dict = {"to": args.to, "subject": args.subject, "text": args.body}
        if args.file:
            payload["attachments"] = [{"path": f, "filename": f.split("/")[-1]} for f in args.file]
        # Prefer AgentMail-shaped POST .../messages
        try:
            print(json.dumps(_req("POST", f"/inboxes/{inbox}/messages", payload, timeout=180), indent=2))
        except SystemExit:
            print(json.dumps(_req("POST", f"/inboxes/{inbox}/messages/send", payload, timeout=180), indent=2))


if __name__ == "__main__":
    main()

"""Autonomous setup: the human only runs Bridge `login`; this writes the Bridge credentials the service uses."""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

from .security import new_token

INFO_USER = re.compile(r"(?:Username|username|IMAP user)\s*[:=]\s*(\S+)", re.I)
INFO_PASS = re.compile(r"(?:Password|password|IMAP password)\s*[:=]\s*(\S+)", re.I)
INFO_EMAIL = re.compile(r"([\w.+-]+@[\w.-]+)", re.I)


def port_up(port: int, host: str = "127.0.0.1") -> bool:
    s = socket.socket()
    s.settimeout(0.4)
    try:
        s.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def parse_info(blob: str) -> dict[str, str]:
    user_m = INFO_USER.search(blob)
    pass_m = INFO_PASS.search(blob)
    emails = INFO_EMAIL.findall(blob)
    user = user_m.group(1) if user_m else ""
    pw = pass_m.group(1) if pass_m else ""
    email = emails[0] if emails else user
    return {"username": user, "password": pw, "email": email}


def which_bridge() -> str | None:
    for name in ("protonmail-bridge", "proton-bridge"):
        p = shutil.which(name)
        if p:
            return p
    p = Path("/usr/bin/protonmail-bridge")
    return str(p) if p.is_file() else None


def bridge_cli(bridge: str, command: str, timeout: int = 20) -> str:
    """One-shot CLI command. Never print the result (may contain IMAP password)."""
    proc = subprocess.run(
        [bridge, "-c"],
        input=f"{command}\nexit\n",
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    return (proc.stdout or "") + "\n" + (proc.stderr or "")


def write_bridge_credentials(email: str, username: str, password: str) -> Path:
    """Store the Bridge login the service reads (mode 0600, created that way, never printed)."""
    cfg = Path(os.environ.get("PROTON_AGENT_BRIDGE_FILE") or Path.home() / ".config" / "proton-agent-mail" / "bridge.json")
    cfg.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(cfg, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump({"user": username, "password": password, "email": email}, fh)
    cfg.chmod(0o600)
    return cfg


def write_token_file() -> Path:
    p = Path.home() / ".config" / "proton-agent-mail.token"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(new_token() + "\n", encoding="utf-8")
    p.chmod(0o600)
    return p


def start_bridge_noninteractive(bridge: str) -> None:
    if port_up(1143) and port_up(1025):
        return
    subprocess.Popen(
        [bridge, "--noninteractive"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def wait_for_login(bridge: str, timeout: int = 900, every: int = 4) -> dict[str, str]:
    """Poll until Bridge has an account. Human must `login` in another terminal."""
    print(
        "WAITING_FOR_LOGIN: in another terminal run:\n"
        f"  {bridge} -c\n"
        "  login\n"
        "Sign in there (2FA if asked). I will continue when Bridge accepts it.\n"
        "Do not paste your Proton password into this chat.",
        flush=True,
    )
    deadline = time.time() + timeout
    while time.time() < deadline:
        if port_up(1143) and port_up(1025):
            try:
                raw = bridge_cli(bridge, "info")
            except (subprocess.TimeoutExpired, OSError):
                time.sleep(every)
                continue
            parsed = parse_info(raw)
            if parsed["username"] and parsed["password"]:
                print("LOGIN_ACCEPTED", flush=True)
                return parsed
        time.sleep(every)
    raise RuntimeError("timed out waiting for Bridge login")


def setup(*, watch: bool = True) -> None:
    bridge = which_bridge()
    if not bridge:
        print(
            "NEED_BRIDGE: install Proton Mail Bridge from https://proton.me/mail/bridge "
            "then re-run: proton-agent-mail setup",
            flush=True,
        )
        sys.exit(2)
    start_bridge_noninteractive(bridge)
    creds = wait_for_login(bridge) if watch else parse_info(bridge_cli(bridge, "info"))
    if not creds.get("password"):
        raise RuntimeError("Bridge info had no IMAP password yet — finish login")
    cfg = write_bridge_credentials(creds["email"] or creds["username"], creds["username"], creds["password"])
    tok = write_token_file()
    print(f"CONFIGURED bridge_file={cfg} token_file={tok} (secrets not printed)", flush=True)
    print("NEXT: PROTON_AGENT_TOKEN_FILE=%s PROTON_AGENT_FROM='%s' proton-agent-mail serve" % (tok, creds["email"]), flush=True)

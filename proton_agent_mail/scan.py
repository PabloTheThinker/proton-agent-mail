"""Attachment quarantine + malware scan.

Default flow:
  incoming (mode 0700) → scan (docker clamav preferred, host clamdscan/clamscan fallback)
  → clean/ or blocked/

Nothing is "usable" until it lands under clean/ with a scan manifest.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

# Hard block even if AV is clean — agents must not execute these.
BLOCKED_EXTENSIONS = frozenset(
    {
        ".exe",
        ".com",
        ".dll",
        ".msi",
        ".bat",
        ".cmd",
        ".ps1",
        ".psm1",
        ".vbs",
        ".vbe",
        ".js",
        ".jse",
        ".wsf",
        ".wsh",
        ".hta",
        ".scr",
        ".pif",
        ".cpl",
        ".jar",
        ".apk",
        ".dmg",
        ".pkg",
        ".sh",
        ".bash",
        ".zsh",
        ".csh",
        ".ksh",
        ".elf",
        ".so",
        ".dylib",
        ".reg",
        ".lnk",
        ".iso",
        ".img",
        ".vhd",
        ".vhdx",
    }
)

# Allowed for agent use after clean scan (business / docs / media).
ALLOWED_EXTENSIONS = frozenset(
    {
        ".pdf",
        ".txt",
        ".md",
        ".csv",
        ".json",
        ".xml",
        ".html",
        ".htm",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".tif",
        ".tiff",
        ".bmp",
        ".heic",
        ".svg",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".odt",
        ".ods",
        ".odp",
        ".rtf",
        ".zip",
        ".7z",
        ".gz",
        ".tgz",
        ".bz2",
        ".xz",
        ".eml",
        ".ics",
        ".vcf",
        ".mp3",
        ".wav",
        ".m4a",
        ".mp4",
        ".webm",
        ".mov",
        ".opus",
        ".ogg",
    }
)

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._+-]+")
_DOUBLE_EXT = re.compile(
    r"\.(?:pdf|png|jpe?g|gif|txt|doc|docx|xls|xlsx|zip)\.(?:exe|com|scr|bat|cmd|js|vbs|ps1)$",
    re.I,
)


@dataclass
class ScanResult:
    ok: bool
    status: str  # clean | blocked_policy | infected | scan_error | oversized
    path: str | None
    quarantine_path: str | None
    sha256: str
    filename: str
    size: int
    backend: str
    detail: str = ""
    reasons: list[str] = field(default_factory=list)
    scan_ms: int = 0
    message_id: str | None = None
    attachment_index: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def default_quarantine_root() -> Path:
    env = os.environ.get("PROTON_AGENT_QUARANTINE")
    if env:
        return Path(env).expanduser()
    xdg = os.environ.get("XDG_STATE_HOME")
    if xdg:
        return Path(xdg) / "proton-agent-mail" / "quarantine"
    return Path.home() / ".local" / "state" / "proton-agent-mail" / "quarantine"


def max_bytes() -> int:
    raw = os.environ.get("PROTON_AGENT_ATTACH_MAX_BYTES", str(25 * 1024 * 1024))
    try:
        return max(1024, int(raw))
    except ValueError:
        return 25 * 1024 * 1024


def ensure_dirs(root: Path | None = None) -> dict[str, Path]:
    root = root or default_quarantine_root()
    dirs = {
        "root": root,
        "incoming": root / "incoming",
        "clean": root / "clean",
        "blocked": root / "blocked",
        "meta": root / "meta",
    }
    for p in dirs.values():
        p.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(p, 0o700)
        except OSError:
            pass
    return dirs


def safe_filename(name: str, fallback: str = "attachment.bin") -> str:
    base = Path(name or fallback).name  # strip any path
    base = base.replace("\x00", "")
    base = _SAFE_NAME.sub("_", base).strip("._") or fallback
    if len(base) > 180:
        stem, suf = Path(base).stem[:140], Path(base).suffix[:20]
        base = stem + suf
    return base


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def extension_policy(filename: str) -> tuple[str, list[str]]:
    """Return (allow|block|review, reasons)."""
    reasons: list[str] = []
    name = filename or ""
    lower = name.lower()
    if _DOUBLE_EXT.search(lower):
        return "block", ["double_extension_executable"]
    # multi-suffix: file.pdf.exe
    parts = Path(lower).name.split(".")
    if len(parts) >= 3:
        last = f".{parts[-1]}"
        if last in BLOCKED_EXTENSIONS:
            return "block", ["blocked_extension", last]
    ext = Path(lower).suffix
    if ext in BLOCKED_EXTENSIONS:
        return "block", ["blocked_extension", ext]
    if ext in ALLOWED_EXTENSIONS or ext == "":
        if ext == "":
            reasons.append("no_extension_review")
            return "review", reasons
        return "allow", reasons
    reasons.append(f"unknown_extension:{ext or '(none)'}")
    return "review", reasons


def _run(cmd: list[str], timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _scan_clamdscan(path: Path) -> tuple[str, str, str]:
    """Return (status, backend, detail) status in clean|infected|error."""
    bin_ = shutil.which("clamdscan")
    if not bin_:
        return "error", "clamdscan", "clamdscan not found"
    r = _run([bin_, "--no-summary", "--fdpass", str(path)], timeout=180)
    out = (r.stdout or "") + (r.stderr or "")
    if "FOUND" in out and "OK" not in out.splitlines()[-1:]:
        # clamdscan prints "file: Signature FOUND"
        if re.search(r":\s+\S+\s+FOUND", out):
            return "infected", "clamdscan", out.strip()[:500]
    if r.returncode == 0 and "FOUND" not in out:
        return "clean", "clamdscan", "OK"
    if r.returncode == 1 or "FOUND" in out:
        return "infected", "clamdscan", out.strip()[:500]
    return "error", "clamdscan", out.strip()[:500] or f"exit {r.returncode}"


def _scan_clamscan(path: Path) -> tuple[str, str, str]:
    bin_ = shutil.which("clamscan")
    if not bin_:
        return "error", "clamscan", "clamscan not found"
    r = _run([bin_, "--no-summary", "--infected", str(path)], timeout=300)
    out = (r.stdout or "") + (r.stderr or "")
    if r.returncode == 0:
        return "clean", "clamscan", "OK"
    if r.returncode == 1 or "FOUND" in out:
        return "infected", "clamscan", out.strip()[:500]
    return "error", "clamscan", out.strip()[:500] or f"exit {r.returncode}"


def _scan_docker(path: Path) -> tuple[str, str, str]:
    """Run ClamAV in an isolated container; file mounted read-only."""
    if not shutil.which("docker"):
        return "error", "docker-clamav", "docker not found"
    image = os.environ.get("PROTON_AGENT_CLAM_IMAGE", "clamav/clamav:stable")
    work_dir = path.parent.resolve()
    name = path.name
    # Official image entrypoint runs freshclam/install into /run — override it.
    # Mount docker.sock NOT used. Network none. RW tmpfs for clam temp only.
    cmd = [
        "docker",
        "run",
        "--rm",
        "--network=none",
        "--security-opt",
        "no-new-privileges",
        "--entrypoint",
        "clamscan",
        "--tmpfs",
        "/tmp:rw,mode=1777,size=128m",
        "-v",
        f"{work_dir}:/scan:ro",
        image,
        "--no-summary",
        "--stdout",
        f"/scan/{name}",
    ]
    try:
        r = _run(cmd, timeout=600)
    except subprocess.TimeoutExpired:
        return "error", "docker-clamav", "docker scan timed out"
    out = (r.stdout or "") + (r.stderr or "")
    low = out.lower()
    if "unable to find image" in low or ("pull access denied" in low):
        return "error", "docker-clamav", out.strip()[:500]
    if "executable file not found" in low or "no such file or directory" in low and "clamscan" in low:
        return "error", "docker-clamav", out.strip()[:500]
    # clamscan: 0 clean, 1 infected, 2 error
    if r.returncode == 0 and "FOUND" not in out:
        return "clean", "docker-clamav", "OK"
    if r.returncode == 1 or re.search(r":\s+\S+\s+FOUND", out) or "FOUND" in out:
        return "infected", "docker-clamav", out.strip()[:500]
    return "error", "docker-clamav", out.strip()[:500] or f"exit {r.returncode}"


def scan_backends_order() -> list[str]:
    pref = (os.environ.get("PROTON_AGENT_SCAN") or "auto").strip().lower()
    if pref == "docker":
        return ["docker", "clamdscan", "clamscan"]
    if pref == "clamdscan":
        return ["clamdscan", "clamscan", "docker"]
    if pref == "clamscan":
        return ["clamscan", "clamdscan", "docker"]
    # auto: host daemon first (fast), then docker isolation, then clamscan
    return ["clamdscan", "docker", "clamscan"]


def run_av_scan(path: Path) -> tuple[str, str, str]:
    last = ("error", "none", "no scanner available")
    for b in scan_backends_order():
        if b == "docker":
            st, backend, detail = _scan_docker(path)
        elif b == "clamdscan":
            st, backend, detail = _scan_clamdscan(path)
        else:
            st, backend, detail = _scan_clamscan(path)
        last = (st, backend, detail)
        if st in {"clean", "infected"}:
            return last
        # error → try next backend
    return last


def admit_file(
    src: Path,
    *,
    original_name: str | None = None,
    message_id: str | None = None,
    attachment_index: int | None = None,
    require_allow_ext: bool = True,
    trust_known: bool = False,
) -> ScanResult:
    """Move/copy src into quarantine, scan, promote to clean or blocked.

    trust_known: still scans, but unknown extensions become review→clean if AV clean
    only when PROTON_AGENT_ALLOW_UNKNOWN=1 or trust_known and env set.
    """
    dirs = ensure_dirs()
    t0 = time.time()
    original_name = original_name or src.name
    fname = safe_filename(original_name)
    if not src.is_file():
        return ScanResult(
            ok=False,
            status="scan_error",
            path=None,
            quarantine_path=None,
            sha256="",
            filename=fname,
            size=0,
            backend="none",
            detail="source missing",
            reasons=["missing_source"],
            message_id=message_id,
            attachment_index=attachment_index if isinstance(attachment_index, int) else None,
        )

    size = src.stat().st_size
    if size > max_bytes():
        blocked = dirs["blocked"] / f"{uuid.uuid4().hex[:10]}_{fname}"
        shutil.copy2(src, blocked)
        try:
            os.chmod(blocked, 0o600)
        except OSError:
            pass
        digest = file_sha256(blocked)
        res = ScanResult(
            ok=False,
            status="oversized",
            path=None,
            quarantine_path=str(blocked),
            sha256=digest,
            filename=fname,
            size=size,
            backend="policy",
            detail=f"max {max_bytes()} bytes",
            reasons=["oversized"],
            scan_ms=int((time.time() - t0) * 1000),
            message_id=message_id,
            attachment_index=attachment_index if isinstance(attachment_index, int) else None,
        )
        _write_meta(dirs, res)
        return res

    policy, reasons = extension_policy(fname)
    incoming = dirs["incoming"] / f"{uuid.uuid4().hex}_{fname}"
    shutil.copy2(src, incoming)
    try:
        os.chmod(incoming, 0o600)
    except OSError:
        pass
    digest = file_sha256(incoming)

    if policy == "block":
        dest = dirs["blocked"] / incoming.name
        shutil.move(str(incoming), str(dest))
        res = ScanResult(
            ok=False,
            status="blocked_policy",
            path=None,
            quarantine_path=str(dest),
            sha256=digest,
            filename=fname,
            size=size,
            backend="policy",
            detail="extension blocked",
            reasons=reasons,
            scan_ms=int((time.time() - t0) * 1000),
            message_id=message_id,
            attachment_index=attachment_index if isinstance(attachment_index, int) else None,
        )
        _write_meta(dirs, res)
        return res

    av_status, backend, detail = run_av_scan(incoming)
    if av_status == "infected":
        dest = dirs["blocked"] / incoming.name
        shutil.move(str(incoming), str(dest))
        res = ScanResult(
            ok=False,
            status="infected",
            path=None,
            quarantine_path=str(dest),
            sha256=digest,
            filename=fname,
            size=size,
            backend=backend,
            detail=detail,
            reasons=reasons + ["av_infected"],
            scan_ms=int((time.time() - t0) * 1000),
            message_id=message_id,
            attachment_index=attachment_index if isinstance(attachment_index, int) else None,
        )
        _write_meta(dirs, res)
        return res

    if av_status != "clean":
        dest = dirs["blocked"] / incoming.name
        shutil.move(str(incoming), str(dest))
        res = ScanResult(
            ok=False,
            status="scan_error",
            path=None,
            quarantine_path=str(dest),
            sha256=digest,
            filename=fname,
            size=size,
            backend=backend,
            detail=detail,
            reasons=reasons + ["av_unavailable"],
            scan_ms=int((time.time() - t0) * 1000),
            message_id=message_id,
            attachment_index=attachment_index if isinstance(attachment_index, int) else None,
        )
        _write_meta(dirs, res)
        return res

    # AV clean — extension review gate
    allow_unknown = os.environ.get("PROTON_AGENT_ALLOW_UNKNOWN", "").strip() == "1" or trust_known
    if policy == "review" and require_allow_ext and not allow_unknown:
        dest = dirs["blocked"] / incoming.name
        shutil.move(str(incoming), str(dest))
        res = ScanResult(
            ok=False,
            status="blocked_policy",
            path=None,
            quarantine_path=str(dest),
            sha256=digest,
            filename=fname,
            size=size,
            backend=backend,
            detail="unknown extension held (set PROTON_AGENT_ALLOW_UNKNOWN=1 to release after clean scan)",
            reasons=reasons + ["unknown_ext_held"],
            scan_ms=int((time.time() - t0) * 1000),
            message_id=message_id,
            attachment_index=attachment_index if isinstance(attachment_index, int) else None,
        )
        _write_meta(dirs, res)
        return res

    dest = dirs["clean"] / incoming.name
    shutil.move(str(incoming), str(dest))
    try:
        os.chmod(dest, 0o600)
    except OSError:
        pass
    res = ScanResult(
        ok=True,
        status="clean",
        path=str(dest),
        quarantine_path=str(dest),
        sha256=digest,
        filename=fname,
        size=size,
        backend=backend,
        detail=detail,
        reasons=reasons,
        scan_ms=int((time.time() - t0) * 1000),
        message_id=message_id,
        attachment_index=attachment_index if isinstance(attachment_index, int) else None,
    )
    _write_meta(dirs, res)
    return res


def _write_meta(dirs: dict[str, Path], res: ScanResult) -> None:
    meta = dirs["meta"] / f"{res.sha256[:16]}_{int(time.time())}.json"
    try:
        meta.write_text(json.dumps(res.to_dict(), indent=2), encoding="utf-8")
        os.chmod(meta, 0o600)
    except OSError:
        pass


def is_under_clean(path: Path, root: Path | None = None) -> bool:
    dirs = ensure_dirs(root)
    try:
        path = path.resolve()
        clean = dirs["clean"].resolve()
        return path.is_file() and str(path).startswith(str(clean) + os.sep)
    except OSError:
        return False

from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

USER_AGENT = "Mozilla/5.0 (compatible; js-endpoints-hunter/1.0; " "+https://github.com/your_handle)"

_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA|EC|OPENSSH|PGP|DSA) PRIVATE KEY-----.*?"
    r"-----END (?:RSA|EC|OPENSSH|PGP|DSA) PRIVATE KEY-----",
    re.DOTALL,
)


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def host_of(value: str) -> str:
    try:
        parsed = urlparse(value)
    except ValueError:
        return ""
    return parsed.netloc.lower()


def safe_filename(value: str, fallback: str = "artifact") -> str:
    name = Path(value.replace("\\", "/")).name.strip() or fallback
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name)
    name = name.strip("._") or fallback
    return name[:120]


def human_bytes(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.1f} MB"


def mask_secret(value: str, kind: str = "generic") -> str:
    """Mask a secret without retaining enough material to reuse it."""
    if not value:
        return "***"
    kind = kind.lower()
    if "private" in kind:
        match = _PRIVATE_KEY.search(value)
        header = match.group(0).splitlines()[0] if match else "PRIVATE KEY"
        return f"{header} [REDACTED]"
    if "jwt" in kind:
        return value[:8] + "..." + value[-6:] if len(value) > 20 else "***"
    if "aws" in kind and "access" in kind:
        return value[:4] + "*" * max(0, len(value) - 4)
    if len(value) <= 8:
        return "***"
    visible = 4 if len(value) > 16 else 2
    tail = 2 if len(value) > 24 else 0
    masked = "*" * max(4, len(value) - visible - tail)
    return value[:visible] + masked + (value[-tail:] if tail else "")


def redact_text(text: str, raw: str, masked: str) -> str:
    if raw and len(raw) >= 4:
        return text.replace(raw, masked)
    return text


def decode_jwt(token: str) -> dict[str, Any] | None:
    """Decode JWT header/payload for display. Signature is never verified."""
    parts = token.split(".")
    if len(parts) != 3:
        return None

    def decode(part: str) -> Any:
        padded = part + "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))

    try:
        return {"header": decode(parts[0]), "payload": decode(parts[1])}
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def truncate(value: str, limit: int = 120) -> str:
    value = " ".join(value.split())
    return value if len(value) <= limit else value[: limit - 1] + "…"

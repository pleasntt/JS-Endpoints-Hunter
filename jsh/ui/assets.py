"""Read static UI assets from disk or from inside a zipapp archive."""

from __future__ import annotations

import mimetypes
from pathlib import Path
from typing import Any

try:
    from importlib.resources import files as _resource_files
except ImportError:  # pragma: no cover - Python 3.10 has it
    _resource_files = None  # type: ignore[assignment]


def read_asset(name: str) -> bytes | None:
    if not name:
        return None
    safe = Path(name).name
    if safe != name:
        return None
    if _resource_files is not None:
        try:
            target = _resource_files("jsh.ui.static").joinpath(safe)
            if target.is_file():
                return target.read_bytes()
        except (ImportError, ModuleNotFoundError, OSError):
            pass
    local = Path(__file__).parent / "static" / safe
    try:
        if local.is_file():
            return local.read_bytes()
    except OSError:
        return None
    return None


def _content_type(name: str) -> str:
    guessed = mimetypes.guess_type(name)[0] or "application/octet-stream"
    if guessed.startswith("text/") or guessed == "application/javascript":
        return guessed + "; charset=utf-8"
    return guessed


def attach_static(app: Any) -> None:
    """Route /static/* through the archive-aware reader, everything else to Flask."""
    inner = app.wsgi_app

    def wrapper(environ: dict[str, Any], start_response: Any) -> Any:
        name = str(environ.get("PATH_INFO", "")).lstrip("/")
        if not name.startswith("static/"):
            return inner(environ, start_response)
        data = read_asset(name[len("static/") :])
        if data is None:
            return inner(environ, start_response)
        start_response(
            "200 OK",
            [
                ("Content-Type", _content_type(name)),
                ("Content-Length", str(len(data))),
                ("Cache-Control", "public, max-age=300"),
            ],
        )
        return [data]

    app.wsgi_app = wrapper

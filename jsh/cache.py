from __future__ import annotations

import json
import threading
from pathlib import Path

from .utils import sha256_text


class Cache:
    """Content-addressed cache plus a small URL index for fast re-scans."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.index_path = self.root / "index.json"
        self._lock = threading.Lock()
        self._index: dict[str, str] = self._read_index()

    def _read_index(self) -> dict[str, str]:
        try:
            data = json.loads(self.index_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return (
            {str(key): str(value) for key, value in data.items()} if isinstance(data, dict) else {}
        )

    def _write_index(self) -> None:
        try:
            self.index_path.write_text(
                json.dumps(self._index, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except OSError:
            pass

    def get(self, url: str) -> str | None:
        with self._lock:
            digest = self._index.get(url)
        if not digest:
            return None
        path = self.root / f"{digest}.js"
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    def put(self, url: str, content: str, suffix: str = ".js") -> str:
        digest = sha256_text(url + "\n" + content)
        path = self.root / f"{digest}{suffix}"
        try:
            if not path.exists():
                path.write_text(content, encoding="utf-8", errors="replace")
            with self._lock:
                self._index[url] = digest
                self._write_index()
        except OSError:
            pass
        return digest

    def path_for(self, url: str) -> Path | None:
        with self._lock:
            digest = self._index.get(url)
        return self.root / f"{digest}.js" if digest else None

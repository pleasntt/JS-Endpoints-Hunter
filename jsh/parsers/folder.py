from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from ..models import Dependency

JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".json", ".map"}
SKIP_DIRS = {"node_modules", ".git", "vendor", "bower_components", ".venv", "__pycache__"}


@dataclass
class FolderFile:
    path: Path
    relative: str
    content: str


def iter_js_files(root: Path, include_vendor: bool = False) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in JS_EXTENSIONS:
            continue
        parts = {part.lower() for part in path.relative_to(root).parts[:-1]}
        if not include_vendor and parts & SKIP_DIRS:
            continue
        files.append(path)
    return sorted(files)


def read_folder_file(path: Path, root: Path) -> FolderFile | None:
    try:
        if path.stat().st_size > 12 * 1024 * 1024:
            return None
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    return FolderFile(path=path, relative=str(path.relative_to(root)), content=content)


def read_package_dependencies(path: Path, source: str = "") -> list[Dependency]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, dict):
        return []
    dependencies: list[Dependency] = []
    for section in ("dependencies", "devDependencies"):
        values = data.get(section, {})
        if not isinstance(values, dict):
            continue
        for name, version in values.items():
            if isinstance(name, str) and isinstance(version, str):
                dependencies.append(
                    Dependency(name=name, version=version, source=source or str(path))
                )
    return dependencies

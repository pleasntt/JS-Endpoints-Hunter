"""Build a single-file zipapp for the Web UI.

The archive bundles the jsh package plus UI templates and static files.
Third-party packages are taken from the interpreter that runs the archive,
so this stays small and never ships a broken partial dependency tree.
"""

from __future__ import annotations

import argparse
import shutil
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STAGE = ROOT / ".build" / "zipapp"
DIST = ROOT / "dist"


def _copy_into(directory: Path, path: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path, directory / path.name)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default=str(DIST / "js-endpoints-hunter.pyz"))
    parser.add_argument("--python", default="/usr/bin/env python3")
    args = parser.parse_args()

    if STAGE.exists():
        shutil.rmtree(STAGE)
    STAGE.mkdir(parents=True)
    for path in (ROOT / "jsh").rglob("*"):
        if path.is_file() and "__pycache__" not in path.parts:
            target = STAGE / "jsh" / path.relative_to(ROOT / "jsh")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
    for name in ("patterns.yaml", "config.toml", "allowlist.example.txt"):
        _copy_into(STAGE, ROOT / name)

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    zipapp.create_archive(
        STAGE, target=output, interpreter=args.python, main="jsh.ui.app:run_ui", compressed=True
    )
    print(f"{output} · {output.stat().st_size / 1024:.1f} KB")
    print("Зависимости (flask, httpx, PyYAML…) берутся из интерпретатора, который запускает архив.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

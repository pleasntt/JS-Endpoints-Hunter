# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for a standalone js-endpoints-hunter binary.
# Build from the project root: pyinstaller --noconfirm packaging/jsh.spec
import os
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files

ROOT = Path(os.path.abspath(os.getcwd()))
datas = []
for name in ("patterns.yaml", "config.toml", "allowlist.example.txt"):
    datas.append((str(ROOT / name), "."))
for path in (ROOT / "jsh" / "ui" / "templates").glob("*"):
    if path.is_file():
        datas.append((str(path), "jsh/ui/templates"))
for path in (ROOT / "jsh" / "ui" / "static").glob("*"):
    if path.is_file():
        datas.append((str(path), "jsh/ui/static"))

a = Analysis(
    [str(ROOT / "app.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=[],
    excludes=["tkinter", "pytest", "mypy", "black", "ruff"],
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    name="js-endpoints-hunter",
    console=False,
    upx=False,
)

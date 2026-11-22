from __future__ import annotations

from pathlib import Path

from jsh.config import PathsConfig, load_config
from jsh.ui.app import create_app
from jsh.ui.assets import read_asset

ROOT = Path(__file__).resolve().parents[1]


def test_static_assets_are_served(tmp_path: Path):
    config = load_config(ROOT / "config.toml")
    config.paths = PathsConfig(data_dir=tmp_path / "data")
    app = create_app(config)
    client = app.test_client()
    css = client.get("/static/styles.css")
    js = client.get("/static/app.js")
    assert css.status_code == 200
    assert b"color-scheme" in css.data
    assert js.status_code == 200
    assert b"JS-Endpoints-Hunter" in js.data or b"select-all" in js.data
    assert client.get("/static/%2e%2e/app.py").status_code == 404


def test_read_asset_rejects_path_traversal():
    assert read_asset("../app.py") is None
    assert read_asset("nope.css") is None
    assert read_asset("styles.css") is not None

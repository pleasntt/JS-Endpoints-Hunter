from __future__ import annotations

from pathlib import Path

from jsh.config import PathsConfig, load_config
from jsh.ui.app import create_app

ROOT = Path(__file__).resolve().parents[1]


def test_ui_health_and_index(tmp_path: Path):
    config = load_config(ROOT / "config.toml")
    config.paths = PathsConfig(data_dir=tmp_path / "data")
    app = create_app(config)
    client = app.test_client()
    index = client.get("/")
    assert index.status_code == 200
    assert b"JS-Endpoints-Hunter" in index.data
    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json["ok"] is True
    assert (
        client.post("/api/scan", json={"input_type": "url", "value": "not-a-url"}).status_code
        == 400
    )
    assert client.get("/api/scans").status_code == 200

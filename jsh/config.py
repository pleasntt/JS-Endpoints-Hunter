from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

from .models import ScanSettings
from .utils import USER_AGENT


@dataclass
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 8765
    open_browser: bool = True


@dataclass
class PathsConfig:
    data_dir: Path = field(default_factory=lambda: Path.home() / ".js-endpoints-hunter")
    cache_dir: Path = field(init=False)
    results_dir: Path = field(init=False)
    db_path: Path = field(init=False)

    def __post_init__(self) -> None:
        self.data_dir = self.data_dir.expanduser().resolve()
        self.cache_dir = self.data_dir / "cache"
        self.results_dir = self.data_dir / "results"
        self.db_path = self.data_dir / "history.sqlite"


@dataclass
class UIConfig:
    theme: str = "dark"
    lang: str = "ru"


@dataclass
class AppConfig:
    server: ServerConfig = field(default_factory=ServerConfig)
    scan: ScanSettings = field(default_factory=lambda: ScanSettings(user_agent=USER_AGENT))
    paths: PathsConfig = field(default_factory=PathsConfig)
    ui: UIConfig = field(default_factory=UIConfig)
    patterns_path: Path = field(default_factory=lambda: Path("patterns.yaml"))

    def ensure_dirs(self) -> None:
        self.paths.data_dir.mkdir(parents=True, exist_ok=True)
        self.paths.cache_dir.mkdir(parents=True, exist_ok=True)
        self.paths.results_dir.mkdir(parents=True, exist_ok=True)


def _section(data: dict[str, Any], name: str) -> dict[str, Any]:
    value = data.get(name, {})
    return value if isinstance(value, dict) else {}


def load_config(
    path: str | Path | None = None, overrides: dict[str, Any] | None = None
) -> AppConfig:
    raw: dict[str, Any] = {}
    config_path = Path(path) if path else Path("config.toml")
    if config_path.exists():
        with config_path.open("rb") as handle:
            raw = tomllib.load(handle)

    server = _section(raw, "server")
    scan = _section(raw, "scan")
    ui = _section(raw, "ui")
    paths = _section(raw, "paths")

    host = os.getenv("JSH_HOST", str(server.get("host", "127.0.0.1")))
    port = int(os.getenv("JSH_PORT", str(server.get("port", 8765))))
    open_browser = bool(server.get("open_browser", True))
    data_dir = Path(
        os.getenv("JSH_DATA_DIR", str(paths.get("data_dir", "~/.js-endpoints-hunter")))
    ).expanduser()

    settings = ScanSettings(
        timeout=float(os.getenv("JSH_TIMEOUT", str(scan.get("timeout", 10.0)))),
        concurrency=int(os.getenv("JSH_CONCURRENCY", str(scan.get("concurrency", 10)))),
        rate_limit=float(os.getenv("JSH_RATE_LIMIT", str(scan.get("rate_limit", 5.0)))),
        download_maps=bool(scan.get("download_maps", True)),
        find_secrets=bool(scan.get("find_secrets", True)),
        show_secrets=bool(scan.get("show_secrets", False)),
        resolve_relative=bool(scan.get("resolve_relative", True)),
        include_vendor=bool(scan.get("include_vendor", False)),
        keep_assets=bool(scan.get("keep_assets", False)),
        proxy=os.getenv("JSH_PROXY", str(scan.get("proxy", ""))),
        user_agent=str(scan.get("user_agent", USER_AGENT)),
        entropy_secrets=bool(scan.get("entropy_secrets", False)),
        allowlist_file=str(scan.get("allowlist_file", "")),
        harvest_maps=bool(scan.get("harvest_maps", True)),
    )
    if overrides:
        for key, value in overrides.items():
            if hasattr(settings, key) and value is not None:
                setattr(settings, key, value)

    return AppConfig(
        server=ServerConfig(host=host, port=port, open_browser=open_browser),
        scan=settings,
        paths=PathsConfig(data_dir=data_dir),
        ui=UIConfig(
            theme=str(ui.get("theme", "dark")),
            lang=str(ui.get("lang", "ru")),
        ),
        patterns_path=Path(str(raw.get("patterns_path", "patterns.yaml"))).expanduser(),
    )


def with_scan_overrides(base: AppConfig, values: dict[str, Any]) -> AppConfig:
    allowed = {
        key: value for key, value in values.items() if hasattr(base.scan, key) and value is not None
    }
    return replace(base, scan=replace(base.scan, **allowed))

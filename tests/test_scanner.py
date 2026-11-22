from __future__ import annotations

import asyncio
from pathlib import Path

from jsh.cache import Cache
from jsh.config import PathsConfig, load_config
from jsh.patterns import load_patterns
from jsh.scanner import Scanner

ROOT = Path(__file__).resolve().parents[1]


def test_scanner_local_folder_with_source_map(tmp_path: Path):
    examples = tmp_path / "js"
    examples.mkdir()
    (examples / "billing.js").write_text(
        'fetch("/api/v1/users");\nconst key = "AKIAABCDEFGHIJKLMNOP";\n//# sourceMappingURL=billing.js.map\n',
        encoding="utf-8",
    )
    (examples / "billing.js.map").write_text(
        '{"version":3,"sources":["src/billing.ts"],"sourcesContent":["fetch(\\"/api/v1/original\\")"]}',
        encoding="utf-8",
    )
    config = load_config(ROOT / "config.toml")
    config.paths = PathsConfig(data_dir=tmp_path / "data")
    config.paths.data_dir.mkdir(parents=True)
    patterns = load_patterns(ROOT / "patterns.yaml")
    scanner = Scanner(config, patterns, Cache(config.paths.cache_dir))
    result = asyncio.run(scanner.run("dir", str(examples), out_dir=tmp_path / "report"))
    assert result.status == "completed"
    assert any(item.value.endswith("/api/v1/users") for item in result.findings)
    assert any(
        item.origin == "original" and item.value.endswith("/api/v1/original")
        for item in result.findings
    )
    assert any(
        item.secret_type == "aws_access_key" and item.masked == "AKIA****************"
        for item in result.findings
    )
    assert (tmp_path / "report" / "report.html").exists()
    assert (tmp_path / "report" / "raw" / "billing.js").exists()

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class Pattern:
    name: str
    kind: str
    regex: re.Pattern[str]
    url_group: int = 1
    method_group: int = 0
    method: str = ""
    default_method: str = ""
    confidence: int = 50
    severity: str = ""
    value_group: int = 0
    name_group: int = 0
    secret_type: str = ""


@dataclass
class PatternSet:
    http: list[Pattern]
    websocket: list[Pattern]
    graphql: list[Pattern]
    paths: list[Pattern]
    absolute: list[Pattern]
    secrets: list[Pattern]

    @property
    def endpoint_patterns(self) -> Iterable[Pattern]:
        yield from self.http
        yield from self.websocket
        yield from self.graphql
        yield from self.paths
        yield from self.absolute


def default_patterns_path() -> Path:
    candidates = [
        Path.cwd() / "patterns.yaml",
        Path(__file__).resolve().parent.parent / "patterns.yaml",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise FileNotFoundError(
        "patterns.yaml not found; pass --patterns or create it in the project root"
    )


def _compile_item(item: dict[str, Any], default_kind: str) -> Pattern:
    name = str(item.get("name", "unnamed"))
    raw_regex = item.get("regex")
    if not raw_regex:
        raise ValueError(f"pattern {name}: regex is required")
    try:
        compiled = re.compile(str(raw_regex).strip(), re.MULTILINE)
    except re.error as exc:
        raise ValueError(f"pattern {name}: {exc}") from exc
    url_group = int(item.get("url_group", 1))
    value_group = int(item.get("value_group", 0))
    method_group = int(item.get("method_group", 0))
    name_group = int(item.get("name_group", 0))
    for label, group in (
        ("url_group", url_group),
        ("value_group", value_group),
        ("method_group", method_group),
        ("name_group", name_group),
    ):
        if group > compiled.groups:
            raise ValueError(
                f"pattern {name}: {label}={group} but regex has {compiled.groups} groups"
            )
    return Pattern(
        name=name,
        kind=str(item.get("kind", default_kind)),
        regex=compiled,
        url_group=url_group,
        method_group=method_group,
        method=str(item.get("method", "")).upper(),
        default_method=str(item.get("default_method", "")).upper(),
        confidence=int(item.get("confidence", 50)),
        severity=str(item.get("severity", "")).upper(),
        value_group=value_group,
        name_group=name_group,
        secret_type=str(item.get("secret_type", name)),
    )


def _section(data: dict[str, Any], name: str, default_kind: str) -> list[Pattern]:
    raw_items = data.get(name, [])
    if not isinstance(raw_items, list):
        raise ValueError(f"patterns.yaml: {name} must be a list")
    return [_compile_item(item, default_kind) for item in raw_items if isinstance(item, dict)]


def load_patterns(path: str | Path | None = None) -> PatternSet:
    pattern_path = Path(path) if path else default_patterns_path()
    with pattern_path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError("patterns.yaml must contain a mapping")
    return PatternSet(
        http=_section(data, "http", "rest"),
        websocket=_section(data, "websocket", "websocket"),
        graphql=_section(data, "graphql", "graphql"),
        paths=_section(data, "paths", "path"),
        absolute=_section(data, "absolute", "absolute"),
        secrets=_section(data, "secrets", "secret"),
    )

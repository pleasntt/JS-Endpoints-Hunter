from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from typing import Any

_SOURCE_MAP_RE = re.compile(
    r"(?://[#@]\s*sourceMappingURL=|/\*[#@]\s*sourceMappingURL=)\s*([^\s*]+)"
)


@dataclass
class SourceMapSource:
    name: str
    content: str


@dataclass
class SourceMapData:
    url: str = ""
    sources: list[SourceMapSource] = field(default_factory=list)
    error: str = ""


def find_source_map_url(text: str) -> str:
    match = _SOURCE_MAP_RE.search(text)
    return match.group(1).strip() if match else ""


def _collect_sources(data: Any, result: SourceMapData, depth: int = 0) -> None:
    if depth > 8 or not isinstance(data, dict):
        return
    sources = data.get("sources", [])
    contents = data.get("sourcesContent", [])
    if isinstance(sources, list) and isinstance(contents, list):
        for index, content in enumerate(contents):
            if not isinstance(content, str) or not content:
                continue
            name = str(sources[index]) if index < len(sources) else f"source-{index}"
            result.sources.append(SourceMapSource(name=name, content=content))
    sections = data.get("sections", [])
    if isinstance(sections, list):
        for section in sections:
            if isinstance(section, dict) and isinstance(section.get("map"), dict):
                _collect_sources(section["map"], result, depth + 1)


def parse_source_map(text: str, url: str = "") -> SourceMapData:
    payload = text
    if text.startswith("data:"):
        try:
            _, encoded = text.split(",", 1)
            if ";base64" in text.split(",", 1)[0]:
                payload = base64.b64decode(encoded).decode("utf-8", errors="replace")
            else:
                from urllib.parse import unquote

                payload = unquote(encoded)
        except (ValueError, TypeError) as exc:
            return SourceMapData(url=url, error=f"invalid data source map: {exc}")
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        return SourceMapData(url=url, error=f"invalid source map: {exc}")
    result = SourceMapData(url=url)
    _collect_sources(data, result)
    if not result.sources:
        result.error = "source map has no sourcesContent"
    return result

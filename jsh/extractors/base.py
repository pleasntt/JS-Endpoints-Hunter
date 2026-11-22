from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..normalize import host_from, is_noise, normalize_endpoint, normalize_template
from ..patterns import Pattern
from ..utils import truncate


@dataclass
class RawMatch:
    value: str
    method: str
    line: int
    snippet: str
    start: int
    end: int


def line_of(text: str, position: int) -> int:
    return text.count("\n", 0, position) + 1


def snippet_of(text: str, start: int, end: int, width: int = 120) -> str:
    left = max(0, start - width // 2)
    right = min(len(text), end + width // 2)
    return truncate(text[left:right], width + 40)


def match_context(text: str, match: Any, pattern: Pattern) -> RawMatch | None:
    group = pattern.value_group or pattern.url_group
    if group <= 0 or group > len(match.groups()):
        return None
    value = match.group(group)
    if not value:
        return None
    method = pattern.method
    if pattern.method_group and pattern.method_group <= len(match.groups()):
        method = match.group(pattern.method_group) or pattern.default_method or method
    if not method:
        method = pattern.default_method
    return RawMatch(
        value=value,
        method=method.upper(),
        line=line_of(text, match.start()),
        snippet=snippet_of(text, match.start(), match.end()),
        start=match.start(),
        end=match.end(),
    )


def endpoint_meta(value: str, base_url: str | None) -> dict[str, Any]:
    normalized_template = normalize_template(value)
    return {
        "host": host_from(value, base_url),
        "original": value,
        "template": normalized_template if normalized_template != value else "",
    }


def is_usable_endpoint(value: str, keep_assets: bool) -> bool:
    return (
        bool(value)
        and not is_noise(value, keep_assets=keep_assets)
        and bool(normalize_endpoint(value, keep_assets=keep_assets))
    )

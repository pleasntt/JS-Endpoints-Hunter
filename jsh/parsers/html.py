from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

_SCRIPT_RE = re.compile(r"<script\b([^>]*)>(.*?)</script\s*>", re.IGNORECASE | re.DOTALL)
_LINK_RE = re.compile(r"<link\b([^>]*)>", re.IGNORECASE)
_BASE_RE = re.compile(r"<base\b([^>]*)>", re.IGNORECASE)
_ATTR_RE = re.compile(r"([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s\"'>]+))")
_URL_KEYS = {"main", "bundle", "src", "entry", "entrypoint"}


@dataclass
class ScriptRef:
    url: str = ""
    inline: str = ""
    kind: str = "script"
    source: str = ""


@dataclass
class HTMLDocument:
    base_url: str
    title: str = ""
    scripts: list[ScriptRef] = field(default_factory=list)
    manifests: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _attrs(raw: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for match in _ATTR_RE.finditer(raw):
        key = match.group(1).lower()
        value = match.group(2) or match.group(3) or match.group(4) or ""
        result[key] = value
    return result


def _collect_importmap(data: Any, base_url: str, refs: list[ScriptRef]) -> None:
    if not isinstance(data, dict):
        return
    mappings: list[str] = []
    imports = data.get("imports", {})
    if isinstance(imports, dict):
        for value in imports.values():
            if isinstance(value, str):
                mappings.append(value)
    scopes = data.get("scopes", {})
    if isinstance(scopes, dict):
        for scope in scopes.values():
            if isinstance(scope, dict):
                for value in scope.values():
                    if isinstance(value, str):
                        mappings.append(value)
    for value in mappings:
        url = (
            urljoin(base_url, value)
            if not value.startswith(("http://", "https://", "//"))
            else value
        )
        if url.startswith("//") and base_url:
            url = "https:" + url
        refs.append(ScriptRef(url=url, kind="importmap"))


def parse_manifest(text: str, base_url: str) -> list[ScriptRef]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    refs: list[ScriptRef] = []
    for key, value in data.items():
        if key.lower() not in _URL_KEYS:
            continue
        values = value if isinstance(value, list) else [value]
        for item in values:
            if isinstance(item, str) and item:
                url = (
                    item
                    if item.startswith(("http://", "https://", "//"))
                    else urljoin(base_url, item)
                )
                refs.append(ScriptRef(url=url, kind="manifest"))
    return refs


def parse_html(text: str, base_url: str) -> HTMLDocument:
    document = HTMLDocument(base_url=base_url)
    title_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
    if title_match:
        document.title = " ".join(title_match.group(1).split())

    base_match = _BASE_RE.search(text)
    if base_match:
        base_href = _attrs(base_match.group(1)).get("href", "")
        if base_href:
            document.base_url = urljoin(base_url, base_href)

    for link_match in _LINK_RE.finditer(text):
        attrs = _attrs(link_match.group(1))
        rel = attrs.get("rel", "").lower()
        href = attrs.get("href", "")
        if not href:
            continue
        if "manifest" in rel.split():
            document.manifests.append(urljoin(document.base_url, href))
        if "script" in attrs.get("as", "").lower() or "modulepreload" in rel.split():
            document.scripts.append(ScriptRef(url=urljoin(document.base_url, href), kind="preload"))

    for script_match in _SCRIPT_RE.finditer(text):
        attrs = _attrs(script_match.group(1))
        script_type = attrs.get("type", "").lower()
        src = attrs.get("src", "")
        inline = script_match.group(2).strip()
        if script_type == "importmap" and inline:
            try:
                _collect_importmap(json.loads(inline), document.base_url, document.scripts)
            except json.JSONDecodeError as exc:
                document.warnings.append(f"invalid importmap: {exc}")
            continue
        if src:
            document.scripts.append(
                ScriptRef(
                    url=urljoin(document.base_url, src),
                    kind="module" if script_type == "module" else "script",
                )
            )
        elif inline:
            document.scripts.append(ScriptRef(inline=inline, kind="inline", source="inline-script"))
    return document

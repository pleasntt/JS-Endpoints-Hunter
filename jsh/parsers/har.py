from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class HarResource:
    url: str
    content: str
    mime_type: str = ""
    is_html: bool = False
    source: str = ""


@dataclass
class HARData:
    resources: list[HarResource] = field(default_factory=list)
    js_urls: list[str] = field(default_factory=list)
    websocket_urls: list[str] = field(default_factory=list)
    missing_js: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _decode_content(content: dict[str, Any]) -> str:
    text = content.get("text")
    if not isinstance(text, str) or not text:
        return ""
    if content.get("encoding") == "base64":
        try:
            return base64.b64decode(text).decode("utf-8", errors="replace")
        except (ValueError, TypeError):
            return ""
    return text


def _is_javascript(url: str, mime_type: str) -> bool:
    lower_url = url.lower().split("?", 1)[0]
    lower_mime = mime_type.lower()
    return (
        "javascript" in lower_mime
        or "ecmascript" in lower_mime
        or "typescript" in lower_mime
        or lower_url.endswith((".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"))
    )


def parse_har(source: str | Path) -> HARData:
    path = Path(source)
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError) as exc:
        return HARData(errors=[f"cannot read HAR: {exc}"])
    entries = data.get("log", {}).get("entries", [])
    if not isinstance(entries, list):
        return HARData(errors=["HAR has no log.entries list"])
    result = HARData()
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        request = entry.get("request", {})
        response = entry.get("response", {})
        url = request.get("url", "") if isinstance(request, dict) else ""
        if not isinstance(url, str) or not url or url in seen:
            continue
        seen.add(url)
        if url.startswith(("ws://", "wss://")):
            result.websocket_urls.append(url)
            continue
        content = response.get("content", {}) if isinstance(response, dict) else {}
        mime_type = content.get("mimeType", "") if isinstance(content, dict) else ""
        text = _decode_content(content)
        is_html = "html" in mime_type.lower()
        if _is_javascript(url, mime_type) or is_html:
            if text:
                result.resources.append(
                    HarResource(
                        url=url,
                        content=text,
                        mime_type=mime_type,
                        is_html=is_html,
                        source=str(path),
                    )
                )
            elif _is_javascript(url, mime_type):
                result.missing_js.append(url)
        if _is_javascript(url, mime_type):
            result.js_urls.append(url)
    return result

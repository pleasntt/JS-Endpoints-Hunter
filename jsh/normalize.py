from __future__ import annotations

import html
import posixpath
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from .utils import host_of

_TEMPLATE = re.compile(r"\$\{([^}]+)\}")
_ASSET_EXT = re.compile(
    r"\.(?:css|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|mp4|webm|pdf)(?:$|\?)",
    re.IGNORECASE,
)
_NOISE_PREFIXES = (
    "data:",
    "blob:",
    "javascript:",
    "mailto:",
    "tel:",
    "chrome-extension:",
    "moz-extension:",
)


def normalize_template(value: str) -> str:
    """Turn `/users/${id}/orders` into `/users/{param}/orders`."""
    return _TEMPLATE.sub(lambda match: "{" + match.group(1) + "}", value)


def clean_literal(value: str) -> str:
    value = value.strip().strip("`'\"")
    value = value.replace("\\/", "/").replace("\\u002F", "/").replace("\\u002f", "/")
    return html.unescape(value)


def is_noise(value: str, keep_assets: bool = False) -> bool:
    if not value or len(value) > 4000:
        return True
    lowered = value.lower()
    if lowered.startswith(_NOISE_PREFIXES) or lowered.startswith("#"):
        return True
    if "node_modules/" in lowered or lowered.startswith("webpack://"):
        return True
    if "sourcemappingurl=data:" in lowered:
        return True
    if not keep_assets and _ASSET_EXT.search(lowered):
        return True
    return False


def resolve_url(value: str, base_url: str | None, resolve_relative: bool = True) -> str:
    value = clean_literal(value)
    if not value:
        return ""
    if value.startswith("//"):
        scheme = "https"
        if base_url:
            scheme = urlparse(base_url).scheme or "https"
        return f"{scheme}:{value}"
    lowered = value.lower()
    if lowered.startswith(("http://", "https://", "ws://", "wss://")):
        return value
    if not resolve_relative:
        return value
    if base_url:
        if value.startswith("/"):
            return urljoin(base_url, value)
        if not value.startswith(("/", "#", "?")):
            return urljoin(base_url, value)
    return value


def _normalize_absolute(value: str) -> str:
    parsed = urlparse(value)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    if ":" in netloc:
        host, port = netloc.rsplit(":", 1)
        if (scheme == "http" and port == "80") or (scheme == "https" and port == "443"):
            netloc = host
    path = re.sub(r"/{2,}", "/", parsed.path or "/")
    if path != "/":
        path = path.rstrip("/")
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    pairs.sort(key=lambda item: (item[0], item[1]))
    query = urlencode(pairs, doseq=True)
    return urlunparse((scheme, netloc, path, "", query, ""))


def normalize_endpoint(
    value: str,
    base_url: str | None = None,
    resolve_relative: bool = True,
    keep_assets: bool = False,
) -> str:
    value = normalize_template(clean_literal(value))
    if not value or is_noise(value, keep_assets=keep_assets):
        return ""
    value = resolve_url(value, base_url, resolve_relative=resolve_relative)
    lowered = value.lower()
    if lowered.startswith(("http://", "https://")):
        return _normalize_absolute(value)
    if lowered.startswith(("ws://", "wss://")):
        return _normalize_websocket(value)
    value = value.split("#", 1)[0]
    path, _, query = value.partition("?")
    path = re.sub(r"/{2,}", "/", path)
    if path != "/":
        path = path.rstrip("/")
    pairs = parse_qsl(query, keep_blank_values=True)
    pairs.sort(key=lambda item: (item[0], item[1]))
    return path + (("?" + urlencode(pairs)) if pairs else "")


def _normalize_websocket(value: str) -> str:
    parsed = urlparse(value)
    netloc = parsed.netloc.lower()
    if ":" in netloc:
        host, port = netloc.rsplit(":", 1)
        if (parsed.scheme.lower() == "ws" and port == "80") or (
            parsed.scheme.lower() == "wss" and port == "443"
        ):
            netloc = host
    path = re.sub(r"/{2,}", "/", parsed.path or "/")
    if path != "/":
        path = path.rstrip("/")
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    pairs.sort(key=lambda item: (item[0], item[1]))
    query = urlencode(pairs, doseq=True)
    return urlunparse((parsed.scheme.lower(), netloc, path, "", query, ""))


def canonical_key(value: str, method: str = "") -> str:
    return f"{(method or '').upper()}|{value.lower()}"


def classify(value: str) -> str:
    lowered = value.lower()
    if lowered.startswith(("ws://", "wss://")):
        return "websocket"
    if "/graphql" in lowered:
        return "graphql"
    if lowered.startswith(("http://", "https://")):
        return "absolute"
    if lowered.endswith((".json", ".xml", ".map")):
        return "file"
    return "path"


def top_prefixes(values: list[str], limit: int = 10) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for value in values:
        path = (
            urlparse(value).path
            if value.startswith(("http://", "https://", "ws://", "wss://"))
            else value.split("?", 1)[0]
        )
        bits = [bit for bit in path.split("/") if bit]
        if not bits:
            continue
        prefix = "/" + "/".join(bits[:2]) + "/"
        counts[prefix] = counts.get(prefix, 0) + 1
    return [
        {"prefix": key, "count": count}
        for key, count in sorted(counts.items(), key=lambda x: (-x[1], x[0]))[:limit]
    ]


def host_from(value: str, base_url: str | None = None) -> str:
    host = host_of(value)
    if host:
        return host
    if base_url:
        return host_of(base_url)
    return ""


def join_and_normalize(path: str, base_url: str | None) -> str:
    return posixpath.normpath(path) if path and not path.startswith("http") else path

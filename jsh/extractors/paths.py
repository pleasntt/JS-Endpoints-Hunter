from __future__ import annotations

from ..models import Finding
from ..normalize import normalize_endpoint
from ..patterns import PatternSet
from .base import endpoint_meta, match_context


def extract_paths(
    text: str, base_url: str | None, source: str, origin: str, patterns: PatternSet
) -> list[Finding]:
    return _extract(text, base_url, source, origin, patterns.paths)


def _extract(
    text: str, base_url: str | None, source: str, origin: str, patterns: list
) -> list[Finding]:
    findings: list[Finding] = []
    for pattern in patterns:
        for match in pattern.regex.finditer(text):
            context = match_context(text, match, pattern)
            if context is None:
                continue
            normalized = normalize_endpoint(context.value, base_url=base_url)
            if not normalized:
                continue
            kind = pattern.kind
            if kind == "path" and normalized.startswith(("http://", "https://")):
                kind = "rest"
            findings.append(
                Finding(
                    kind=kind,
                    value=normalized,
                    method=context.method,
                    source=source,
                    line=context.line,
                    snippet=context.snippet,
                    confidence=max(1, min(99, pattern.confidence)),
                    origin=origin,
                    meta=endpoint_meta(context.value, base_url),
                )
            )
    return findings

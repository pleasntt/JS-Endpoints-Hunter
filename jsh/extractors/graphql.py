from __future__ import annotations

from ..models import Finding
from ..patterns import PatternSet
from ..utils import truncate
from .base import line_of, snippet_of


def extract_graphql(
    text: str,
    base_url: str | None,
    source: str,
    origin: str,
    patterns: PatternSet,
) -> list[Finding]:
    findings: list[Finding] = []
    for pattern in patterns.graphql:
        for match in pattern.regex.finditer(text):
            value = match.group(1) if match.groups() else match.group(0)
            if not value:
                continue
            findings.append(
                Finding(
                    kind="graphql",
                    value=truncate(" ".join(value.split()), 240),
                    method="POST",
                    source=source,
                    line=line_of(text, match.start()),
                    snippet=truncate(snippet_of(text, match.start(), match.end()), 200),
                    confidence=pattern.confidence,
                    origin=origin,
                    meta={"host": base_url or "", "graphql": True},
                )
            )
    return findings

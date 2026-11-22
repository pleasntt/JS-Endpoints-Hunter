from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

from ..models import Finding
from ..patterns import Pattern, PatternSet
from ..utils import decode_jwt, mask_secret, truncate
from .base import line_of, snippet_of


def _secret_patterns(patterns: PatternSet) -> list[Pattern]:
    return patterns.secrets


def extract_secrets(
    text: str,
    base_url: str | None,
    source: str,
    origin: str,
    patterns: PatternSet,
) -> list[Finding]:
    findings: list[Finding] = []
    for pattern in _secret_patterns(patterns):
        group = pattern.value_group or 1
        for match in pattern.regex.finditer(text):
            if group > len(match.groups()):
                continue
            raw = match.group(group)
            if not raw or len(raw) < 8:
                continue
            secret_type = pattern.secret_type or pattern.name
            masked = mask_secret(raw, secret_type)
            meta: dict[str, Any] = {"host": base_url or ""}
            if "jwt" in secret_type:
                meta["jwt"] = decode_jwt(raw)
            findings.append(
                Finding(
                    kind="secret",
                    value=masked,
                    raw=raw,
                    masked=masked,
                    secret_type=secret_type,
                    severity=pattern.severity or "LOW",
                    source=source,
                    line=line_of(text, match.start()),
                    snippet=truncate(snippet_of(text, match.start(), match.end()), 200),
                    confidence=pattern.confidence,
                    origin=origin,
                    meta=meta,
                )
            )
    return findings


_ENTROPY_CANDIDATE = re.compile(r"['\"]([A-Za-z0-9_\-+/=]{24,120})['\"]")


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def extract_entropy_secrets(
    text: str,
    base_url: str | None,
    source: str,
    origin: str,
    known_values: set[str] | None = None,
) -> list[Finding]:
    known_values = known_values or set()
    findings: list[Finding] = []
    for match in _ENTROPY_CANDIDATE.finditer(text):
        raw = match.group(1)
        lowered = raw.lower()
        if raw in known_values or any(raw in value for value in known_values):
            continue
        if lowered.startswith(("http://", "https://", "/")):
            continue
        if any(
            token in lowered
            for token in ("function", "return", "undefined", "javascript", "webpack")
        ):
            continue
        if shannon_entropy(raw) < 4.35:
            continue
        masked = mask_secret(raw, "high_entropy")
        findings.append(
            Finding(
                kind="secret",
                value=masked,
                raw=raw,
                masked=masked,
                secret_type="high_entropy",
                severity="LOW",
                source=source,
                line=line_of(text, match.start()),
                snippet=truncate(snippet_of(text, match.start(), match.end()), 200),
                confidence=32,
                origin=origin,
                meta={"host": base_url or "", "entropy": round(shannon_entropy(raw), 2)},
            )
        )
    return findings

from __future__ import annotations

from ..constants import extract_constants, resolve_placeholders
from ..models import Finding
from ..normalize import normalize_endpoint
from ..patterns import PatternSet
from .graphql import extract_graphql
from .http import extract_absolute, extract_http
from .paths import extract_paths
from .secrets import extract_entropy_secrets, extract_secrets
from .websocket import extract_websocket


def extract_all(
    text: str,
    base_url: str | None,
    source: str,
    origin: str,
    patterns: PatternSet,
    find_secrets: bool = True,
    entropy_secrets: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(extract_http(text, base_url, source, origin, patterns))
    findings.extend(extract_websocket(text, base_url, source, origin, patterns))
    findings.extend(extract_graphql(text, base_url, source, origin, patterns))
    findings.extend(extract_paths(text, base_url, source, origin, patterns))
    findings.extend(extract_absolute(text, base_url, source, origin, patterns))
    if find_secrets:
        secret_findings = extract_secrets(text, base_url, source, origin, patterns)
        findings.extend(secret_findings)
        if entropy_secrets:
            known = {item.raw for item in secret_findings if item.raw}
            findings.extend(
                extract_entropy_secrets(text, base_url, source, origin, known_values=known)
            )
    constants = extract_constants(text)
    if constants:
        for finding in findings:
            if finding.is_secret:
                continue
            original = str(finding.meta.get("original") or finding.value)
            resolved = resolve_placeholders(original, constants)
            if resolved == original:
                continue
            normalized = normalize_endpoint(resolved, base_url=base_url)
            if normalized:
                finding.value = normalized
                finding.meta["resolved_constants"] = True
                finding.confidence = min(99, finding.confidence + 2)
    return findings

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from .utils import now_iso, redact_text, sha256_text


@dataclass
class Finding:
    kind: str
    value: str
    method: str = ""
    source: str = ""
    line: int = 0
    snippet: str = ""
    confidence: int = 50
    severity: str = ""
    secret_type: str = ""
    raw: str = ""
    masked: str = ""
    origin: str = "minified"
    meta: dict[str, Any] = field(default_factory=dict)
    fingerprint: str = ""
    occurrences: int = 1

    def __post_init__(self) -> None:
        self.kind = self.kind.lower()
        self.method = (self.method or "").upper()
        if self.kind == "secret":
            self.masked = self.masked or self.value
            self.value = self.masked
            if not self.raw:
                self.raw = ""
        if not self.fingerprint:
            material = f"{self.kind}|{self.method}|{self.value}|{self.source}|{self.line}"
            self.fingerprint = hashlib.sha256(material.encode()).hexdigest()[:16]

    @property
    def is_secret(self) -> bool:
        return self.kind == "secret"

    def display_value(self, show_secrets: bool = False) -> str:
        if self.is_secret and not show_secrets:
            return self.masked or "***"
        if self.is_secret:
            return self.raw or self.value
        return self.value

    def safe_snippet(self, show_secrets: bool = False) -> str:
        if self.is_secret and not show_secrets and self.raw:
            return redact_text(self.snippet, self.raw, self.masked)
        return self.snippet

    def to_dict(self, show_secrets: bool = False) -> dict[str, Any]:
        is_secret = self.is_secret
        value = self.display_value(show_secrets)
        meta = dict(self.meta)
        if is_secret and not show_secrets:
            meta.pop("jwt", None)
        return {
            "kind": self.kind,
            "value": value,
            "raw": self.raw if is_secret and show_secrets else "",
            "method": self.method,
            "source": self.source,
            "line": self.line,
            "snippet": self.safe_snippet(show_secrets),
            "confidence": self.confidence,
            "severity": self.severity,
            "secret_type": self.secret_type,
            "masked": self.masked if is_secret else "",
            "origin": self.origin,
            "meta": meta,
            "fingerprint": self.fingerprint,
            "occurrences": self.occurrences,
            "host": self.meta.get("host", ""),
        }


@dataclass
class RawFile:
    name: str
    url: str
    content: str
    content_type: str = ""
    origin: str = "network"
    sha256: str = ""
    map_url: str = ""

    def __post_init__(self) -> None:
        if not self.sha256:
            self.sha256 = sha256_text(self.content)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "url": self.url,
            "content_type": self.content_type,
            "origin": self.origin,
            "sha256": self.sha256,
            "size": len(self.content.encode("utf-8", errors="replace")),
            "map_url": self.map_url,
        }


@dataclass
class Dependency:
    name: str
    version: str
    source: str = ""
    cve_search: str = ""

    def __post_init__(self) -> None:
        if not self.cve_search:
            query = f"{self.name} {self.version}".strip()
            from urllib.parse import quote_plus

            self.cve_search = "https://nvd.nist.gov/vuln/search/results?query=" + quote_plus(query)


@dataclass
class ScanSettings:
    timeout: float = 10.0
    concurrency: int = 10
    rate_limit: float = 5.0
    download_maps: bool = True
    find_secrets: bool = True
    show_secrets: bool = False
    resolve_relative: bool = True
    include_vendor: bool = False
    keep_assets: bool = False
    proxy: str = ""
    user_agent: str = ""
    max_bytes: int = 8 * 1024 * 1024
    entropy_secrets: bool = False
    allowlist_file: str = ""
    harvest_maps: bool = True


def empty_stats() -> dict[str, Any]:
    return {
        "files": 0,
        "bytes": 0,
        "endpoints": 0,
        "secrets": 0,
        "hosts": 0,
        "by_type": {},
        "by_severity": {},
        "top_prefixes": [],
    }


@dataclass
class ScanResult:
    input_type: str
    target: str
    scan_id: int = 0
    status: str = "running"
    started_at: str = field(default_factory=now_iso)
    finished_at: str = ""
    findings: list[Finding] = field(default_factory=list)
    raw_files: list[RawFile] = field(default_factory=list)
    dependencies: list[Dependency] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=empty_stats)
    artifacts: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    options: dict[str, Any] = field(default_factory=dict)

    def finish(self, status: str = "completed", error: str = "") -> None:
        self.status = status
        self.finished_at = now_iso()
        if error:
            self.errors.append(error)

    def to_dict(self, show_secrets: bool = False) -> dict[str, Any]:
        findings = [f.to_dict(show_secrets) for f in self.findings]
        if not show_secrets:
            # A snippet for a non-secret finding may sit next to a secret line.
            # Redact every known raw secret across the whole payload.
            pairs = [(f.raw, f.masked) for f in self.findings if f.is_secret and f.raw and f.masked]
            if pairs:
                serialized = json.dumps(findings, ensure_ascii=False)
                for raw, masked in pairs:
                    serialized = serialized.replace(raw, masked)
                findings = json.loads(serialized)
        return {
            "scan_id": self.scan_id,
            "input_type": self.input_type,
            "target": self.target,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "findings": findings,
            "raw_files": [r.to_dict() for r in self.raw_files],
            "dependencies": [
                {
                    "name": d.name,
                    "version": d.version,
                    "source": d.source,
                    "cve_search": d.cve_search,
                }
                for d in self.dependencies
            ],
            "hosts": self.hosts,
            "stats": self.stats,
            "artifacts": self.artifacts,
            "errors": self.errors,
            "options": self.options,
        }

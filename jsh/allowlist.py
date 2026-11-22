from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .models import Finding


@dataclass
class Allowlist:
    patterns: list[re.Pattern[str]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: str | Path | None) -> Allowlist:
        result = cls()
        if not path:
            return result
        file_path = Path(path).expanduser()
        if not file_path.is_file():
            result.errors.append(f"allowlist not found: {file_path}")
            return result
        try:
            lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            result.errors.append(f"allowlist: {exc}")
            return result
        for line in lines:
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            try:
                result.patterns.append(re.compile(value, re.IGNORECASE))
            except re.error as exc:
                result.errors.append(f"allowlist pattern {value!r}: {exc}")
        return result

    def matches(self, finding: Finding) -> bool:
        haystack = "\n".join(
            part
            for part in (
                finding.value,
                finding.raw,
                finding.source,
                finding.secret_type,
                finding.meta.get("host", ""),
            )
            if part
        )
        return any(pattern.search(haystack) for pattern in self.patterns)

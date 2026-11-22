from __future__ import annotations

import re

_ASSIGN = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(['\"`])((?:\\.|(?!\2).)*?)\2",
    re.MULTILINE,
)
_PLACEHOLDER = re.compile(r"\$?\{([A-Za-z_$][\w$]*)\}")


def extract_constants(text: str) -> dict[str, str]:
    constants: dict[str, str] = {}
    for match in _ASSIGN.finditer(text):
        name, value = match.group(1), match.group(3)
        if not name or not value or len(value) > 500:
            continue
        if "${" in value or "\n" in value:
            continue
        constants[name] = value
    return constants


def resolve_placeholders(value: str, constants: dict[str, str]) -> str:
    if not value or not constants:
        return value

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        return constants.get(name, match.group(0))

    return _PLACEHOLDER.sub(replace, value)

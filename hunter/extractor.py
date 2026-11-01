"""
Модуль извлечения эндпоинтов и секретов из JavaScript-кода.

Содержит класс EndpointExtractor с двумя основными методами:
    - find_endpoints(text) -> set[str]
    - find_secrets(text)   -> dict[str, set[str]]
"""

from __future__ import annotations

import re
from typing import Dict, Set

# --------------------------------------------------------------------------- #
#                        РЕГУЛЯРНЫЕ ВЫРАЖЕНИЯ: ЭНДПОИНТЫ
# --------------------------------------------------------------------------- #

# 1) Полные URL: http(s)://..., ws(s)://...
_RE_FULL_URL = re.compile(
    r"""\b(?:https?|wss?)://[\w\-\.]+(?::\d+)?(?:/[^\s"'`<>\)\]]*)?""",
    re.IGNORECASE,
)

# 2) Пути, начинающиеся с "/" (но не "//" — это комментарий в JS и не URL-путь).
#    Исключаем типичные ложные срабатывания: регулярки, куски вида "/g", "/*",
#    одиночные слэши, а также очень короткие строки.
_RE_PATH = re.compile(
    r"""(?<![\w:/])/(?![\*/])[\w\-\.~%/]{2,}""",
    re.IGNORECASE,
)

# 3) Строки внутри fetch('...'), axios.get('...'), axios.post('...'),
#    $.ajax('...'), $.get('...'), $.post('...'), new URL('...'),
#    XMLHttpRequest.open('GET', '...') и т.п.
_RE_CALL_ARG = re.compile(
    r"""
    (?:
        fetch
      | axios\.(?:get|post|put|patch|delete|request)
      | \$\.(?:get|post|ajax|getJSON)
      | new\s+URL
      | \.open
    )
    \s*\(\s*
    ['"`](?P<url>[^'"`\s]{2,})['"`]
    """,
    re.VERBOSE | re.IGNORECASE,
)

# 4) Строковые литералы, похожие на API-путь: "/api/...", "/v1/...", "/users/..."
#    Ловит пути в конфигах вида { baseUrl: "/api/v1" } и подобных.
_RE_QUOTED_PATH = re.compile(
    r"""['"`]((?:/|\bapi/|/api/|/v\d+/)[\w\-\.~%/]{2,})['"`]""",
    re.IGNORECASE,
)

# --------------------------------------------------------------------------- #
#                         РЕГУЛЯРНЫЕ ВЫРАЖЕНИЯ: СЕКРЕТЫ
# --------------------------------------------------------------------------- #

_PATTERNS_SECRETS: Dict[str, re.Pattern[str]] = {
    # AWS Access Key ID — начинается на AKIA / ASIA / AGPA / AIDA / AROA / AIPA / ANPA / ANVA
    "AWS Access Key": re.compile(
        r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b"
    ),
    # JWT — три base64url-сегмента, разделённые точками, начинаются с "eyJ"
    "JWT Token": re.compile(
        r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"
    ),
    # Google API key — AIza + 35 символов
    "Google API Key": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    # Bearer-токен в строке: "Bearer xxx" (токен минимум 20 символов)
    "Bearer Token": re.compile(r"\bBearer\s+([A-Za-z0-9\-\._~\+/]{20,}=*)"),
    # Slack token
    "Slack Token": re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b"),
    # Приватные ключи в PEM-обёртке (RSA/EC/DSA/OPENSSH)
    "Private Key (PEM)": re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    ),
    # Stripe live-ключи
    "Stripe Secret Key": re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"),
    # GitHub tokens (classic PAT)
    "GitHub Token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
}


class EndpointExtractor:
    """Извлекает эндпоинты и секреты из произвольного текста (JS-кода)."""

    def __init__(self, min_path_len: int = 3) -> None:
        """
        :param min_path_len: минимальная длина пути (без учёта ведущего "/"),
                             чтобы отсеять мусор вида "/a" и "/x".
        """
        self.min_path_len = min_path_len

    # ------------------------------------------------------------------ #
    #                            ЭНДПОИНТЫ
    # ------------------------------------------------------------------ #
    def find_endpoints(self, text: str) -> Set[str]:
        """Возвращает множество уникальных эндпоинтов, найденных в тексте."""
        if not text:
            return set()

        found: Set[str] = set()

        # 1. Полные URL
        for m in _RE_FULL_URL.finditer(text):
            url = m.group(0).rstrip(".,;)]}\"'`")
            found.add(url)

        # 2. Пути внутри fetch(), axios.get(), $.ajax() и т.п.
        for m in _RE_CALL_ARG.finditer(text):
            url = m.group("url").strip()
            if self._is_valid_path(url):
                found.add(url)

        # 3. Пути в строковых литералах, начинающиеся с "/" или "api/"
        for m in _RE_QUOTED_PATH.finditer(text):
            path = m.group(1).strip()
            if self._is_valid_path(path):
                found.add(path)

        # 4. Общее сканирование на "сырые" пути /api/...
        for m in _RE_PATH.finditer(text):
            path = m.group(0).rstrip(".,;)\"'`")
            if self._is_valid_path(path):
                found.add(path)

        return found

    # ------------------------------------------------------------------ #
    #                             СЕКРЕТЫ
    # ------------------------------------------------------------------ #
    def find_secrets(self, text: str) -> Dict[str, Set[str]]:
        """
        Возвращает словарь: {тип_секрета: {найденные_значения}}.
        Пустые значения отфильтрованы.
        """
        if not text:
            return {}

        results: Dict[str, Set[str]] = {}

        for name, pattern in _PATTERNS_SECRETS.items():
            matches: Set[str] = set()
            for m in pattern.finditer(text):
                # Если в паттерне есть группа — берём её, иначе всё совпадение
                value = m.group(1) if m.groups() else m.group(0)
                value = value.strip()
                if value and not self._is_placeholder(value):
                    matches.add(value)
            if matches:
                results[name] = matches

        return results

    # ------------------------------------------------------------------ #
    #                             ХЕЛПЕРЫ
    # ------------------------------------------------------------------ #
    def _is_valid_path(self, path: str) -> bool:
        """Фильтр для путей: длина, отсутствие очевидного мусора."""
        if not path or len(path) < self.min_path_len:
            return False
        # Путь должен содержать хотя бы одну букву (не только "/1/2/3")
        if not re.search(r"[A-Za-z]", path):
            return False
        # Отсекаем типичные JS-паттерны: "/*", "*/", "//", "/g", "/i" (флаги regex)
        if path in {"/*", "*/", "//", "/g", "/i", "/m", "/u", "/s", "/y"}:
            return False
        # Отсекаем шум: пути из одних точек/дефисов
        if re.fullmatch(r"[/\.\-_]+", path):
            return False
        return True

    @staticmethod
    def _is_placeholder(value: str) -> bool:
        """Отсекает очевидные заглушки: your_api_key, xxx, changeme и т.п."""
        lowered = value.lower()
        placeholders = (
            "your_",
            "your-",
            "xxxxxxxx",
            "changeme",
            "example",
            "dummy",
            "placeholder",
            "test_key",
        )
        return any(p in lowered for p in placeholders)
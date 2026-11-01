"""
Модуль получения JavaScript-исходников: HTTP(S), локальные файлы и папки.

Публичный интерфейс:
    - JSFetcher.fetch_url(url)          -> str | None
    - JSFetcher.fetch_file(path)        -> str | None
    - JSFetcher.fetch_directory(dir)    -> dict[str, str]
    - JSFetcher.collect(source)         -> dict[str, str]   (авто-режим)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, Optional

import requests

logger = logging.getLogger(__name__)

# Расширения JS-подобных файлов, которые ищем в директории
_JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".jsx"}

_DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


class JSFetcher:
    """Загружает JS-содержимое из URL, файлов и директорий."""

    def __init__(
        self,
        timeout: float = 15.0,
        max_size: int = 5 * 1024 * 1024,
        user_agent: str = _DEFAULT_UA,
        verify_ssl: bool = True,
    ) -> None:
        """
        :param timeout:    таймаут HTTP-запроса (сек)
        :param max_size:   максимальный размер файла (байт), по умолчанию 5 МБ
        :param user_agent: User-Agent для HTTP-запросов
        :param verify_ssl: проверять SSL-сертификат (для багбаунти иногда
                           выключают: verify_ssl=False)
        """
        self.timeout = timeout
        self.max_size = max_size
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": user_agent,
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.9",
            }
        )

    # ------------------------------------------------------------------ #
    #                                URL
    # ------------------------------------------------------------------ #
    def fetch_url(self, url: str) -> Optional[str]:
        """Скачивает JS-файл по URL. Возвращает текст или None при ошибке."""
        try:
            resp = self.session.get(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True,
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            logger.warning("Не удалось скачать %s: %s", url, exc)
            return None

        # Проверка размера (заголовок + фактическое тело)
        cl = resp.headers.get("Content-Length", "")
        if cl.isdigit() and int(cl) > self.max_size:
            logger.warning(
                "Файл %s больше лимита (%d байт), пропускаю", url, self.max_size
            )
            return None
        if len(resp.content) > self.max_size:
            logger.warning(
                "Файл %s больше лимита (%d байт), пропускаю", url, self.max_size
            )
            return None

        if self._is_binary(resp.content):
            logger.warning("%s не похож на текст (бинарные данные)", url)
            return None

        try:
            return resp.content.decode(resp.encoding or "utf-8", errors="replace")
        except LookupError:
            return resp.content.decode("utf-8", errors="replace")

    # ------------------------------------------------------------------ #
    #                          ЛОКАЛЬНЫЙ ФАЙЛ
    # ------------------------------------------------------------------ #
    def fetch_file(self, path: str | Path) -> Optional[str]:
        """Читает локальный файл. Возвращает текст или None при ошибке."""
        p = Path(path).expanduser()
        if not p.is_file():
            logger.warning("Файл не найден: %s", p)
            return None
        try:
            return p.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("Не удалось прочитать %s: %s", p, exc)
            return None

    # ------------------------------------------------------------------ #
    #                         ЛОКАЛЬНАЯ ПАПКА
    # ------------------------------------------------------------------ #
    def fetch_directory(self, dir_path: str | Path) -> Dict[str, str]:
        """
        Рекурсивно читает все JS-файлы в директории.
        Возвращает {относительный_путь: содержимое}.
        """
        root = Path(dir_path).expanduser()
        result: Dict[str, str] = {}

        if not root.is_dir():
            logger.warning("Директория не найдена: %s", root)
            return result

        for file in root.rglob("*"):
            if not file.is_file() or file.suffix.lower() not in _JS_EXTENSIONS:
                continue
            try:
                text = file.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                logger.warning("Не удалось прочитать %s: %s", file, exc)
                continue
            result[str(file.relative_to(root))] = text
            logger.debug("Прочитан %s (%d симв.)", file, len(text))

        return result

    # ------------------------------------------------------------------ #
    #                        УНИВЕРСАЛЬНЫЙ ВХОД
    # ------------------------------------------------------------------ #
    def collect(self, source: str) -> Dict[str, str]:
        """
        Авто-определяет тип источника и возвращает {имя: текст}.

        - URL (http:// или https://) → скачивание
        - Путь к файлу               → чтение файла
        - Путь к директории          → рекурсивное чтение JS-файлов
        """
        source = source.strip()
        if not source:
            return {}

        if source.startswith(("http://", "https://")):
            text = self.fetch_url(source)
            return {source: text} if text is not None else {}

        p = Path(source).expanduser()
        if p.is_file():
            text = self.fetch_file(p)
            return {str(p): text} if text is not None else {}
        if p.is_dir():
            return self.fetch_directory(p)

        logger.warning(
            "Источник не распознан (не URL, не файл, не папка): %s", source
        )
        return {}

    # ------------------------------------------------------------------ #
    #                              ХЕЛПЕРЫ
    # ------------------------------------------------------------------ #
    @staticmethod
    def _is_binary(content: bytes) -> bool:
        """Грубая проверка на бинарные данные: наличие нулевого байта."""
        if not content:
            return False
        return b"\x00" in content[:1024]
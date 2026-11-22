from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx

from .cache import Cache
from .models import ScanSettings
from .utils import USER_AGENT


@dataclass
class FetchResult:
    url: str
    final_url: str = ""
    status: int = 0
    content: str = ""
    content_type: str = ""
    error: str = ""
    from_cache: bool = False
    truncated: bool = False
    headers: dict[str, str] = field(default_factory=dict)


class RateLimiter:
    def __init__(self, per_second: float) -> None:
        self.per_second = max(per_second, 0.1)
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def wait(self, host: str) -> None:
        while True:
            async with self._lock:
                now = time.monotonic()
                events = self._events[host]
                while events and now - events[0] >= 1.0:
                    events.popleft()
                if len(events) < self.per_second:
                    events.append(now)
                    return
                sleep_for = max(0.0, 1.0 - (now - events[0]))
            await asyncio.sleep(sleep_for)


class Fetcher:
    def __init__(self, settings: ScanSettings, cache: Cache) -> None:
        self.settings = settings
        self.cache = cache
        self.limiter = RateLimiter(settings.rate_limit)
        self.client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> Fetcher:
        headers = {
            "User-Agent": self.settings.user_agent or USER_AGENT,
            "Accept": "text/html,application/javascript,application/json,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
        }
        kwargs: dict[str, Any] = {
            "headers": headers,
            "follow_redirects": True,
            "timeout": httpx.Timeout(self.settings.timeout),
            "limits": httpx.Limits(
                max_connections=max(self.settings.concurrency, 4),
                max_keepalive_connections=max(self.settings.concurrency, 4),
            ),
        }
        if self.settings.proxy:
            kwargs["proxy"] = self.settings.proxy
        self.client = httpx.AsyncClient(**kwargs)
        return self

    async def __aexit__(self, *args: object) -> None:
        if self.client is not None:
            await self.client.aclose()

    async def get(self, url: str, use_cache: bool = True) -> FetchResult:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return FetchResult(url=url, error="only http(s) URLs are supported")
        if use_cache:
            cached = self.cache.get(url)
            if cached is not None:
                return FetchResult(
                    url=url, final_url=url, status=200, content=cached, from_cache=True
                )
        if self.client is None:
            return FetchResult(url=url, error="fetcher is not open")
        await self.limiter.wait(parsed.netloc)
        last_error = ""
        for attempt in range(3):
            try:
                response = await self.client.get(url)
                content_type = response.headers.get("content-type", "")
                text = response.text
                truncated = len(text.encode("utf-8", errors="replace")) > self.settings.max_bytes
                if truncated:
                    text = text[: self.settings.max_bytes]
                if response.status_code >= 500 or response.status_code == 429:
                    last_error = f"HTTP {response.status_code}"
                    if attempt < 2:
                        await asyncio.sleep(0.4 * (attempt + 1))
                        continue
                if response.status_code >= 400:
                    last_error = f"HTTP {response.status_code}"
                if response.status_code < 400 and text:
                    self.cache.put(url, text)
                return FetchResult(
                    url=url,
                    final_url=str(response.url),
                    status=response.status_code,
                    content=text,
                    content_type=content_type,
                    error=last_error,
                    truncated=truncated,
                    headers=dict(response.headers),
                )
            except (httpx.HTTPError, OSError) as exc:
                last_error = str(exc)
                if attempt < 2:
                    await asyncio.sleep(0.4 * (attempt + 1))
        return FetchResult(url=url, error=last_error or "request failed")

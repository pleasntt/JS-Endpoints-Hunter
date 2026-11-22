from __future__ import annotations

from pathlib import Path

import httpx
import respx

from jsh.cache import Cache
from jsh.models import ScanSettings
from jsh.net import Fetcher


@respx.mock
async def test_fetcher_and_cache(tmp_path: Path):
    route = respx.get("https://example.test/app.js").mock(
        return_value=httpx.Response(
            200, text='fetch("/api/v1/a")', headers={"content-type": "application/javascript"}
        )
    )
    settings = ScanSettings(timeout=2, concurrency=2, rate_limit=100)
    cache = Cache(tmp_path / "cache")
    async with Fetcher(settings, cache) as fetcher:
        first = await fetcher.get("https://example.test/app.js")
        second = await fetcher.get("https://example.test/app.js")
    assert first.status == 200
    assert "/api/v1/a" in first.content
    assert second.from_cache is True
    assert route.call_count == 1


@respx.mock
async def test_fetcher_retries_server_error(tmp_path: Path):
    route = respx.get("https://example.test/retry.js").mock(
        side_effect=[
            httpx.Response(503),
            httpx.Response(200, text="fetch('/api/v1/ok')"),
        ]
    )
    settings = ScanSettings(timeout=2, concurrency=1, rate_limit=100)
    async with Fetcher(settings, Cache(tmp_path / "cache")) as fetcher:
        result = await fetcher.get("https://example.test/retry.js", use_cache=False)
    assert result.status == 200
    assert route.call_count == 2

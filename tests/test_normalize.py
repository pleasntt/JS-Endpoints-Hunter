from __future__ import annotations

from jsh.normalize import (
    canonical_key,
    is_noise,
    normalize_endpoint,
    normalize_template,
    top_prefixes,
)


def test_template_and_query_normalization():
    assert normalize_template("/api/${id}/orders") == "/api/{id}/orders"
    assert normalize_endpoint("/api/v1/users/?b=2&a=1#frag") == "/api/v1/users?a=1&b=2"
    assert normalize_endpoint("/api/v1/users/") == "/api/v1/users"


def test_absolute_url_normalization():
    assert (
        normalize_endpoint("HTTPS://Example.COM:443/api/v1/?z=2&a=1")
        == "https://example.com/api/v1?a=1&z=2"
    )
    assert normalize_endpoint("wss://WS.Example.com:443/socket/") == "wss://ws.example.com/socket"


def test_noise_assets_and_data_uris():
    assert is_noise("data:image/png;base64,abc")
    assert is_noise("/static/logo.png")
    assert not is_noise("/static/logo.png", keep_assets=True)
    assert is_noise("webpack:///./src/index.ts")
    assert is_noise("node_modules/pkg/index.js")


def test_canonical_key_and_prefixes():
    assert canonical_key("/api/v1/x", "get") == "GET|/api/v1/x"
    prefixes = top_prefixes(["/api/v1/users", "/api/v1/orders", "/api/v2/pay"])
    assert prefixes[0] == {"prefix": "/api/v1/", "count": 2}

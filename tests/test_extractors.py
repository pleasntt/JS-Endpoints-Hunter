from __future__ import annotations

from jsh.extractors import extract_all


def vals(findings, kind=None):
    return [item for item in findings if kind is None or item.kind == kind]


def test_fetch_and_axios(patterns):
    findings = extract_all(
        'fetch("/api/v1/users"); axios.post("/api/v2/payments", {});',
        "https://example.com/static/app.js",
        "app.js",
        "minified",
        patterns,
    )
    rest = vals(findings, "rest")
    assert any(item.value.endswith("/api/v1/users") for item in rest)
    assert any(item.value.endswith("/api/v2/payments") and item.method == "POST" for item in rest)


def test_xhr_jquery_and_got(patterns):
    text = """
    xhr.open("DELETE", "/api/v1/session");
    $.ajax({url: "/api/v1/audit"});
    $.get("/api/v1/plans");
    got.get("https://cdn.example.com/config.json");
    """
    findings = extract_all(text, "https://example.com/app.js", "app.js", "minified", patterns)
    rest = vals(findings, "rest")
    assert any(item.method == "DELETE" and item.value.endswith("/session") for item in rest)
    assert any(item.method == "GET" and item.value.endswith("/config.json") for item in rest)
    assert any(item.value.endswith("/api/v1/plans") for item in rest)


def test_template_string_is_normalized(patterns):
    findings = extract_all(
        "fetch(`/api/v1/users/${id}/orders`);",
        "https://example.com/static/app.js",
        "app.js",
        "minified",
        patterns,
    )
    assert any(item.value.endswith("/api/v1/users/{id}/orders") for item in findings)


def test_relative_path_is_resolved(patterns):
    findings = extract_all(
        'fetch("api/v1/users");',
        "https://example.com/static/app.js",
        "app.js",
        "minified",
        patterns,
    )
    assert any(item.value == "https://example.com/static/api/v1/users" for item in findings)


def test_websocket_and_sse(patterns):
    findings = extract_all(
        'new WebSocket("wss://ws.example.com/socket"); new EventSource("/api/v1/events");',
        "https://example.com/app.js",
        "app.js",
        "minified",
        patterns,
    )
    assert any(
        item.kind == "websocket" and item.value == "wss://ws.example.com/socket"
        for item in findings
    )
    assert any(item.kind == "sse" and item.value.endswith("/api/v1/events") for item in findings)


def test_graphql_path_and_query(patterns):
    findings = extract_all(
        'const q = "query Billing { invoices { id } }"; const path = "/api/graphql";',
        "https://example.com/app.js",
        "app.js",
        "minified",
        patterns,
    )
    graphql = vals(findings, "graphql")
    assert any(item.value.endswith("/api/graphql") for item in graphql)
    assert any("query Billing" in item.value for item in graphql)

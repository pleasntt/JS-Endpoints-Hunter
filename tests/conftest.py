from __future__ import annotations

from pathlib import Path

import pytest

from jsh.patterns import PatternSet, load_patterns

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def patterns() -> PatternSet:
    return load_patterns(ROOT / "patterns.yaml")


@pytest.fixture
def sample_js() -> str:
    return """
    const API = "/api/v1";
    fetch(`${API}/billing/invoices`);
    axios.post("/api/v2/payments/charge", {amount: 10});
    const xhr = new XMLHttpRequest();
    xhr.open("DELETE", "/api/v1/sessions/current");
    $.ajax({url: "/api/v1/admin/audit"});
    $.get("/api/v1/plans");
    got.get("https://cdn.example.com/config.json");
    new WebSocket("wss://ws.example.com/socket");
    new EventSource("/api/v1/events");
    const q = "query Billing { invoices { id } }";
    const gql = "/api/graphql";
    const aws = "AKIAABCDEFGHIJKLMNOP";
    const stripe = "sk_test_" + "000000000000000000000000";
    const token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature";
    """

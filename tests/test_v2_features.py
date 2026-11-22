from __future__ import annotations

import json
from pathlib import Path

from jsh.allowlist import Allowlist
from jsh.extractors import extract_all
from jsh.extractors.secrets import extract_entropy_secrets
from jsh.models import Finding, RawFile, ScanResult
from jsh.parsers.har import parse_har
from jsh.parsers.sourcemap import parse_source_map
from jsh.report import generate_report


def test_constants_are_resolved_before_normalization(patterns):
    text = 'const API = "/api/v1"; fetch(`${API}/billing/invoices`);'
    findings = extract_all(
        text, "https://example.com/static/app.js", "app.js", "minified", patterns
    )
    values = {item.value for item in findings}
    assert "https://example.com/api/v1/billing/invoices" in values


def test_worker_openapi_and_graphql_markers(patterns):
    text = """
    new Worker("/worker.js");
    navigator.serviceWorker.register("/sw.js");
    importScripts("/legacy.js");
    const spec = "/openapi.json";
    const introspection = "__schema";
    """
    findings = extract_all(text, "https://example.com/app.js", "app.js", "minified", patterns)
    kinds = {item.kind for item in findings}
    assert "worker" in kinds
    assert "openapi" in kinds
    assert "graphql" in kinds


def test_source_map_sections():
    payload = {
        "version": 3,
        "sections": [
            {
                "offset": {"line": 0, "column": 0},
                "map": {
                    "version": 3,
                    "sources": ["src/a.ts"],
                    "sourcesContent": ['fetch("/api/v1/section")'],
                },
            }
        ],
    }
    parsed = parse_source_map(json.dumps(payload), "app.js.map")
    assert parsed.sources[0].name == "src/a.ts"
    assert "/api/v1/section" in parsed.sources[0].content


def test_har_websocket_urls(tmp_path: Path):
    har = {
        "log": {
            "entries": [
                {
                    "request": {"url": "wss://ws.example.com/socket"},
                    "response": {"content": {"mimeType": "text/plain", "text": ""}},
                }
            ]
        }
    }
    path = tmp_path / "ws.har"
    path.write_text(json.dumps(har), encoding="utf-8")
    data = parse_har(path)
    assert data.websocket_urls == ["wss://ws.example.com/socket"]


def test_entropy_heuristic():
    text = 'const opaque = "Q2x7vN4pR8sT1uW6yZ3aB5cD9eF0gH2j";'
    findings = extract_entropy_secrets(text, "https://example.com/app.js", "app.js", "minified")
    assert findings
    assert findings[0].secret_type == "high_entropy"
    assert findings[0].raw not in findings[0].to_dict(False)["snippet"]


def test_allowlist(tmp_path: Path):
    path = tmp_path / "allowlist.txt"
    path.write_text("cdn\\.example\\.com\n", encoding="utf-8")
    allowlist = Allowlist.load(path)
    assert allowlist.matches(Finding(kind="rest", value="https://cdn.example.com/a.js"))
    assert not allowlist.matches(Finding(kind="rest", value="https://api.example.com/a.js"))


def test_sarif_and_jsonl_artifacts(tmp_path: Path):
    result = ScanResult(
        input_type="url",
        target="https://example.com/app.js",
        scan_id=1,
        findings=[
            Finding(
                kind="secret",
                value="AKIA****************",
                raw="AKIAABCDEFGHIJKLMNOP",
                masked="AKIA****************",
                secret_type="aws_access_key",
                severity="HIGH",
                source="app.js:src/app.ts",
                line=2,
            )
        ],
        raw_files=[
            RawFile(
                name="app.js",
                url="https://example.com/app.js",
                content="const key = 'AKIAABCDEFGHIJKLMNOP'",
            )
        ],
    )
    result.finish("completed")
    artifacts = generate_report(result, tmp_path / "out")
    sarif = json.loads((tmp_path / "out" / artifacts["report.sarif"]).read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["level"] == "error"
    uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ]
    assert uri == "app.js"
    lines = (
        (tmp_path / "out" / artifacts["findings.jsonl"]).read_text(encoding="utf-8").splitlines()
    )
    assert len(lines) == 1
    assert "AKIAABCDEFGHIJKLMNOP" not in lines[0]

from __future__ import annotations

import json
from pathlib import Path

from jsh.models import Finding, RawFile, ScanResult
from jsh.report import generate_report
from jsh.storage import Storage


def make_result(scan_id: int, target: str, endpoint: str, secret: str = "") -> ScanResult:
    result = ScanResult(input_type="url", target=target, scan_id=scan_id)
    result.findings.append(
        Finding(
            kind="rest",
            value=endpoint,
            method="GET",
            source="https://example.com/app.js",
            line=3,
            snippet=f'fetch("{endpoint}")',
            confidence=90,
        )
    )
    if secret:
        result.findings.append(
            Finding(
                kind="secret",
                value="AKIA****************",
                raw=secret,
                masked="AKIA****************",
                secret_type="aws_access_key",
                severity="HIGH",
                source="https://example.com/app.js",
                line=4,
                snippet=f'const key = "{secret}"',
            )
        )
        result.raw_files.append(
            RawFile(
                name="app.js",
                url="https://example.com/app.js",
                content=f'const key = "{secret}"; fetch("{endpoint}");',
            )
        )
    result.finish("completed")
    return result


def test_storage_roundtrip_and_diff(tmp_path: Path):
    storage = Storage(tmp_path / "history.sqlite")
    first_id = storage.create_scan("url", "https://example.com/app.js", {})
    first = make_result(first_id, "https://example.com/app.js", "/api/v1/a")
    storage.save_result(first)
    loaded = storage.get_scan(first_id)
    assert loaded is not None
    assert loaded["scan"]["status"] == "completed"
    assert loaded["findings"][0]["value"] == "/api/v1/a"
    assert storage.list_scans()[0]["id"] == first_id

    second_id = storage.create_scan("url", "https://example.com/v2.js", {})
    second = make_result(second_id, "https://example.com/v2.js", "/api/v1/b")
    storage.save_result(second)
    diff = storage.diff_scans(first_id, second_id)
    assert [item["value"] for item in diff["added"]] == ["/api/v1/b"]
    assert storage.delete_scan(second_id)
    assert storage.get_scan(second_id) is None


def test_cross_finding_snippet_redaction():
    result = ScanResult(input_type="url", target="https://example.com/app.js", scan_id=1)
    result.findings.append(
        Finding(
            kind="rest",
            value="/api/v1/a",
            method="GET",
            source="app.js",
            line=2,
            snippet='const key = "AKIAABCDEFGHIJKLMNOP"; fetch("/api/v1/a")',
        )
    )
    result.findings.append(
        Finding(
            kind="secret",
            value="AKIA****************",
            raw="AKIAABCDEFGHIJKLMNOP",
            masked="AKIA****************",
            secret_type="aws_access_key",
            severity="HIGH",
            source="app.js",
            line=2,
            snippet='const key = "AKIAABCDEFGHIJKLMNOP"',
        )
    )
    payload = result.to_dict(show_secrets=False)
    assert "AKIAABCDEFGHIJKLMNOP" not in json.dumps(payload, ensure_ascii=False)
    assert "AKIA****************" in payload["findings"][0]["snippet"]


def test_report_artifacts_and_masking(tmp_path: Path):
    result = make_result(0, "https://example.com/app.js", "/api/v1/a", "AKIAABCDEFGHIJKLMNOP")
    result.scan_id = 7
    artifacts = generate_report(result, tmp_path / "report", show_secrets=False)
    assert artifacts["report.html"] == "report.html"
    assert (tmp_path / "report" / "report.json").exists()
    assert (tmp_path / "report" / "endpoints.txt").read_text().strip() == "/api/v1/a"
    assert (tmp_path / "report" / "endpoints.csv").read_text().startswith("path,method,type")
    assert "AKIA****************" in (tmp_path / "report" / "secrets.txt").read_text()
    report_json = json.loads((tmp_path / "report" / "report.json").read_text())
    assert report_json["findings"][1]["raw"] == ""
    raw_text = (tmp_path / "report" / "raw" / "app.js").read_text()
    assert "AKIAABCDEFGHIJKLMNOP" not in raw_text
    assert "AKIA****************" in raw_text
    html_text = (tmp_path / "report" / "report.html").read_text(encoding="utf-8")
    assert "AKIAABCDEFGHIJKLMNOP" not in html_text
    assert "JS-Endpoints-Hunter" in html_text


def test_report_show_secrets_opt_in(tmp_path: Path):
    result = make_result(0, "https://example.com/app.js", "/api/v1/a", "AKIAABCDEFGHIJKLMNOP")
    generate_report(result, tmp_path / "raw", show_secrets=True)
    assert "AKIAABCDEFGHIJKLMNOP" in (tmp_path / "raw" / "raw" / "app.js").read_text()

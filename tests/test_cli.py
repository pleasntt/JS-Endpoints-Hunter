from __future__ import annotations

import json
from argparse import Namespace
from pathlib import Path

from jsh.cli import cmd_diff, cmd_report, main

ROOT = Path(__file__).resolve().parents[1]


def report_payload(target: str, path: str) -> dict:
    return {
        "scan_id": 1,
        "input_type": "url",
        "target": target,
        "status": "completed",
        "findings": [
            {
                "kind": "rest",
                "value": path,
                "method": "GET",
                "source": target,
                "line": 1,
                "confidence": 90,
            }
        ],
        "hosts": ["example.com"],
        "stats": {},
    }


def test_report_and_diff_commands(tmp_path: Path, capsys):
    left = tmp_path / "left.json"
    right = tmp_path / "right.json"
    left.write_text(json.dumps(report_payload("https://example.com/a", "/api/a")), encoding="utf-8")
    right.write_text(
        json.dumps(report_payload("https://example.com/b", "/api/b")), encoding="utf-8"
    )
    assert cmd_report(Namespace(path=str(left), format="md", output=None)) == 0
    output = capsys.readouterr().out
    assert "/api/a" in output
    assert cmd_diff(Namespace(left=str(left), right=str(right), format="text")) == 0
    output = capsys.readouterr().out
    assert "+ GET|/api/b" in output
    assert "- GET|/api/a" in output


def test_cli_scan_local_folder(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("JSH_DATA_DIR", str(tmp_path / "data"))
    examples = ROOT / "examples"
    output = tmp_path / "out"
    code = main(
        [
            "scan",
            "--dir",
            str(examples),
            "--output",
            str(output),
            "--no-color",
            "--format",
            "all",
            "--verbose",
        ]
    )
    assert code == 0
    assert (output / "report.html").exists()
    assert (output / "report.json").exists()

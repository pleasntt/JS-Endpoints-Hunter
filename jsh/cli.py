from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .cache import Cache
from .config import load_config
from .patterns import load_patterns
from .scanner import Scanner
from .storage import Storage
from .ui.app import run_ui
from .utils import human_bytes


def _console(no_color: bool = False) -> Any:
    try:
        from rich.console import Console

        return Console(highlight=False, force_terminal=not no_color)
    except Exception:
        return None


def _print(console: Any, message: str, style: str = "") -> None:
    if console is not None:
        console.print(message, style=style or None)
    else:
        print(message)


def _read_list(value: str) -> str:
    path = Path(value)
    if path.is_file():
        return path.read_text(encoding="utf-8", errors="replace")
    return value


def _confirm_secrets(args: argparse.Namespace) -> bool:
    if not args.show_secrets or args.yes:
        return True
    print(
        "WARNING: --show-secrets writes raw secret values to the report and SQLite.",
        file=sys.stderr,
    )
    if sys.stdin.isatty():
        answer = input("Type YES to continue: ").strip()
        return answer == "YES"
    print("Non-interactive mode: proceeding with explicit --show-secrets.", file=sys.stderr)
    return True


def _summary(result: Any, console: Any, verbose: bool) -> None:
    stats = result.stats
    _print(console, f"\n[bold]JS-Endpoints-Hunter {__version__}[/bold] · {result.target}")
    _print(
        console,
        f"status: [cyan]{result.status}[/cyan] · {stats.get('endpoints', 0)} endpoints · "
        f"{stats.get('secrets', 0)} secrets · {stats.get('hosts', 0)} hosts",
    )
    _print(
        console, f"files: {stats.get('files', 0)} · size: {human_bytes(int(stats.get('bytes', 0)))}"
    )
    if result.artifacts.get("dir"):
        _print(console, f"report: {result.artifacts['dir']}")
    if verbose:
        for item in result.findings:
            label = item.secret_type if item.is_secret else (item.method or "-")
            value = item.masked if item.is_secret else item.value
            _print(console, f"  {item.kind:10} {label:9} {value}  ({item.source}:{item.line})")


def _print_format(result: Any, fmt: str) -> None:
    artifacts = result.artifacts
    mapping = {
        "json": "report.json",
        "md": "report.md",
        "csv": "endpoints.csv",
        "sarif": "report.sarif",
        "jsonl": "findings.jsonl",
    }
    if fmt == "all":
        return
    if fmt == "html":
        print(artifacts.get("report.html", "report.html"))
        return
    name = mapping.get(fmt)
    if not name or not artifacts.get(name):
        return
    path = Path(artifacts["dir"]) / name
    if path.exists():
        print(path.read_text(encoding="utf-8", errors="replace"))


def cmd_scan(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    if args.patterns:
        config = replace(config, patterns_path=Path(args.patterns))
    settings = replace(
        config.scan,
        download_maps=config.scan.download_maps and not args.no_maps,
        find_secrets=not args.no_secrets,
        show_secrets=args.show_secrets,
        include_vendor=args.include_vendor,
        keep_assets=args.keep_assets,
        entropy_secrets=args.entropy,
        allowlist_file=args.allowlist or config.scan.allowlist_file,
        harvest_maps=not args.no_harvest_maps,
        proxy=args.proxy if args.proxy is not None else config.scan.proxy,
        timeout=args.timeout if args.timeout is not None else config.scan.timeout,
        concurrency=args.concurrency if args.concurrency is not None else config.scan.concurrency,
    )
    if not _confirm_secrets(args):
        return 2

    input_type = "url"
    target = args.target or ""
    content: str | None = None
    if args.html:
        input_type = "html"
    elif args.dir_path:
        input_type = "dir"
        target = args.dir_path
    elif args.har_path:
        input_type = "har"
        target = args.har_path
    elif args.list_path:
        input_type = "list"
        target = args.list_path
        content = _read_list(args.list_path)
    elif args.clipboard:
        input_type = "clipboard"
        try:
            import pyperclip

            content = pyperclip.paste()
        except Exception as exc:
            print(f"clipboard unavailable: {exc}", file=sys.stderr)
            return 1
        target = "clipboard"
    if not target:
        print("error: target is required", file=sys.stderr)
        return 1

    patterns = load_patterns(config.patterns_path)
    storage = Storage(config.paths.db_path)
    cache = Cache(config.paths.cache_dir)
    scan_id = storage.create_scan(input_type, target, asdict(settings))
    console = _console(args.no_color)
    out_dir = Path(args.output).expanduser().resolve() if args.output else None

    def emit(event: dict[str, Any]) -> None:
        if args.quiet:
            return
        if event.get("type") == "log":
            _print(console, f"[dim]{event.get('message', '')}[/dim]")
        elif args.verbose and event.get("type") == "progress":
            _print(
                console,
                f"[dim]{event.get('done')}/{event.get('total')} · {event.get('file', '')}[/dim]",
            )

    scanner = Scanner(
        config=replace(config, scan=settings), patterns=patterns, cache=cache, emit=emit
    )
    result = asyncio.run(
        scanner.run(input_type, target, content=content, scan_id=scan_id, out_dir=out_dir)
    )
    storage.save_result(result, show_secrets=settings.show_secrets)
    _summary(result, console, args.verbose)
    _print_format(result, args.format)
    exit_code = 0 if result.status in {"completed", "stopped"} else 1
    result_data = result.to_dict(show_secrets=settings.show_secrets)
    if args.baseline:
        _, baseline = _load_report(args.baseline)
        baseline_keys = {
            f"{item.get('method', '')}|{item.get('value', '')}"
            for item in baseline.get("findings", [])
            if item.get("kind") != "secret"
        }
        new_keys = sorted(
            {
                f"{item.get('method', '')}|{item.get('value', '')}"
                for item in result_data["findings"]
                if item.get("kind") != "secret"
            }
            - baseline_keys
        )
        _print(console, f"baseline: {len(new_keys)} new endpoint(s)")
        for key in new_keys[:30]:
            _print(console, f"  + {key}")
        if args.fail_on_new and new_keys:
            exit_code = 4
    if args.fail_on_severity != "none":
        rank = {"low": 1, "medium": 2, "high": 3}
        threshold = rank[args.fail_on_severity]
        if any(
            rank.get(str(item.get("severity", "")).lower(), 0) >= threshold
            for item in result_data["findings"]
            if item.get("kind") == "secret"
        ):
            exit_code = 5
    return exit_code


def cmd_ui(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    server = config.server
    if args.port is not None:
        server = replace(server, port=args.port)
    if args.host is not None:
        server = replace(server, host=args.host)
    if args.patterns:
        config = replace(config, patterns_path=Path(args.patterns))
    config = replace(config, server=server)
    if server.host not in {"127.0.0.1", "localhost"}:
        print("warning: UI is not bound to loopback", file=sys.stderr)
    run_ui(config, open_browser=not args.no_open)
    return 0


def _load_report(path: str) -> tuple[Path, dict[str, Any]]:
    report_path = Path(path)
    if report_path.is_dir():
        report_path = report_path / "report.json"
    return report_path, json.loads(report_path.read_text(encoding="utf-8", errors="replace"))


def cmd_history(args: argparse.Namespace) -> int:
    config = load_config(args.config if hasattr(args, "config") else None)
    scans = Storage(config.paths.db_path).list_scans(max(1, args.limit))
    cutoff = None
    if args.since:
        match = re.fullmatch(r"(\d+)([mhd])", args.since)
        if not match:
            print("error: --since must look like 7d, 24h or 30m", file=sys.stderr)
            return 1
        amount, unit = int(match.group(1)), match.group(2)
        delta = {
            "m": timedelta(minutes=amount),
            "h": timedelta(hours=amount),
            "d": timedelta(days=amount),
        }[unit]
        cutoff = (datetime.now(timezone.utc) - delta).strftime("%Y-%m-%d %H:%M:%S")
    if cutoff:
        scans = [scan for scan in scans if str(scan.get("started_at", "")) >= cutoff]
    if args.search:
        needle = args.search.lower()
        scans = [
            scan
            for scan in scans
            if needle in f"{scan.get('target', '')} {scan.get('input_type', '')}".lower()
        ]
    if args.json:
        print(json.dumps(scans, ensure_ascii=False, indent=2))
        return 0
    if not scans:
        print("no scans")
        return 0
    for scan in scans:
        stats = scan.get("stats", {})
        print(
            f"#{scan['id']:<4} {scan['status']:<10} {scan['started_at']}  "
            f"{stats.get('endpoints', 0):>3} ep  {stats.get('secrets', 0):>2} sec  {scan['target']}"
        )
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    path, data = _load_report(args.path)
    endpoints = [item for item in data.get("findings", []) if item.get("kind") != "secret"]
    fmt = args.format
    if fmt in {"sarif", "jsonl"}:
        sibling = path.with_name("report.sarif" if fmt == "sarif" else "findings.jsonl")
        text = sibling.read_text(encoding="utf-8", errors="replace")
    elif fmt == "json":
        text = json.dumps(data, ensure_ascii=False, indent=2)
    elif fmt == "csv":
        lines = ["path,method,type,source,line,confidence"]
        for item in endpoints:
            values = [
                str(item.get("value", "")),
                str(item.get("method", "")),
                str(item.get("kind", "")),
                str(item.get("source", "")),
                str(item.get("line", 0)),
                str(item.get("confidence", 0)),
            ]
            lines.append(",".join('"' + value.replace('"', '""') + '"' for value in values))
        text = "\n".join(lines) + "\n"
    else:
        lines = [f"# {data.get('target', '')}", "", f"Status: `{data.get('status', '')}`", ""]
        for item in endpoints:
            lines.append(
                f"- `{item.get('value', '')}` · {item.get('method', '') or '-'} · {item.get('kind', '')}"
            )
        text = "\n".join(lines) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(args.output)
    else:
        print(text, end="")
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    _, left = _load_report(args.left)
    _, right = _load_report(args.right)

    def endpoints(data: dict[str, Any]) -> set[str]:
        return {
            f"{item.get('method', '')}|{item.get('value', '')}"
            for item in data.get("findings", [])
            if item.get("kind") != "secret"
        }

    before = endpoints(left)
    after = endpoints(right)
    added = sorted(after - before)
    removed = sorted(before - after)
    if args.format == "json":
        print(
            json.dumps(
                {"added": added, "removed": removed, "common": len(before & after)}, indent=2
            )
        )
    else:
        print(f"added: {len(added)} · removed: {len(removed)} · common: {len(before & after)}")
        for item in added:
            print(f"+ {item}")
        for item in removed:
            print(f"- {item}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="jsh",
        description="JS-Endpoints-Hunter - local JS endpoint and secret extractor.",
        epilog=(
            "Examples:\n"
            "  python jsh.py scan https://example.com/static/billing.js\n"
            "  python jsh.py scan --html https://example.com\n"
            "  python jsh.py scan --dir ./js-dump\n"
            "  python jsh.py scan --har ./capture.har\n"
            "  python jsh.py scan --list urls.txt --concurrency 10\n"
            "  python jsh.py ui\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan JS/HTML/HAR/folder")
    scan.add_argument("target", nargs="?", help="URL or path; use a mode flag for clarity")
    modes = scan.add_mutually_exclusive_group()
    modes.add_argument("--html", action="store_true", help="scan an HTML page and its scripts")
    modes.add_argument("--dir", dest="dir_path", metavar="PATH", help="scan a local folder")
    modes.add_argument("--har", dest="har_path", metavar="FILE", help="scan a HAR capture")
    modes.add_argument(
        "--list", dest="list_path", metavar="FILE", help="scan URL list (file or literal)"
    )
    modes.add_argument("--clipboard", action="store_true", help="scan clipboard contents")
    scan.add_argument(
        "--show-secrets", action="store_true", help="show raw secrets (writes them to reports)"
    )
    scan.add_argument("--yes", action="store_true", help="skip the show-secrets confirmation")
    scan.add_argument("--include-vendor", action="store_true", help="include node_modules/vendor")
    scan.add_argument("--keep-assets", action="store_true", help="keep CSS/image paths")
    scan.add_argument("--no-maps", action="store_true", help="do not download source maps")
    scan.add_argument("--no-secrets", action="store_true", help="disable secret extraction")
    scan.add_argument("--entropy", action="store_true", help="add high-entropy secret candidates")
    scan.add_argument("--allowlist", help="regex allowlist file")
    scan.add_argument(
        "--no-harvest-maps", action="store_true", help="do not probe adjacent .map files"
    )
    scan.add_argument("--proxy", help="HTTP(S) proxy for Burp/Caido")
    scan.add_argument("--timeout", type=float, help="request timeout in seconds")
    scan.add_argument("--concurrency", type=int, help="parallel fetches")
    scan.add_argument("--no-color", action="store_true", help="disable ANSI color")
    scan.add_argument("--output", metavar="DIR", help="artifact directory")
    scan.add_argument(
        "--format", choices=["all", "json", "csv", "md", "html", "sarif", "jsonl"], default="all"
    )
    scan.add_argument(
        "--resume", action="store_true", help="reuse the content cache (enabled by default)"
    )
    scan.add_argument("--quiet", action="store_true", help="suppress live logs")
    scan.add_argument("--verbose", action="store_true", help="print findings and progress")
    scan.add_argument("--baseline", help="baseline report.json for a diff")
    scan.add_argument(
        "--fail-on-new", action="store_true", help="exit 4 when baseline has new endpoints"
    )
    scan.add_argument(
        "--fail-on-severity", choices=["none", "low", "medium", "high"], default="none"
    )
    scan.add_argument("--config", help="config.toml path")
    scan.add_argument("--patterns", help="patterns.yaml path")
    scan.set_defaults(func=cmd_scan)

    ui = sub.add_parser("ui", help="run the local web UI")
    ui.add_argument("--port", type=int)
    ui.add_argument("--host")
    ui.add_argument("--no-open", action="store_true", help="do not open a browser")
    ui.add_argument("--config")
    ui.add_argument("--patterns")
    ui.set_defaults(func=cmd_ui)

    history = sub.add_parser("history", help="list and filter local scan history")
    history.add_argument("--limit", type=int, default=20)
    history.add_argument("--since", help="e.g. 7d, 24h, 30m")
    history.add_argument("--search", help="substring in target/type")
    history.add_argument("--json", action="store_true")
    history.set_defaults(func=cmd_history)

    report = sub.add_parser("report", help="render a saved report.json")
    report.add_argument("path", help="report.json or scan directory")
    report.add_argument("--format", choices=["json", "csv", "md", "sarif", "jsonl"], default="md")
    report.add_argument("--output", help="write to this file")
    report.set_defaults(func=cmd_report)

    diff = sub.add_parser("diff", help="compare two scans")
    diff.add_argument("left")
    diff.add_argument("right")
    diff.add_argument("--format", choices=["text", "json"], default="text")
    diff.set_defaults(func=cmd_diff)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())

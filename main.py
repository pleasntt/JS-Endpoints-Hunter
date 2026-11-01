"""
JS-Endpoints-Hunter — CLI точка входа.

Скачивает/читает JS-файлы и вытаскивает из них API-эндпоинты и секреты.

Примеры запуска:
    python main.py -u https://example.com/main.js
    python main.py -u https://a.com/app.js -u https://a.com/vendor.js
    python main.py -f ./dist/app.js
    python main.py -d ./dist -o report.json
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from hunter.extractor import EndpointExtractor
from hunter.fetcher import JSFetcher

console = Console()
logger = logging.getLogger("hunter")

BANNER = (
    "╔═══════════════════════════════════════════════╗\n"
    "║        JS-Endpoints-Hunter  v1.0.0            ║\n"
    "║   extract endpoints & secrets from JavaScript  ║\n"
    "╚═══════════════════════════════════════════════╝"
)


# --------------------------------------------------------------------------- #
#                            АРГУМЕНТЫ КОМАНДНОЙ СТРОКИ
# --------------------------------------------------------------------------- #
def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="js-hunter",
        description=(
            "JS-Endpoints-Hunter: находит API-эндпоинты и потенциальные "
            "секреты в JavaScript-файлах."
        ),
    )

    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument(
        "-u", "--url",
        action="append",
        metavar="URL",
        help="URL JS-файла (можно несколько через повтор -u)",
    )
    src.add_argument(
        "-f", "--file",
        action="append",
        metavar="PATH",
        help="локальный JS-файл (можно несколько через повтор -f)",
    )
    src.add_argument(
        "-d", "--dir",
        metavar="DIR",
        help="директория с JS-файлами (рекурсивно)",
    )

    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="сохранить результат в .txt или .json",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="подробный лог (DEBUG)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="отключить цвета в выводе",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="таймаут HTTP-запроса в секундах (по умолчанию 15)",
    )
    parser.add_argument(
        "--no-ssl-verify",
        action="store_true",
        help="не проверять SSL-сертификаты (полезно в багбаунти)",
    )

    return parser.parse_args(argv)


def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(levelname)-8s | %(name)s | %(message)s",
    )


# --------------------------------------------------------------------------- #
#                              СБОР И АНАЛИЗ
# --------------------------------------------------------------------------- #
def gather_sources(args: argparse.Namespace) -> dict[str, str]:
    """Собирает {имя_источника: текст} из URL/файлов/директории."""
    fetcher = JSFetcher(
        timeout=args.timeout,
        verify_ssl=not args.no_ssl_verify,
    )

    targets: list[str] = []
    if args.url:
        targets.extend(args.url)
    elif args.file:
        targets.extend(args.file)
    elif args.dir:
        targets.append(args.dir)

    sources: dict[str, str] = {}
    for target in targets:
        for name, text in fetcher.collect(target).items():
            sources[name] = text
    return sources


def extract_all(
    sources: dict[str, str],
) -> tuple[set[str], dict[str, set[str]]]:
    """Прогоняет все источники через EndpointExtractor и объединяет результаты."""
    ext = EndpointExtractor()
    endpoints: set[str] = set()
    secrets: dict[str, set[str]] = {}

    for name, text in sources.items():
        logger.debug("Анализ %s (%d симв.)", name, len(text))
        endpoints.update(ext.find_endpoints(text))
        for kind, values in ext.find_secrets(text).items():
            secrets.setdefault(kind, set()).update(values)

    return endpoints, secrets


# --------------------------------------------------------------------------- #
#                                  ВЫВОД
# --------------------------------------------------------------------------- #
def show_banner() -> None:
    console.print(BANNER, style="cyan", highlight=False)


def show_sources(sources: dict[str, str]) -> None:
    table = Table(
        title=f"Loaded sources ({len(sources)})",
        box=box.SIMPLE_HEAVY,
        show_edge=False,
    )
    table.add_column("#", justify="right", style="dim")
    table.add_column("Source", overflow="fold", style="white")
    table.add_column("Size", justify="right", style="green")

    for i, (name, text) in enumerate(sources.items(), 1):
        table.add_row(str(i), name, f"{len(text):,}")

    console.print(table)


def show_endpoints(endpoints: set[str]) -> None:
    if not endpoints:
        console.print("[yellow]No endpoints found.[/yellow]\n")
        return

    table = Table(
        title=f"Endpoints  ({len(endpoints)} unique)",
        box=box.ROUNDED,
        header_style="bold cyan",
    )
    table.add_column("#", justify="right", style="dim")
    table.add_column("Endpoint", style="bright_cyan", overflow="fold")

    for i, ep in enumerate(sorted(endpoints), 1):
        table.add_row(str(i), ep)

    console.print(table)


def show_secrets(secrets: dict[str, set[str]]) -> None:
    total = sum(len(v) for v in secrets.values())
    if not secrets:
        console.print("[yellow]No secrets found.[/yellow]\n")
        return

    table = Table(
        title=f"Secrets  ({total} total)",
        box=box.ROUNDED,
        header_style="bold red",
    )
    table.add_column("Type", style="magenta")
    table.add_column("Value", style="bright_red", overflow="fold")

    for kind in sorted(secrets):
        for val in sorted(secrets[kind]):
            table.add_row(kind, val)

    console.print(table)


def show_summary(
    endpoints: set[str],
    secrets: dict[str, set[str]],
    output_path: Optional[str],
) -> None:
    total_secrets = sum(len(v) for v in secrets.values())
    text = Text()
    text.append("Endpoints : ", style="bold")
    text.append(f"{len(endpoints)}\n", style="bright_cyan")
    text.append("Secrets   : ", style="bold")
    text.append(f"{total_secrets}\n", style="bright_red")
    if output_path:
        text.append("Saved to  : ", style="bold")
        text.append(output_path, style="green")

    console.print(Panel(text, title="Summary", border_style="green", expand=False))


# --------------------------------------------------------------------------- #
#                              СОХРАНЕНИЕ ОТЧЁТА
# --------------------------------------------------------------------------- #
def save_output(
    path: str,
    sources: dict[str, str],
    endpoints: set[str],
    secrets: dict[str, set[str]],
) -> bool:
    """Сохраняет отчёт в .json или .txt. Возвращает True при успехе."""
    p = Path(path).expanduser()
    try:
        if p.suffix.lower() == ".json":
            payload = {
                "sources": {name: len(text) for name, text in sources.items()},
                "endpoints": sorted(endpoints),
                "secrets": {k: sorted(v) for k, v in secrets.items()},
            }
            p.write_text(
                json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
        else:
            lines: list[str] = [
                "# JS-Endpoints-Hunter report",
                f"# sources: {len(sources)}",
                "",
                "[ENDPOINTS]",
                *sorted(endpoints),
                "",
                "[SECRETS]",
            ]
            for kind in sorted(secrets):
                for val in sorted(secrets[kind]):
                    lines.append(f"{kind}: {val}")
            p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except OSError as exc:
        console.print(f"[red]Cannot write {p}: {exc}[/red]")
        return False
    return True


# --------------------------------------------------------------------------- #
#                                    MAIN
# --------------------------------------------------------------------------- #
def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    if args.no_color:
        console.no_color = True

    _configure_logging(args.verbose)
    show_banner()

    sources = gather_sources(args)
    if not sources:
        console.print(
            "[bold red]Nothing was loaded.[/bold red] "
            "Проверьте URL/путь и повторите."
        )
        return 1

    show_sources(sources)

    with console.status("[cyan]Analysing...[/cyan]", spinner="dots"):
        endpoints, secrets = extract_all(sources)

    show_endpoints(endpoints)
    show_secrets(secrets)

    saved = False
    if args.output:
        saved = save_output(args.output, sources, endpoints, secrets)

    show_summary(endpoints, secrets, args.output if saved else None)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        console.print("\n[red]Interrupted by user.[/red]")
        sys.exit(130)
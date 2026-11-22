from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from .allowlist import Allowlist
from .cache import Cache
from .config import AppConfig
from .extractors import extract_all
from .models import Finding, RawFile, ScanResult
from .net import Fetcher, FetchResult
from .normalize import host_from, normalize_endpoint, top_prefixes
from .parsers.folder import iter_js_files, read_folder_file, read_package_dependencies
from .parsers.har import parse_har
from .parsers.html import parse_html, parse_manifest
from .parsers.sourcemap import find_source_map_url, parse_source_map
from .patterns import PatternSet
from .utils import host_of, safe_filename, sha256_text

EventCallback = Callable[[dict[str, Any]], None]


class ScanCancelled(Exception):
    pass


class Scanner:
    def __init__(
        self,
        config: AppConfig,
        patterns: PatternSet,
        cache: Cache,
        emit: EventCallback | None = None,
        stop_event: threading.Event | None = None,
    ) -> None:
        self.config = config
        self.settings = config.scan
        self.patterns = patterns
        self.cache = cache
        self.emit = emit
        self.stop_event = stop_event or threading.Event()
        self.semaphore = asyncio.Semaphore(max(1, self.settings.concurrency))
        self.fetcher: Fetcher | None = None
        self.result: ScanResult | None = None
        self._findings: list[Finding] = []
        self._raw_files: list[RawFile] = []
        self._raw_hashes: set[str] = set()
        self._raw_names: set[str] = set()
        self._processed_urls: set[str] = set()
        self._processed_maps: set[str] = set()
        self._total = 1
        self._done = 0

    def _event(self, kind: str, **fields: Any) -> None:
        if self.emit is None:
            return
        payload = {"type": kind, "scan_id": self.result.scan_id if self.result else 0, **fields}
        try:
            self.emit(payload)
        except Exception:
            pass

    def _check_stop(self) -> None:
        if self.stop_event.is_set():
            raise ScanCancelled()

    def _progress(self, filename: str = "") -> None:
        endpoints = sum(1 for item in self._findings if item.kind != "secret")
        secrets = len(self._findings) - endpoints
        hosts = {item.meta.get("host") or host_of(item.value) for item in self._findings}
        hosts.discard("")
        self._event(
            "progress",
            done=self._done,
            total=max(self._total, self._done),
            file=filename,
            endpoints=endpoints,
            secrets=secrets,
            hosts=len(hosts),
        )

    def _log(self, message: str, level: str = "info") -> None:
        self._event("log", message=message, level=level)

    async def _get(self, url: str) -> FetchResult:
        if self.fetcher is None:
            return FetchResult(url=url, error="fetcher is not open")
        self._check_stop()
        async with self.semaphore:
            return await self.fetcher.get(url)

    def _add_raw(
        self,
        name: str,
        url: str,
        content: str,
        content_type: str = "",
        origin: str = "network",
        map_url: str = "",
    ) -> None:
        if not content:
            return
        digest = sha256_text(content)
        if digest in self._raw_hashes:
            return
        base = safe_filename(name)
        filename = base
        counter = 2
        while filename in self._raw_names:
            stem = Path(base).stem
            suffix = Path(base).suffix
            filename = f"{stem}-{counter}{suffix}"
            counter += 1
        self._raw_names.add(filename)
        self._raw_hashes.add(digest)
        self._raw_files.append(
            RawFile(
                name=filename,
                url=url,
                content=content,
                content_type=content_type,
                origin=origin,
                map_url=map_url,
            )
        )

    def _add_findings(self, findings: list[Finding], base_url: str | None) -> None:
        for finding in findings:
            if not finding.meta.get("host"):
                finding.meta["host"] = host_from(finding.value, base_url)
            self._findings.append(finding)

    async def _analyze_text(
        self,
        text: str,
        source: str,
        base_url: str | None,
        origin: str = "minified",
        filename: str = "",
        allow_source_maps: bool = True,
        allow_fetch_maps: bool = True,
        local_base: Path | None = None,
        is_map: bool = False,
    ) -> None:
        if not text:
            return
        self._add_raw(
            filename or source,
            base_url or source,
            text,
            content_type="application/javascript",
            origin=origin,
        )
        findings = extract_all(
            text,
            base_url=base_url,
            source=source,
            origin=origin,
            patterns=self.patterns,
            find_secrets=self.settings.find_secrets,
            entropy_secrets=self.settings.entropy_secrets,
        )
        self._add_findings(findings, base_url)
        if is_map or not allow_source_maps or not self.settings.download_maps:
            return
        map_ref = find_source_map_url(text)
        if map_ref:
            await self._analyze_map_ref(
                map_ref,
                base_url=base_url,
                source_label=source,
                allow_fetch=allow_fetch_maps,
                local_base=local_base,
            )
        elif (
            self.settings.harvest_maps
            and allow_fetch_maps
            and base_url
            and base_url.startswith(("http://", "https://"))
            and base_url.split("?", 1)[0].endswith((".js", ".mjs", ".cjs"))
        ):
            await self._analyze_map_ref(
                base_url.split("?", 1)[0] + ".map",
                base_url=base_url,
                source_label=source,
                allow_fetch=allow_fetch_maps,
                local_base=None,
            )

    def _read_local_map(self, ref: str, local_base: Path | None) -> tuple[str, str] | None:
        if ref.startswith("data:"):
            return ref, "inline-map"
        if not local_base:
            return None
        path = Path(ref)
        if not path.is_absolute():
            path = local_base / path
        try:
            return path.read_text(encoding="utf-8", errors="replace"), str(path)
        except OSError:
            return None

    async def _analyze_map_ref(
        self,
        ref: str,
        base_url: str | None,
        source_label: str,
        allow_fetch: bool,
        local_base: Path | None,
    ) -> None:
        ref = ref.strip().strip("'\"`")
        if not ref:
            return
        map_text = ""
        map_url = ref
        if ref.startswith("data:"):
            map_text = ref
        elif ref.startswith(("http://", "https://")):
            map_url = ref
            if allow_fetch:
                fetched = await self._get(map_url)
                if fetched.error:
                    self._log(f"source map: {fetched.error}", "warn")
                    return
                map_text = fetched.content
        elif local_base:
            local = self._read_local_map(ref, local_base)
            if local is None:
                return
            map_text, map_url = local
        elif base_url:
            map_url = urljoin(base_url, ref)
            if allow_fetch:
                fetched = await self._get(map_url)
                if fetched.error:
                    self._log(f"source map: {fetched.error}", "warn")
                    return
                map_text = fetched.content
        if not map_text or map_url in self._processed_maps:
            return
        self._processed_maps.add(map_url)
        self._add_raw(
            safe_filename(Path(urlparse(map_url).path).name or "source.map"),
            map_url,
            map_text,
            content_type="application/json",
            origin="sourcemap",
        )
        parsed = parse_source_map(map_text, map_url)
        if parsed.error:
            self._log(parsed.error, "warn")
            return
        self._log(f"source map: {len(parsed.sources)} original source(s) from {source_label}")
        for item in parsed.sources[:300]:
            source_name = f"{source_label}:{item.name}"
            await self._analyze_text(
                item.content,
                source=source_name,
                base_url=map_url,
                origin="original",
                filename=safe_filename(item.name),
                allow_source_maps=False,
                allow_fetch_maps=False,
                is_map=False,
            )

    async def _scan_js_url(
        self, url: str, origin: str = "minified", allow_fetch: bool = True
    ) -> None:
        if not url or url in self._processed_urls:
            return
        if not url.startswith(("http://", "https://")):
            return
        self._processed_urls.add(url)
        self._check_stop()
        try:
            fetched = await self._get(url)
            if fetched.error and not fetched.content:
                self._log(f"{url}: {fetched.error}", "warn")
                self.result.errors.append(f"{url}: {fetched.error}") if self.result else None
                return
            self._log(f"analyze {url}")
            content = fetched.content
            final_url = fetched.final_url or url
            content_type = fetched.content_type.lower()
            if "html" in content_type or content.lstrip().lower().startswith(
                ("<!doctype html", "<html")
            ):
                await self._process_html(
                    content,
                    base_url=final_url,
                    source=url,
                    allow_fetch=allow_fetch,
                )
            else:
                await self._analyze_text(
                    content,
                    source=url,
                    base_url=final_url,
                    origin=origin,
                    filename=safe_filename(Path(urlparse(final_url).path).name or "bundle.js"),
                    allow_fetch_maps=allow_fetch,
                )
        finally:
            self._done += 1
            self._progress(url)

    async def _process_html(
        self,
        text: str,
        base_url: str,
        source: str,
        allow_fetch: bool = True,
    ) -> None:
        document = parse_html(text, base_url)
        for warning in document.warnings:
            self._log(warning, "warn")
        self._add_raw(
            safe_filename(Path(urlparse(base_url).path).name or "page.html"),
            base_url,
            text,
            content_type="text/html",
            origin="html",
        )
        for manifest_url in document.manifests:
            if not allow_fetch:
                continue
            fetched = await self._get(manifest_url)
            if fetched.error or not fetched.content:
                continue
            for ref in parse_manifest(fetched.content, manifest_url):
                document.scripts.append(ref)
        inline = [ref for ref in document.scripts if ref.inline]
        external = [ref for ref in document.scripts if ref.url]
        if not allow_fetch:
            external = []
        self._total += len(inline) + len(external)
        for index, ref in enumerate(inline, start=1):
            self._check_stop()
            await self._analyze_text(
                ref.inline,
                source=f"{source}#inline-{index}",
                base_url=base_url,
                origin="html",
                filename=f"{safe_filename(Path(urlparse(base_url).path).name or 'page')}-inline-{index}.js",
                allow_fetch_maps=allow_fetch,
            )
            self._done += 1
            self._progress(f"inline script {index}")
        if external:
            self._log(f"{source}: found {len(external)} external script(s)")
            await asyncio.gather(
                *[
                    self._scan_js_url(ref.url, origin="minified", allow_fetch=allow_fetch)
                    for ref in external
                ],
                return_exceptions=True,
            )

    async def _scan_page(self, url: str) -> None:
        self._check_stop()
        fetched = await self._get(url)
        if fetched.error and not fetched.content:
            if self.result:
                self.result.errors.append(f"{url}: {fetched.error}")
            self._log(f"{url}: {fetched.error}", "error")
            self._done += 1
            self._progress(url)
            return
        await self._process_html(
            fetched.content,
            base_url=fetched.final_url or url,
            source=url,
            allow_fetch=True,
        )
        self._done += 1
        self._progress(url)

    async def _scan_url(self, url: str) -> None:
        self._check_stop()
        fetched = await self._get(url)
        if fetched.error and not fetched.content:
            if self.result:
                self.result.errors.append(f"{url}: {fetched.error}")
            self._log(f"{url}: {fetched.error}", "error")
            self._done += 1
            self._progress(url)
            return
        content = fetched.content
        content_type = fetched.content_type.lower()
        if "html" in content_type or content.lstrip().lower().startswith(
            ("<!doctype html", "<html")
        ):
            await self._process_html(
                content, fetched.final_url or url, source=url, allow_fetch=True
            )
        else:
            await self._analyze_text(
                content,
                source=url,
                base_url=fetched.final_url or url,
                origin="minified",
                filename=safe_filename(
                    Path(urlparse(fetched.final_url or url).path).name or "bundle.js"
                ),
            )
        self._done += 1
        self._progress(url)

    async def _scan_list(self, text: str) -> None:
        urls = [
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        self._total = max(1, len(urls))
        self._done = 0
        if not urls:
            self._log("list is empty", "warn")
            return
        for url in urls:
            self._check_stop()
            await self._scan_js_url(url)

    async def _scan_dir(self, root: Path) -> None:
        if not root.is_dir():
            raise ValueError(f"directory not found: {root}")
        files = iter_js_files(root, include_vendor=self.settings.include_vendor)
        self._total = max(1, len(files))
        self._done = 0
        if not files:
            self._log("no JS/TS/JSON files found", "warn")
            return
        self._log(f"local files: {len(files)}")
        for path in files:
            self._check_stop()
            item = read_folder_file(path, root)
            if item is None:
                self._done += 1
                self._progress(str(path))
                continue
            source = item.relative.replace("\\", "/")
            if path.name == "package.json":
                self.result.dependencies.extend(  # type: ignore[union-attr]
                    read_package_dependencies(path, source=source)
                )
            if path.suffix.lower() == ".map":
                await self._analyze_map_ref(
                    str(path),
                    base_url=None,
                    source_label=source,
                    allow_fetch=False,
                    local_base=path.parent,
                )
            else:
                await self._analyze_text(
                    item.content,
                    source=source,
                    base_url=None,
                    origin="minified",
                    filename=source,
                    allow_fetch_maps=False,
                    local_base=path.parent,
                )
                adjacent = path.with_name(path.name + ".map")
                if adjacent.exists() and self.settings.download_maps:
                    await self._analyze_map_ref(
                        str(adjacent),
                        base_url=None,
                        source_label=source,
                        allow_fetch=False,
                        local_base=path.parent,
                    )
            self._done += 1
            self._progress(source)

    async def _scan_har(self, path: Path) -> None:
        data = parse_har(path)
        for error in data.errors:
            self._log(error, "error")
            if self.result:
                self.result.errors.append(error)
        self._total = max(1, len(data.resources))
        self._done = 0
        for resource in data.resources:
            self._check_stop()
            source = resource.url
            if resource.is_html:
                await self._process_html(
                    resource.content,
                    base_url=resource.url,
                    source=source,
                    allow_fetch=False,
                )
            else:
                await self._analyze_text(
                    resource.content,
                    source=source,
                    base_url=resource.url,
                    origin="har",
                    filename=safe_filename(Path(urlparse(resource.url).path).name or "har.js"),
                    allow_fetch_maps=False,
                )
            self._done += 1
            self._progress(source)
        for url in data.missing_js:
            self._log(f"HAR has JS URL without response body: {url}", "warn")
        for url in data.websocket_urls:
            normalized = normalize_endpoint(url)
            if normalized:
                self._add_findings(
                    [
                        Finding(
                            kind="websocket",
                            value=normalized,
                            source=str(path),
                            line=1,
                            snippet=url,
                            confidence=86,
                            origin="har",
                            meta={"host": host_from(normalized), "original": url, "har": True},
                        )
                    ],
                    None,
                )
        self._log(
            f"HAR: {len(data.js_urls)} JS URL(s), {len(data.missing_js)} without body, "
            f"{len(data.websocket_urls)} WebSocket URL(s)"
        )

    async def _scan_clipboard(self, text: str) -> None:
        lowered = text.lstrip().lower()
        if lowered.startswith(("<!doctype html", "<html", "<script")):
            await self._process_html(text, base_url="", source="clipboard", allow_fetch=True)
            self._done += 1
            self._progress("clipboard")
            return
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if len(lines) == 1 and lines[0].startswith(("http://", "https://")):
            await self._scan_js_url(lines[0])
            return
        if all(line.startswith(("http://", "https://")) for line in lines):
            await self._scan_list(text)
            return
        await self._analyze_text(
            text,
            source="clipboard.js",
            base_url=None,
            origin="minified",
            filename="clipboard.js",
            allow_fetch_maps=False,
        )
        self._done += 1
        self._progress("clipboard")

    def _dedupe(self) -> list[Finding]:
        endpoints: dict[str, Finding] = {}
        secrets: dict[str, Finding] = {}
        methodful_values = {
            finding.value for finding in self._findings if not finding.is_secret and finding.method
        }
        for finding in self._findings:
            if finding.is_secret:
                key = f"{finding.secret_type}|{finding.raw or finding.masked}"
                bucket = secrets
            else:
                # A generic path match must not duplicate a typed HTTP call.
                if not finding.method and finding.value in methodful_values:
                    continue
                key = f"{finding.method}|{finding.value}"
                bucket = endpoints
            existing = bucket.get(key)
            if existing is None:
                bucket[key] = finding
                continue
            existing.occurrences += finding.occurrences
            origins = existing.meta.setdefault("origins", [existing.origin])
            if finding.origin not in origins:
                origins.append(finding.origin)
            if finding.confidence > existing.confidence:
                existing.confidence = finding.confidence
        result = list(endpoints.values()) + list(secrets.values())
        severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "": 3}
        result.sort(
            key=lambda item: (
                0 if item.is_secret else 1,
                severity_order.get(item.severity, 3),
                -item.confidence,
                item.value.lower(),
            )
        )
        return result

    def _stats(self, findings: list[Finding]) -> dict[str, Any]:
        endpoints = [item for item in findings if not item.is_secret]
        secrets = [item for item in findings if item.is_secret]
        by_type: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        hosts: set[str] = set()
        for item in findings:
            by_type[item.kind] = by_type.get(item.kind, 0) + 1
            if item.is_secret:
                by_severity[item.severity] = by_severity.get(item.severity, 0) + 1
            host = item.meta.get("host") or host_of(item.value)
            if host:
                hosts.add(host)
        for raw in self._raw_files:
            host = host_of(raw.url)
            if host:
                hosts.add(host)
        prefixes = top_prefixes(
            [
                item.value
                for item in endpoints
                if item.kind in {"rest", "absolute", "path", "file", "websocket", "sse"}
            ]
        )
        size = sum(len(raw.content.encode("utf-8", errors="replace")) for raw in self._raw_files)
        return {
            "files": len(self._raw_files),
            "bytes": size,
            "endpoints": len(endpoints),
            "secrets": len(secrets),
            "hosts": len(hosts),
            "by_type": by_type,
            "by_severity": by_severity,
            "top_prefixes": prefixes,
        }

    def _finalize(self) -> None:
        assert self.result is not None
        allowlist = Allowlist.load(self.settings.allowlist_file)
        for error in allowlist.errors:
            self._log(error, "warn")
        findings = self._dedupe()
        if allowlist.patterns:
            before = len(findings)
            findings = [finding for finding in findings if not allowlist.matches(finding)]
            if len(findings) != before:
                self._log(f"allowlist: suppressed {before - len(findings)} finding(s)")
        self.result.findings = findings
        self.result.raw_files = list(self._raw_files)
        self.result.stats = self._stats(findings)
        raw_hosts = {host_of(item.url) for item in self._raw_files}
        self.result.hosts = sorted(
            ({item.meta.get("host") or host_of(item.value) for item in findings} | raw_hosts) - {""}
        )

    async def run(
        self,
        input_type: str,
        target: str,
        content: str | None = None,
        scan_id: int = 0,
        out_dir: Path | None = None,
    ) -> ScanResult:
        self.result = ScanResult(
            input_type=input_type,
            target=target,
            scan_id=scan_id,
            status="running",
            options=asdict(self.settings),
        )
        self._event("start", target=target, input_type=input_type)
        status = "completed"
        try:
            async with Fetcher(self.settings, self.cache) as fetcher:
                self.fetcher = fetcher
                if input_type == "url":
                    await self._scan_url(target)
                elif input_type == "html":
                    await self._scan_page(target)
                elif input_type == "list":
                    text = content
                    if text is None:
                        path = Path(target)
                        text = (
                            path.read_text(encoding="utf-8", errors="replace")
                            if path.exists()
                            else target
                        )
                    await self._scan_list(text)
                elif input_type == "dir":
                    await self._scan_dir(Path(target))
                elif input_type == "har":
                    await self._scan_har(Path(target))
                elif input_type == "clipboard":
                    await self._scan_clipboard(content or target)
                else:
                    raise ValueError(f"unknown input type: {input_type}")
        except ScanCancelled:
            status = "stopped"
            self._log("scan stopped", "warn")
        except Exception as exc:
            status = "error"
            message = f"{type(exc).__name__}: {exc}"
            self.result.errors.append(message)
            self._log(message, "error")
        self._finalize()
        self.result.finish(status)
        if out_dir is None:
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            out_dir = self.config.paths.results_dir / f"{stamp}_{safe_filename(target, 'scan')}"
        try:
            from .report import generate_report

            self.result.artifacts = generate_report(
                self.result,
                out_dir,
                show_secrets=self.settings.show_secrets,
            )
        except Exception as exc:  # reporting must never hide scan results
            self.result.errors.append(f"report: {exc}")
            self._log(f"report error: {exc}", "error")
        self._event("done", status=status, stats=self.result.stats)
        return self.result

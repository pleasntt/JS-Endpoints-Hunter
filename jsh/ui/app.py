"""Flask UI and local API for JS-Endpoints-Hunter."""

from __future__ import annotations

import asyncio
import json
import queue
import threading
import uuid
import webbrowser
from collections.abc import Iterator
from dataclasses import asdict, fields, replace
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from flask import Flask, Response, jsonify, render_template, request, send_from_directory
from flask.typing import ResponseReturnValue
from jinja2 import PackageLoader
from werkzeug.utils import secure_filename

from .. import __version__
from ..cache import Cache
from ..config import AppConfig, load_config
from ..models import ScanSettings
from ..patterns import load_patterns
from ..scanner import Scanner
from ..storage import Storage
from .assets import attach_static


class ScanManager:
    def __init__(self, config: AppConfig, patterns: Any, cache: Cache, storage: Storage) -> None:
        self.config = config
        self.patterns = patterns
        self.cache = cache
        self.storage = storage
        self.lock = threading.Lock()
        self.queues: dict[int, queue.Queue[dict[str, Any]]] = {}
        self.stop_events: dict[int, threading.Event] = {}
        self.statuses: dict[int, str] = {}

    def queue_for(self, scan_id: int) -> queue.Queue[dict[str, Any]]:
        with self.lock:
            return self.queues.setdefault(scan_id, queue.Queue())

    def start(
        self, input_type: str, target: str, content: str | None, options: dict[str, Any]
    ) -> int:
        scan_config = self.config
        allowed = {
            key: value
            for key, value in options.items()
            if key in {f.name for f in fields(ScanSettings)}
        }
        scan_config = replace(scan_config, scan=replace(scan_config.scan, **allowed))
        scan_id = self.storage.create_scan(input_type, target, asdict(scan_config.scan))
        events = self.queue_for(scan_id)
        stop_event = threading.Event()
        with self.lock:
            self.stop_events[scan_id] = stop_event
            self.statuses[scan_id] = "running"

        def emit(event: dict[str, Any]) -> None:
            events.put(event)

        def worker() -> None:
            try:
                scanner = Scanner(
                    scan_config,
                    self.patterns,
                    self.cache,
                    emit=emit,
                    stop_event=stop_event,
                )
                result = asyncio.run(
                    scanner.run(
                        input_type,
                        target,
                        content=content,
                        scan_id=scan_id,
                    )
                )
                self.storage.save_result(result, show_secrets=scan_config.scan.show_secrets)
                self.statuses[scan_id] = result.status
            except Exception as exc:
                self.statuses[scan_id] = "error"
                self.storage.update_status(scan_id, "error", f"{type(exc).__name__}: {exc}")
                events.put({"type": "error", "scan_id": scan_id, "message": str(exc)})
            finally:
                events.put({"type": "saved", "scan_id": scan_id})

        thread = threading.Thread(target=worker, name=f"jsh-scan-{scan_id}", daemon=True)
        thread.start()
        return scan_id

    def stop(self, scan_id: int) -> bool:
        with self.lock:
            event = self.stop_events.get(scan_id)
        if event is None:
            return False
        event.set()
        self.statuses[scan_id] = "stopping"
        self.storage.update_status(scan_id, "stopping")
        return True


def _json_event(event: dict[str, Any]) -> str:
    return f"data: {json.dumps(event, ensure_ascii=False)}\n\n"


def _stream_events(manager: ScanManager, scan_id: int) -> Iterator[str]:
    if scan_id not in manager.statuses:
        yield _json_event({"type": "done", "scan_id": scan_id, "status": "unknown"})
        return
    events = manager.queue_for(scan_id)
    while True:
        try:
            event = events.get(timeout=15)
        except queue.Empty:
            if manager.statuses.get(scan_id) in {"completed", "error", "stopped", "stopping"}:
                yield ": done\n\n"
                return
            yield ": ping\n\n"
            continue
        yield _json_event(event)
        if event.get("type") in {"saved", "error"}:
            return


def _safe_relative(name: str) -> Path:
    parts = [
        secure_filename(part)
        for part in name.replace("\\", "/").split("/")
        if part and part not in {".", ".."}
    ]
    if not parts:
        return Path("upload.bin")
    return Path(*parts)


def _validate_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _allowed_options(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    allowed = {field.name for field in fields(ScanSettings)}
    result: dict[str, Any] = {}
    for key, value in raw.items():
        if key not in allowed or value is None:
            continue
        if isinstance(value, bool):
            result[key] = value
        elif key in {"timeout", "rate_limit"}:
            result[key] = max(0.1, float(value))
        elif key == "concurrency":
            result[key] = max(1, min(100, int(value)))
        elif key in {"proxy", "user_agent"}:
            result[key] = str(value).strip()
        elif key == "max_bytes":
            result[key] = max(1024, int(value))
    return result


def create_app(config: AppConfig | None = None) -> Flask:
    config = config or load_config()
    config.ensure_dirs()
    patterns = load_patterns(config.patterns_path)
    storage = Storage(config.paths.db_path)
    cache = Cache(config.paths.cache_dir)
    manager = ScanManager(config, patterns, cache, storage)

    app = Flask(__name__, template_folder="templates", static_folder="static")
    # Keep local templates working and make the UI loadable from a zipapp.
    local_templates = Path(__file__).parent / "templates"
    if not local_templates.is_dir():
        app.jinja_loader = PackageLoader("jsh.ui", "templates")
    app.config["MAX_CONTENT_LENGTH"] = 256 * 1024 * 1024
    app.config["JSH_CONFIG"] = config
    app.config["JSH_STORAGE"] = storage
    app.config["JSH_MANAGER"] = manager

    attach_static(app)

    @app.get("/")
    def index() -> str:
        return render_template(
            "index.html",
            version=__version__,
            theme=config.ui.theme,
            lang=config.ui.lang,
        )

    @app.get("/favicon.ico")
    def favicon() -> ResponseReturnValue:
        return Response(status=204)

    @app.get("/api/health")
    def health() -> ResponseReturnValue:
        return jsonify(
            {
                "ok": True,
                "version": __version__,
                "mode": "local-read-only",
                "data_dir": str(config.paths.data_dir),
            }
        )

    @app.post("/api/scan")
    def start_scan() -> ResponseReturnValue:
        body = request.get_json(silent=True) or {}
        input_type = str(body.get("input_type", "url")).lower()
        value = str(body.get("value", "")).strip()
        options = _allowed_options(body.get("options", {}))
        if options.get("show_secrets") and not body.get("confirm_secrets"):
            return jsonify({"error": "show_secrets requires confirm_secrets=true"}), 400
        if input_type in {"url", "html"} and not _validate_url(value):
            return jsonify({"error": "valid http(s) URL required"}), 400
        if input_type == "dir" and not Path(value).is_dir():
            return jsonify({"error": "directory not found"}), 400
        if input_type == "har" and not Path(value).is_file():
            return jsonify({"error": "HAR file not found"}), 400
        if input_type == "clipboard" and not value:
            try:
                import pyperclip

                value = pyperclip.paste()
            except Exception:
                value = ""
            if not value.strip():
                return jsonify({"error": "clipboard is empty or unavailable"}), 400
        if not value:
            return jsonify({"error": "value is required"}), 400
        if input_type not in {"url", "html", "dir", "har", "list", "clipboard"}:
            return jsonify({"error": "unsupported input_type"}), 400
        scan_id = manager.start(input_type, value, None, options)
        return jsonify({"ok": True, "scan_id": scan_id}), 202

    @app.post("/api/upload")
    def upload() -> ResponseReturnValue:
        kind = str(request.args.get("kind", "dir"))
        files = request.files.getlist("files")
        if not files:
            return jsonify({"error": "no files"}), 400
        upload_root = config.paths.data_dir / "uploads" / uuid.uuid4().hex
        upload_root.mkdir(parents=True, exist_ok=True)
        saved = 0
        for item in files:
            if not item.filename:
                continue
            if kind == "har":
                target = upload_root / _safe_relative(item.filename).name
            else:
                target = upload_root / _safe_relative(item.filename)
            target.parent.mkdir(parents=True, exist_ok=True)
            item.save(target)
            saved += 1
        if not saved:
            return jsonify({"error": "empty upload"}), 400
        if kind == "har":
            har_files = list(upload_root.glob("*.har")) + list(upload_root.glob("*.json"))
            if not har_files:
                return jsonify({"error": "no .har file found"}), 400
            return jsonify({"ok": True, "path": str(har_files[0]), "files": saved})
        return jsonify({"ok": True, "path": str(upload_root), "files": saved})

    @app.post("/api/clipboard")
    def clipboard() -> ResponseReturnValue:
        try:
            import pyperclip

            return jsonify({"ok": True, "text": pyperclip.paste()})
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc), "text": ""}), 503

    @app.get("/api/scans")
    def scans() -> ResponseReturnValue:
        return jsonify(storage.list_scans())

    @app.get("/api/scan/<int:scan_id>")
    def scan_detail(scan_id: int) -> ResponseReturnValue:
        data = storage.get_scan(scan_id)
        if data is None:
            return jsonify({"error": "scan not found"}), 404
        return jsonify(data)

    @app.post("/api/scan/<int:scan_id>/stop")
    def stop_scan(scan_id: int) -> ResponseReturnValue:
        if manager.stop(scan_id):
            return jsonify({"ok": True})
        return jsonify({"error": "scan is not running"}), 409

    @app.get("/api/scan/<int:scan_id>/events")
    def scan_events(scan_id: int) -> ResponseReturnValue:
        return Response(
            _stream_events(manager, scan_id),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
                "Connection": "keep-alive",
            },
        )

    @app.get("/api/report/<int:scan_id>/<path:name>")
    def report(scan_id: int, name: str) -> ResponseReturnValue:
        data = storage.get_scan(scan_id)
        if data is None:
            return jsonify({"error": "scan not found"}), 404
        directory = data["scan"].get("artifacts", {}).get("dir", "")
        if not directory:
            return jsonify({"error": "no artifacts"}), 404
        safe_name = Path(name).name
        if safe_name != name:
            return jsonify({"error": "invalid artifact"}), 400
        return send_from_directory(directory, safe_name, as_attachment=safe_name.endswith(".sh"))

    @app.get("/api/raw/<int:scan_id>/<path:name>")
    def raw(scan_id: int, name: str) -> ResponseReturnValue:
        data = storage.get_scan(scan_id)
        if data is None:
            return jsonify({"error": "scan not found"}), 404
        directory = Path(data["scan"].get("artifacts", {}).get("dir", "")) / "raw"
        safe_name = Path(name).name
        if safe_name != name or not directory.is_dir():
            return jsonify({"error": "invalid raw file"}), 400
        return send_from_directory(directory, safe_name, mimetype="text/plain; charset=utf-8")

    @app.get("/api/diff/<int:left>/<int:right>")
    def diff(left: int, right: int) -> ResponseReturnValue:
        return jsonify(storage.diff_scans(left, right))

    @app.delete("/api/history/<int:scan_id>")
    def delete_history(scan_id: int) -> ResponseReturnValue:
        if storage.delete_scan(scan_id):
            return jsonify({"ok": True})
        return jsonify({"error": "scan not found"}), 404

    return app


def run_ui(config: AppConfig | None = None, open_browser: bool | None = None) -> None:
    config = config or load_config()
    app = create_app(config)
    should_open = config.server.open_browser if open_browser is None else open_browser
    url = f"http://{config.server.host}:{config.server.port}"
    if should_open:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    print(f"JS-Endpoints-Hunter {__version__}: {url}")
    print(f"Data directory: {config.paths.data_dir}")
    app.run(
        host=config.server.host,
        port=config.server.port,
        debug=False,
        use_reloader=False,
        threaded=True,
    )

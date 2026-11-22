from __future__ import annotations

import base64
import json
from pathlib import Path

from jsh.parsers.har import parse_har
from jsh.parsers.html import parse_html, parse_manifest
from jsh.parsers.sourcemap import find_source_map_url, parse_source_map


def test_html_scripts_preload_importmap_and_manifest():
    html = """
    <html><head>
      <link rel="preload" as="script" href="/pre.js">
      <link rel="modulepreload" href="/module.mjs">
      <link rel="manifest" href="/manifest.json">
      <script src="/a.js"></script>
      <script type="module" src="/b.mjs"></script>
      <script type="importmap">{"imports":{"react":"/react.js"}}</script>
      <script>fetch("/inline")</script>
    </head></html>
    """
    doc = parse_html(html, "https://example.com/page")
    urls = {ref.url for ref in doc.scripts}
    assert "https://example.com/a.js" in urls
    assert "https://example.com/b.mjs" in urls
    assert "https://example.com/pre.js" in urls
    assert "https://example.com/module.mjs" in urls
    assert "https://example.com/react.js" in urls
    assert doc.manifests == ["https://example.com/manifest.json"]
    assert any(ref.inline == 'fetch("/inline")' for ref in doc.scripts)


def test_manifest_bundle_urls():
    refs = parse_manifest(
        '{"main":"/static/main.js","bundle":["/static/a.js"]}', "https://example.com"
    )
    assert {ref.url for ref in refs} == {
        "https://example.com/static/main.js",
        "https://example.com/static/a.js",
    }


def test_sourcemap_comment_and_sources():
    js = 'fetch("/api");\n//# sourceMappingURL=app.js.map'
    assert find_source_map_url(js) == "app.js.map"
    data = {
        "version": 3,
        "sources": ["src/app.ts"],
        "sourcesContent": ['fetch("/api/original");'],
    }
    parsed = parse_source_map(json.dumps(data), "https://example.com/app.js.map")
    assert parsed.sources[0].name == "src/app.ts"
    assert "/api/original" in parsed.sources[0].content


def test_har_base64_and_html(tmp_path: Path):
    js = 'fetch("/api/v1/from-har")'
    har = {
        "log": {
            "entries": [
                {
                    "request": {"url": "https://example.com/app.js"},
                    "response": {
                        "content": {
                            "mimeType": "application/javascript",
                            "encoding": "base64",
                            "text": base64.b64encode(js.encode()).decode(),
                        }
                    },
                },
                {
                    "request": {"url": "https://example.com/page"},
                    "response": {
                        "content": {
                            "mimeType": "text/html",
                            "text": "<html><script>fetch('/api/v1/inline')</script></html>",
                        }
                    },
                },
                {
                    "request": {"url": "https://example.com/missing.js"},
                    "response": {"content": {"mimeType": "application/javascript"}},
                },
            ]
        }
    }
    path = tmp_path / "capture.har"
    path.write_text(json.dumps(har), encoding="utf-8")
    data = parse_har(path)
    assert len(data.resources) == 2
    assert any("from-har" in item.content for item in data.resources)
    assert any(item.is_html for item in data.resources)
    assert data.missing_js == ["https://example.com/missing.js"]

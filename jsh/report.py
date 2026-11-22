from __future__ import annotations

import csv
import html
import io
import json
import re
from pathlib import Path
from typing import Any

from . import __version__
from .models import Finding, ScanResult
from .utils import human_bytes, shell_quote


def _endpoints(data: dict[str, Any]) -> list[dict[str, Any]]:
    return [item for item in data["findings"] if item["kind"] != "secret"]


def _secrets(data: dict[str, Any]) -> list[dict[str, Any]]:
    return [item for item in data["findings"] if item["kind"] == "secret"]


def _display_url(item: dict[str, Any]) -> str:
    value = str(item.get("value", ""))
    if value.startswith(("http://", "https://", "ws://", "wss://")):
        return value
    host = item.get("host") or "<HOST>"
    return f"https://{host}{value}"


def _placeholder(value: str) -> str:
    return re.sub(r"\{[^}]+\}", "<PARAM>", value)


def _redact_raw(content: str, findings: list[Finding], show_secrets: bool) -> str:
    if show_secrets:
        return content
    for finding in findings:
        if finding.is_secret and finding.raw and finding.masked:
            content = content.replace(finding.raw, finding.masked)
    return content


def _write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8", errors="replace")


def _markdown_table(rows: list[list[str]], header: list[str]) -> str:
    def clean(value: str) -> str:
        return value.replace("|", "\\|").replace("\n", " ")

    lines = ["| " + " | ".join(header) + " |", "| " + " | ".join("---" for _ in header) + " |"]
    lines.extend("| " + " | ".join(clean(str(cell)) for cell in row) + " |" for row in rows)
    return "\n".join(lines)


def _sarif_uri(source: str) -> str:
    # Source maps use "bundle.js:src/file.ts" for display; SARIF needs one file.
    value = str(source or "").replace("\\", "/")
    return value if "://" in value else value.split(":", 1)[0]


def _sarif(data: dict[str, Any]) -> str:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for item in data["findings"]:
        is_secret = item["kind"] == "secret"
        rule_id = (
            f"jseh/secret/{item.get('secret_type') or 'secret'}"
            if is_secret
            else f"jseh/{item['kind']}"
        )
        severity = item.get("severity", "") if is_secret else ""
        level = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note"}.get(severity, "note")
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": (item.get("secret_type") or item["kind"]).replace("_", " ").title(),
                "shortDescription": {"text": f"JavaScript {item['kind']} finding"},
                "defaultConfiguration": {"level": level},
            },
        )
        results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": f"{item['kind']}: {item.get('value', '')}"
                    + (f" ({item.get('severity')})" if severity else "")
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": _sarif_uri(item.get("source", ""))},
                            "region": {"startLine": max(1, int(item.get("line") or 1))},
                        }
                    }
                ],
                "properties": {
                    "confidence": item.get("confidence", 0),
                    "origin": item.get("origin", ""),
                    "host": item.get("host", ""),
                },
            }
        )
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "JS-Endpoints-Hunter",
                        "version": __version__,
                        "informationUri": "https://github.com/your_handle/js-endpoints-hunter",
                        "rules": list(rules.values()),
                    }
                },
                "originalUriBaseIds": {"SRCROOT": {"uri": "file:///"}},
                "results": results,
            }
        ],
    }
    return json.dumps(document, ensure_ascii=False, indent=2)


def _report_markdown(result: ScanResult, data: dict[str, Any]) -> str:
    endpoints = _endpoints(data)
    secrets = _secrets(data)
    stats = data["stats"]
    lines = [
        f"# JS-Endpoints-Hunter - {html.escape(result.target)}",
        "",
        f"- Режим: `{result.input_type}`",
        f"- Статус: `{result.status}`",
        f"- Начало: `{result.started_at}`",
        f"- Файлов: **{stats.get('files', 0)}** · Endpoint'ов: **{stats.get('endpoints', 0)}** · "
        f"Секретов: **{stats.get('secrets', 0)}** · Хостов: **{stats.get('hosts', 0)}**",
        "",
        "> Инструмент только читает JS/HTML/JSON. Секреты по умолчанию замаскированы.",
        "",
        "## Endpoints",
        "",
    ]
    if endpoints:
        lines.append(
            _markdown_table(
                [
                    [
                        item["value"],
                        item["method"] or "-",
                        item["kind"],
                        f"{item['source']}:{item['line']}",
                        str(item["confidence"]),
                    ]
                    for item in endpoints
                ],
                ["Path", "Method", "Type", "Source", "Confidence"],
            )
        )
    else:
        lines.append("_Не найдено._")
    lines.extend(["", "## Secrets", ""])
    if secrets:
        lines.append(
            _markdown_table(
                [
                    [
                        item.get("secret_type", ""),
                        item.get("masked") or item["value"],
                        item.get("severity", ""),
                        f"{item['source']}:{item['line']}",
                    ]
                    for item in secrets
                ],
                ["Type", "Masked value", "Severity", "Source"],
            )
        )
    else:
        lines.append("_Не найдено._")
    lines.extend(["", "## Hosts", ""])
    (
        lines.extend(f"- `{host}`" for host in data.get("hosts", []))
        if data.get("hosts")
        else lines.append("_Не найдено._")
    )
    lines.extend(["", "## Top prefixes", ""])
    prefixes = stats.get("top_prefixes", [])
    if prefixes:
        lines.append(
            _markdown_table([[p["prefix"], str(p["count"])] for p in prefixes], ["Prefix", "Count"])
        )
    else:
        lines.append("_Нет данных._")
    if data.get("dependencies"):
        lines.extend(["", "## Dependencies", ""])
        lines.append(
            _markdown_table(
                [[d["name"], d["version"], d["cve_search"]] for d in data["dependencies"]],
                ["Package", "Version", "NVD search"],
            )
        )
    lines.extend(
        [
            "",
            "---",
            "Отчёт JS-Endpoints-Hunter. Используйте только на своих или разрешённых целях.",
            "",
        ]
    )
    return "\n".join(lines)


def _report_html(result: ScanResult, data: dict[str, Any]) -> str:
    payload = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    title = html.escape(f"JS-Endpoints-Hunter - {result.target}")
    stats = data["stats"]
    summary = f"""
    <section class="summary">
      <div><span>Endpoint'ы</span><strong>{stats.get('endpoints', 0)}</strong></div>
      <div><span>Секреты</span><strong>{stats.get('secrets', 0)}</strong></div>
      <div><span>Хосты</span><strong>{stats.get('hosts', 0)}</strong></div>
      <div><span>Файлы</span><strong>{stats.get('files', 0)}</strong></div>
      <div><span>Объём</span><strong>{human_bytes(int(stats.get('bytes', 0)))}</strong></div>
    </section>
    """
    return (
        '<!doctype html><html lang="ru"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{title}</title><style>{_REPORT_CSS}</style></head><body>"
        f'<header><div><span class="kicker">JS-ENDPOINTS-HUNTER</span><h1>{title}</h1>'
        f'<p class="meta">{html.escape(result.input_type)} · {html.escape(result.status)} · '
        f'{html.escape(result.started_at)}</p></div><span class="badge">offline report</span></header>'
        f"{summary}"
        '<main><div class="toolbar"><input id="search" placeholder="Фильтр: /api, billing, host…">'
        '<select id="type"><option value="">Все типы</option><option>rest</option><option>graphql</option>'
        "<option>websocket</option><option>sse</option><option>absolute</option><option>path</option>"
        '<option>file</option></select><button id="copy">Copy paths</button></div>'
        '<section class="panel"><h2>Endpoints <small id="ep-count"></small></h2>'
        '<div class="table-wrap"><table><thead><tr><th>Path</th><th>Method</th><th>Type</th>'
        '<th>Source</th><th>Confidence</th></tr></thead><tbody id="endpoints"></tbody></table></div></section>'
        '<section class="panel"><h2>Secrets</h2><div class="table-wrap"><table><thead><tr>'
        "<th>Type</th><th>Masked value</th><th>Severity</th><th>Source</th></tr></thead>"
        '<tbody id="secrets"></tbody></table></div></section>'
        '<section class="panel"><h2>Hosts</h2><div id="hosts" class="chips"></div></section>'
        '<section class="panel"><h2>Top prefixes</h2><div id="prefixes" class="chips"></div></section>'
        "</main><footer>Только чтение публичных JS/HTML/JSON. Секреты маскируются. "
        "Используйте только на разрешённых целях.</footer>"
        f"<script>const DATA = {payload};</script><script>{_REPORT_JS}</script></body></html>"
    )


def generate_report(
    result: ScanResult,
    out_dir: Path,
    show_secrets: bool = False,
) -> dict[str, str]:
    out_dir = out_dir.expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    raw_dir = out_dir / "raw"
    raw_dir.mkdir(exist_ok=True)

    data = result.to_dict(show_secrets=show_secrets)
    endpoints = _endpoints(data)
    secrets = _secrets(data)

    (out_dir / "report.json").write_text(
        json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    _write(out_dir / "report.md", _report_markdown(result, data))
    _write(out_dir / "report.html", _report_html(result, data))
    _write(out_dir / "report.sarif", _sarif(data))
    _write(
        out_dir / "findings.jsonl",
        "\n".join(json.dumps(item, ensure_ascii=False) for item in data["findings"])
        + ("\n" if data["findings"] else ""),
    )

    _write(
        out_dir / "endpoints.txt",
        "\n".join(item["value"] for item in endpoints) + ("\n" if endpoints else ""),
    )
    csv_buffer = io.StringIO()
    writer = csv.writer(csv_buffer, lineterminator="\n")
    writer.writerow(["path", "method", "type", "source", "line", "confidence"])
    for item in endpoints:
        writer.writerow(
            [
                item["value"],
                item["method"],
                item["kind"],
                item["source"],
                item["line"],
                item["confidence"],
            ]
        )
    _write(out_dir / "endpoints.csv", csv_buffer.getvalue())

    _write(
        out_dir / "secrets.txt",
        "\n".join(
            f"{item.get('secret_type', '')}\t{item.get('masked') or item['value']}\t"
            f"{item['source']}:{item['line']}\t{item.get('severity', '')}"
            for item in secrets
        )
        + ("\n" if secrets else ""),
    )
    _write(
        out_dir / "hosts.txt",
        "\n".join(data.get("hosts", [])) + ("\n" if data.get("hosts") else ""),
    )
    _write(
        out_dir / "nuclei-targets.txt",
        "\n".join(sorted({_placeholder(_display_url(item)) for item in endpoints})) + "\n",
    )
    _write(out_dir / "curl-commands.sh", _curl_commands(endpoints))
    _write(out_dir / "ffuf-commands.sh", _ffuf_commands(data.get("hosts", [])))

    raw_index: list[dict[str, str]] = []
    for raw in result.raw_files:
        content = _redact_raw(raw.content, result.findings, show_secrets)
        filename = raw.name
        _write(raw_dir / filename, content)
        raw_index.append(
            {
                "name": filename,
                "url": raw.url,
                "origin": raw.origin,
                "map_url": raw.map_url,
                "sha256": raw.sha256,
            }
        )
    _write(raw_dir / "index.json", json.dumps(raw_index, ensure_ascii=False, indent=2))

    artifacts = {
        "dir": str(out_dir),
        "report.html": "report.html",
        "report.md": "report.md",
        "report.json": "report.json",
        "report.sarif": "report.sarif",
        "findings.jsonl": "findings.jsonl",
        "endpoints.txt": "endpoints.txt",
        "endpoints.csv": "endpoints.csv",
        "secrets.txt": "secrets.txt",
        "curl-commands.sh": "curl-commands.sh",
        "ffuf-commands.sh": "ffuf-commands.sh",
        "nuclei-targets.txt": "nuclei-targets.txt",
        "hosts.txt": "hosts.txt",
    }
    return artifacts


def _curl_commands(endpoints: list[dict[str, Any]]) -> str:
    lines = [
        "#!/usr/bin/env sh",
        "# JS-Endpoints-Hunter output. Review targets before running.",
        "# <TOKEN> and <PARAM> are placeholders; no payload is generated.",
        "",
    ]
    for item in endpoints:
        url = _placeholder(_display_url(item))
        method = item.get("method") or "GET"
        lines.append(f"# {item['kind']} {item['source']}:{item['line']}")
        lines.append(f"curl -sS -X {method} {shell_quote(url)}")
        if any(word in item["value"].lower() for word in ("auth", "account", "billing", "admin")):
            lines.append("# add: -H 'Authorization: Bearer <TOKEN>'")
        lines.append("")
    return "\n".join(lines)


def _ffuf_commands(hosts: list[str]) -> str:
    lines = [
        "#!/usr/bin/env sh",
        "# JS-Endpoints-Hunter output. Use only on authorized hosts.",
        "",
    ]
    for host in hosts:
        if not host:
            continue
        lines.append(
            f"ffuf -u {shell_quote(f'https://{host}/FUZZ')} -w wordlist.txt "
            "-mc 200,204,301,302,401,403 -rate 5"
        )
    return "\n".join(lines) + "\n"


_REPORT_CSS = """
:root{color-scheme:dark;--bg:#0b0d10;--panel:#14181d;--line:#262c34;--text:#e6edf3;--muted:#8b949e;--accent:#7c9cff;--good:#7ee787;--warn:#f2cc60;--bad:#ff7b72}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(900px 500px at 15% -10%,#1a2440 0,transparent 60%),var(--bg);color:var(--text);font:14px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
header{display:flex;justify-content:space-between;align-items:flex-start;padding:40px 5vw 20px;gap:20px}h1{margin:4px 0;font-size:30px;letter-spacing:-.04em}.kicker,.meta{color:var(--muted);font-size:12px;letter-spacing:.12em}.badge{border:1px solid var(--line);border-radius:99px;padding:6px 10px;color:var(--muted);font-size:12px}
.summary{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px;padding:0 5vw 20px}.summary div{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:14px}.summary span{display:block;color:var(--muted);font-size:12px}.summary strong{font-size:24px}
main{padding:0 5vw 40px}.toolbar{display:flex;gap:10px;margin:8px 0 16px}input,select,button{background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:10px;padding:10px 12px;font:inherit}input{flex:1}button{cursor:pointer}button:hover{border-color:var(--accent)}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:16px;margin:14px 0}h2{font-size:14px;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);margin:0 0 12px}h2 small{float:right;color:var(--muted);font-weight:400}
.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse;font-family:"JetBrains Mono",ui-monospace,Consolas,monospace;font-size:12.5px}th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:500;position:sticky;top:0;background:var(--panel)}td:first-child{color:#c9d7ff;word-break:break-all}tr:hover td{background:#191f26}
.chips{display:flex;flex-wrap:wrap;gap:8px}.chip{border:1px solid var(--line);background:#101419;border-radius:99px;padding:6px 10px;font-family:"JetBrains Mono",monospace;font-size:12px}.sev-HIGH{color:var(--bad)}.sev-MEDIUM{color:var(--warn)}.sev-LOW{color:var(--good)}
footer{padding:0 5vw 40px;color:var(--muted);font-size:12px}@media(max-width:800px){.summary{grid-template-columns:repeat(2,1fr)}header{flex-direction:column}}
"""

_REPORT_JS = r"""
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const endpoints = DATA.findings.filter(f => f.kind !== 'secret');
const secrets = DATA.findings.filter(f => f.kind === 'secret');
function render() {
  const q = $('#search').value.toLowerCase(); const type = $('#type').value;
  const list = endpoints.filter(f => (!type || f.kind === type) && (!q || (f.value + ' ' + f.source + ' ' + f.host).toLowerCase().includes(q)));
  $('#ep-count').textContent = `${list.length}/${endpoints.length}`;
  $('#endpoints').innerHTML = list.map(f => `<tr><td>${esc(f.value)}</td><td>${esc(f.method || '-')}</td><td>${esc(f.kind)}</td><td>${esc(f.source)}:${f.line}</td><td>${f.confidence}</td></tr>`).join('');
  $('#secrets').innerHTML = secrets.map(f => `<tr><td>${esc(f.secret_type)}</td><td>${esc(f.masked || f.value)}</td><td class="sev-${esc(f.severity)}">${esc(f.severity)}</td><td>${esc(f.source)}:${f.line}</td></tr>`).join('');
  $('#hosts').innerHTML = (DATA.hosts || []).map(h => `<span class="chip">${esc(h)}</span>`).join('');
  $('#prefixes').innerHTML = (DATA.stats.top_prefixes || []).map(p => `<span class="chip">${esc(p.prefix)} · ${p.count}</span>`).join('');
}
$('#search').addEventListener('input', render);
$('#type').addEventListener('change', render);
$('#copy').addEventListener('click', async () => {
  await navigator.clipboard.writeText(endpoints.map(f => f.value).join('\n'));
  $('#copy').textContent = 'Copied!'; setTimeout(() => $('#copy').textContent = 'Copy paths', 1200);
});
render();
"""

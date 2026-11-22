# JS-Endpoints-Hunter

Локальная утилита для разбора JavaScript-бандлов. Находит API-пути, GraphQL-запросы,
WebSocket/SSE, воркеры и секреты в JS, source maps, HAR и папках с фронтендом.
Работает на компьютере пользователя, без облака и без отправки результатов наружу.

Проект рассчитан на ручную проверку: он показывает кандидатов и контекст, но не
отправляет эксплойты и не проверяет догадки запросами.

## Что ищет

- вызовы `fetch`, `axios`, `XMLHttpRequest`, `$.ajax`, `got`, `ky`, `wretch`;
- относительные и абсолютные URL, шаблонные строки вида `/api/users/${id}`;
- GraphQL-пути и маркеры introspection;
- OpenAPI/Swagger-кандидаты, WebSocket, EventSource, Worker и service worker;
- AWS, GCP, Stripe, GitHub, JWT, private key, Bearer и generic-секреты;
- строковые константы, чтобы `const API = "/api/v1"` не терялся в шаблонах;
- source maps, включая `sourcesContent`, `sections` и соседние `.map`-файлы.

Секреты по умолчанию маскируются. Флаг `--show-secrets` требует подтверждения.

## Запуск

Windows:

```bat
run.bat
```

macOS и Linux:

```sh
./run.sh
```

Скрипт создаст `.venv`, установит зависимости и откроет `http://127.0.0.1:8765`.

Вручную:

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Для Python 3.10 нужен `tomli`, он уже указан в `requirements.txt`.

## CLI

```bash
python jsh.py scan https://example.com/static/billing.js
python jsh.py scan --html https://example.com
python jsh.py scan --dir ./js-dump
python jsh.py scan --har ./capture.har
python jsh.py scan --list urls.txt --concurrency 10
python jsh.py scan --dir ./js-dump --entropy --allowlist allowlist.txt
python jsh.py scan --dir ./js-dump --format sarif
python jsh.py scan --dir ./js-dump --baseline old/report.json --fail-on-new
python jsh.py scan --dir ./js-dump --fail-on-severity high
python jsh.py history --since 7d --search example
python jsh.py report ./results/report.json --format md
python jsh.py diff ./results/old ./results/new
```

`--fail-on-new` возвращает код 4, `--fail-on-severity` - код 5. Это удобно для CI.

## Что получается на выходе

```text
~/.js-endpoints-hunter/results/20250115_143022/
├── report.html
├── report.md
├── report.json
├── report.sarif
├── findings.jsonl
├── endpoints.txt
├── endpoints.csv
├── secrets.txt
├── curl-commands.sh
├── ffuf-commands.sh
├── nuclei-targets.txt
├── hosts.txt
└── raw/
```

`report.html` открывается без интернета. В `raw/` лежат исходники, из которых уже
вырезаны найденные секреты, если не включён `--show-secrets`.

## Настройки

Основные параметры лежат в `config.toml`:

- `server.host` и `server.port` - адрес локального UI;
- `scan.timeout`, `scan.concurrency`, `scan.rate_limit` - сеть;
- `scan.download_maps`, `scan.harvest_maps` - source maps;
- `scan.entropy_secrets` - дополнительная эвристика;
- `scan.allowlist_file` - файл исключений;
- `scan.proxy` - Burp или Caido;
- `paths.data_dir` - база, кэш и результаты.

Часть параметров переопределяется через `JSH_HOST`, `JSH_PORT`, `JSH_DATA_DIR`,
`JSH_TIMEOUT`, `JSH_CONCURRENCY`, `JSH_RATE_LIMIT` и `JSH_PROXY`.

## Тесты

```bash
pip install -r requirements-dev.txt
black .
ruff check .
mypy jsh
python -m pytest --cov=jsh --cov-report=term-missing
```

В текущей версии 38 тестов, покрытие около 76%. Все проверки проходят.

## Сборка

```bash
python scripts/build_zipapp.py
pyinstaller --noconfirm packaging/jsh.spec
```

Zipapp лежит в `dist/js-endpoints-hunter.pyz` и использует пакеты из активного интерпретатора.
PyInstaller собирает `dist/js-endpoints-hunter.exe` со всем необходимым.

Есть `Dockerfile` и workflow для GitHub Actions. Docker в этой среде не проверялся.

## Ограничения

- Анализ JS остаётся в основном регулярным. Строковые константы разрешаются, но
  полноценного AST и data-flow нет.
- SPA, которые создают запросы только в браузере, не покрываются. Встроенного
  headless-браузера нет: страница может сама отправить POST, а инструмент работает
  только с GET.
- CVE-проверка ограничена ссылками на NVD по `package.json`, без онлайн-поиска OSV.

## Лицензия

MIT. См. [LICENSE](LICENSE) и [DISCLAIMER.md](DISCLAIMER.md).

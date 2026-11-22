FROM python:3.12-slim

RUN useradd --create-home --uid 10001 hunter
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY jsh ./jsh
COPY app.py jsh.py patterns.yaml config.toml ./
RUN mkdir -p /data && chown -R hunter:hunter /data /app
USER hunter
ENV JSH_DATA_DIR=/data
EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8765/api/health',timeout=2)" || exit 1

CMD ["python", "jsh.py", "ui", "--no-open", "--host", "0.0.0.0"]

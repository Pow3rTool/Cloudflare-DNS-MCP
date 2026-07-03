# Self-contained image for cloudflare-dns-mcp. Build from the repo root:
#   podman build -t cloudflare-dns-mcp .
# Runs as non-root; config + the CFDNS_API_TOKEN are injected at runtime (env), never baked.
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app

# deps installed globally (as root) so any runtime UID can import them
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .
RUN useradd --system --uid 10001 mcp
USER mcp

EXPOSE 8783
CMD ["python", "server.py"]

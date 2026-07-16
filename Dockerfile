# sentryd container image. Serves the web console + REST API on port 8000.
#
#   docker build -t sentryd .
#   docker run --rm -p 8000:8000 -v sentryd-data:/data sentryd
#
# Detection works with no configuration. To enable AI triage pass an
# OpenRouter key: -e OPENROUTER_API_KEY=... . To require an API token when
# exposing the port: -e SENTRYD_API_TOKEN=... .

FROM python:3.11-slim

# uv for fast, reproducible installs.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    SENTRYD_DB=/data/sentryd.db \
    SENTRYD_PCAP_DIR=/data/uploads \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app

# Install dependencies first (cached until the lockfile changes).
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-install-project --no-dev

# Then the application itself.
COPY src ./src
COPY config ./config
RUN uv sync --frozen --no-dev

# Runtime data (db + uploaded pcaps) lives on a volume owned by a non-root user.
RUN useradd --create-home --uid 10001 sentryd \
    && mkdir -p /data/uploads \
    && chown -R sentryd:sentryd /data /app
USER sentryd
VOLUME ["/data"]

EXPOSE 8000
ENTRYPOINT ["sentryd"]
CMD ["web", "--host", "0.0.0.0", "--port", "8000"]

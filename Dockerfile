# Stdio MCP server for local clients and for Glama introspection.
# Starts without capture privileges, nmap, or tcpdump; tools can still be listed.
FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN pip install --no-cache-dir ".[mcp]" \
    && useradd --create-home --uid 1000 --shell /usr/sbin/nologin iotaudit

USER iotaudit

ENTRYPOINT ["iotaudit-mcp"]

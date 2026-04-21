FROM ghcr.io/astral-sh/uv:0.8.15 AS uv

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME="/home/warden" \
    TMPDIR="/tmp/oss-warden-analysis" \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
    && rm -rf /var/lib/apt/lists/*

COPY --from=uv /uv /uvx /bin/

RUN useradd \
        --create-home \
        --home-dir /home/warden \
        --shell /usr/sbin/nologin \
        --uid 10001 \
        warden \
    && mkdir -p /app /tmp/oss-warden-analysis \
    && chown -R warden:warden /app /home/warden /tmp/oss-warden-analysis

USER warden

COPY --chown=warden:warden pyproject.toml uv.lock /app/

RUN uv sync --frozen --no-dev --no-install-project

USER root

RUN rm -f /bin/uv /bin/uvx \
    && mkdir -p /app/site/data/queue /app/site/data/reports /tmp/oss-warden-analysis

COPY --chown=warden:warden . /app

EXPOSE 12000

USER warden

ENTRYPOINT ["python", "service_runner.py"]
CMD ["server"]

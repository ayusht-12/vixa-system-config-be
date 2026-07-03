FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv/app

COPY pyproject.toml README.md ./
COPY app ./app

RUN pip install .

COPY alembic.ini ./
COPY alembic ./alembic
COPY scripts ./scripts
COPY docker-entrypoint.sh ./

RUN chmod +x docker-entrypoint.sh \
    && useradd --create-home --uid 1000 appuser \
    && mkdir -p var \
    && chown -R appuser:appuser /srv/app
USER appuser

EXPOSE 8000

ENTRYPOINT ["./docker-entrypoint.sh"]

# Mirrors cactus-deploy/docker/cactus-orchestrator/Dockerfile, except it builds from the
# local checkout instead of cloning a release tag.
FROM python:3.12-slim-bookworm AS builder
COPY --from=ghcr.io/astral-sh/uv:0.11.16 /uv /bin/uv

# pre-compile .pyc at build time for faster startup; copy instead of hardlink (cache mount
# requirement); strip dev deps; use the image's Python rather than downloading a new one
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_NO_DEV=1 \
    UV_PYTHON_DOWNLOADS=0

# git is needed for the git-sourced dependencies in uv.lock
RUN apt-get update && apt-get install --no-install-recommends -y git && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml uv.lock setup.cfg alembic.ini /app/
COPY alembic /app/alembic
COPY src /app/src

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-editable && \
    uv pip install "uvicorn==0.48.0"

# Record the alembic head this image expects, so cactus-deploy's update.sh can refuse to
# deploy against a database that hasn't had this migration applied yet.
# --no-sync: `uv run` re-syncs the environment, breaking --no-editable above
RUN uv run --no-sync alembic heads | awk '{print $1}' > /app/ALEMBIC_HEAD && \
    test "$(wc -l < /app/ALEMBIC_HEAD)" -eq 1

# RUN stage
FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install --no-install-recommends -y postgresql && rm -rf /var/lib/apt/lists/*

RUN useradd -ms /bin/bash appuser

COPY --from=builder --chown=appuser:appuser /app/.venv /app/.venv
COPY --from=builder --chown=appuser:appuser /app/ALEMBIC_HEAD /app/ALEMBIC_HEAD

USER appuser

# conf
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV LOG_LEVEL=info
CMD uvicorn --host 0.0.0.0 --port 8080 --workers 1 --log-level "${LOG_LEVEL}" cactus_orchestrator.main:app

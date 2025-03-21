FROM python:3.12-slim
WORKDIR /app/

# python conf
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Copy src
COPY ./src /app/src
COPY ./pyproject.toml /app/pyproject.toml

# Install deps
RUN pip install --no-cache-dir -e /app && pip install --no-cache-dir uvicorn

# Entrypoint
CMD ["uvicorn", "--host", "0.0.0.0", "--port", "8080", "--workers", "1", "cactus_orchestrator.main:app"]

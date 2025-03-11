FROM python:3.12


# Copy src
COPY ./src /app/src
COPY ./pyproject.toml /app/pyproject.toml

# Install deps
RUN pip install --no-cache-dir /app

# Entrypoint
CMD ["uvicorn", "--host", "0.0.0.0", "--port", "8080", "--workers", "1", "harness_orchestrator.main:app"]

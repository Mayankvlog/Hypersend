FROM python:3.11-slim

ENV DOCKER_BUILDKIT=1
ENV COMPOSE_DOCKER_CLI_BUILD=1

WORKDIR /app

# Install system dependencies with IPv4 enforcement
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    tzdata \
    ca-certificates \
    gosu \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies with IPv4 enforcement and timeout
# Build context is repo root; backend requirements live under backend/
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt --timeout=60 --retries=3

# Copy repo root into image so tests can read docker-compose/nginx/frontend files
COPY . /app/

# Create empty __init__.py at /app level if not exists
RUN touch /app/__init__.py

# Runtime environment - Optimize memory allocator
ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/backend:/app \
    DATA_ROOT=/data \
    PYTHONMALLOC=malloc

ARG DOCKERHUB_USERNAME
ARG DOCKERHUB_TOKEN

# Create data directory with proper permissions
RUN mkdir -p /data/tmp /data/files

# Create app user and set proper permissions
RUN groupadd -r appuser && useradd -r -g appuser -u 1000 appuser && \
    mkdir -p /app/storage /app/temp /app/uploads /app/data/files /app/data/avatars && \
    chmod -R 755 /app/storage /app/temp /app/uploads /app/data && \
    chown -R appuser:appuser /app/storage /app/temp /app/uploads /app/data /data

# Copy entrypoint script and make it executable
COPY backend/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Health check (inside container) - More robust health check
HEALTHCHECK --interval=30s --timeout=15s --start-period=180s --retries=3 \
  CMD curl -f http://hypersend_backend:8000/api/v1/health || exit 1

# Start FastAPI with single process to ensure startup event and handlers share global state
WORKDIR /app/backend
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--loop", "uvloop", "--http", "httptools"]

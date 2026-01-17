FROM python:3.11-slim

ENV DOCKER_BUILDKIT=1
ENV COMPOSE_DOCKER_CLI_BUILD=1

WORKDIR /app

# Install system dependencies with IPv4 enforcement
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    tzdata \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies with IPv4 enforcement and timeout
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt --timeout=60 --retries=3

# Create the directory structure for proper imports
RUN mkdir -p /app/backend

# Copy all backend files to /app/backend/
COPY . /app/backend/

# Create empty __init__.py at /app level if not exists
RUN touch /app/__init__.py

# Runtime environment

# Runtime environment - Optimize memory allocator
ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    DATA_ROOT=/data \
    PYTHONMALLOC=malloc

# Create data directory
RUN mkdir -p /data/tmp /data/files

# Health check (inside container) - More robust health check
HEALTHCHECK --interval=30s --timeout=15s --start-period=180s --retries=3 \
  CMD curl -f http://127.0.0.1:8000/health || exit 1

# Start FastAPI with optimized workers
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--loop", "uvloop", "--http", "httptools"]

FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    tzdata \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create the directory structure for proper imports
RUN mkdir -p /app/backend

# Copy all backend files to /app/backend/
COPY . /app/backend/

# Create empty __init__.py at /app level if not exists
RUN touch /app/__init__.py

# Runtime environment
ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    DATA_ROOT=/data

# Create data directory
RUN mkdir -p /data/tmp /data/files

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

# Start FastAPI
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]

FROM python:3.11-slim

WORKDIR /app

# Optional system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    tzdata ca-certificates && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend source as a Python package at /app/backend
COPY . /app/backend

# Runtime env
ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    DATA_ROOT=/data

EXPOSE 8000

# Start FastAPI (imports from package "backend")
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]

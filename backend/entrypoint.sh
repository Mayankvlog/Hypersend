#!/bin/bash
set -e

# Change to the backend directory
cd /app/backend

# Create necessary directories if they don't exist
mkdir -p /data/tmp /data/files /app/storage /app/temp /app/uploads /app/data/files /app/data/avatars

# Set proper permissions
chown -R appuser:appuser /app/storage /app/temp /app/uploads /app/data /data 2>/dev/null || true

# Run any database migrations or setup if needed
# python -m alembic upgrade head 2>/dev/null || true

# Execute the command passed as arguments
exec "$@"

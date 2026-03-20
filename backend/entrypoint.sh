#!/bin/bash
set -e

# Change to the backend directory
cd /app/backend

# Create necessary directories if they don't exist
mkdir -p /data/tmp /data/files /app/storage /app/temp /app/uploads /app/data/files /app/data/avatars

# Set proper permissions
chown -R appuser:appuser /app/storage /app/temp /app/uploads /app/data /data 2>/dev/null || true

# Handle optional AWS credentials - only export if non-empty to allow AWS SDK credential chain fallback
if [ -n "$AWS_ACCESS_KEY_ID" ] && [ "$AWS_ACCESS_KEY_ID" != "" ]; then
    export AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID"
fi

if [ -n "$AWS_SECRET_ACCESS_KEY" ] && [ "$AWS_SECRET_ACCESS_KEY" != "" ]; then
    export AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY"
fi

# Run any database migrations or setup if needed
# python -m alembic upgrade head 2>/dev/null || true

# Execute the command passed as arguments
exec "$@"

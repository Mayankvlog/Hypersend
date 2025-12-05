FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app.py .
COPY api_client.py .
COPY theme.py .
COPY update_manager.py .
COPY permissions_manager.py .
COPY assets ./assets
COPY views ./views
COPY __init__.py .

# Expose port
EXPOSE 8550

# Run the application with Python directly (Flet web mode)
CMD ["python", "app.py"]

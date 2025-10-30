FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app.py .
COPY assets ./assets

# Expose port
EXPOSE 8550

# Run the application
CMD ["flet", "run", "--web", "--port", "8550", "app.py"]

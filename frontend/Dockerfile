# Multi-stage build for Zaply Frontend
FROM python:3.11-slim as builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Runtime stage
FROM python:3.11-slim

WORKDIR /app
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY . .

# Create .env with VPS backend
RUN echo "API_BASE_URL=http://139.59.82.105:8000" > .env && \
    echo "DEBUG=False" >> .env

EXPOSE 5000

# Run Flet app
CMD ["python", "app.py"]

#!/bin/bash
# Initialize self-signed certificates for development
# This script creates development certificates in the letsencrypt volume

set -e

CERT_DIR="/etc/letsencrypt/live/zaply.in.net"
mkdir -p "$CERT_DIR"

# Check if certificates already exist
if [ -f "$CERT_DIR/fullchain.pem" ] && [ -f "$CERT_DIR/privkey.pem" ]; then
    echo "Certificates already exist, skipping generation"
    exit 0
fi

echo "Generating self-signed certificates for zaply.in.net..."

# Generate self-signed certificate valid for 365 days
openssl req -x509 -newkey rsa:2048 \
    -keyout "$CERT_DIR/privkey.pem" \
    -out "$CERT_DIR/fullchain.pem" \
    -days 365 -nodes \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=zaply.in.net" \
    -addext "subjectAltName=DNS:zaply.in.net,DNS:www.zaply.in.net"

echo "Certificates generated successfully at $CERT_DIR"
chmod 644 "$CERT_DIR/fullchain.pem"
chmod 600 "$CERT_DIR/privkey.pem"

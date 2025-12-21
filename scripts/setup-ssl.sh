#!/bin/bash
# Setup SSL certificates for zaply.in.net
# Run this script before starting docker-compose

DOMAIN="zaply.in.net"
SSL_DIR="./ssl"
LETSENCRYPT_CERT="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
LETSENCRYPT_KEY="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"

# Create SSL directory
mkdir -p "${SSL_DIR}"

# Check if Let's Encrypt certificates exist
if [ -f "${LETSENCRYPT_CERT}" ] && [ -f "${LETSENCRYPT_KEY}" ]; then
    echo "✅ Using Let's Encrypt certificates..."
    cp "${LETSENCRYPT_CERT}" "${SSL_DIR}/cert.pem"
    cp "${LETSENCRYPT_KEY}" "${SSL_DIR}/key.pem"
else
    echo "⚠️  Let's Encrypt certificates not found."
    echo "🔐 Generating self-signed certificates for ${DOMAIN}..."
    
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "${SSL_DIR}/key.pem" \
        -out "${SSL_DIR}/cert.pem" \
        -subj "/CN=${DOMAIN}/O=Hypersend/C=US"
    
    echo "✅ Self-signed certificates generated!"
    echo "📝 Note: For production, install Let's Encrypt certificates:"
    echo "   sudo certbot certonly --standalone -d ${DOMAIN}"
fi

# Set permissions
chmod 644 "${SSL_DIR}/cert.pem"
chmod 600 "${SSL_DIR}/key.pem"

echo "✅ SSL setup complete!"
echo "📍 Certificates location: ${SSL_DIR}/"


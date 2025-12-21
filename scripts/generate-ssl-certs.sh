#!/bin/bash
# Generate self-signed SSL certificates for zaply.in.net if Let's Encrypt certs don't exist

DOMAIN="zaply.in.net"
SSL_DIR="/etc/nginx/ssl"
LETSENCRYPT_CERT="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
LETSENCRYPT_KEY="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"

# Create SSL directory if it doesn't exist
mkdir -p "${SSL_DIR}"

# Check if Let's Encrypt certificates exist
if [ -f "${LETSENCRYPT_CERT}" ] && [ -f "${LETSENCRYPT_KEY}" ]; then
    echo "Let's Encrypt certificates found, using them..."
    # Copy Let's Encrypt certs to nginx SSL directory
    cp "${LETSENCRYPT_CERT}" "${SSL_DIR}/cert.pem"
    cp "${LETSENCRYPT_KEY}" "${SSL_DIR}/key.pem"
else
    echo "Let's Encrypt certificates not found, generating self-signed certificates..."
    # Generate self-signed certificate
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "${SSL_DIR}/key.pem" \
        -out "${SSL_DIR}/cert.pem" \
        -subj "/CN=${DOMAIN}/O=Hypersend/C=US"
    
    echo "Self-signed certificates generated at ${SSL_DIR}/"
    echo "WARNING: These are self-signed certificates. For production, use Let's Encrypt certificates."
fi

# Set proper permissions
chmod 644 "${SSL_DIR}/cert.pem"
chmod 600 "${SSL_DIR}/key.pem"

echo "SSL certificates ready at:"
echo "  Cert: ${SSL_DIR}/cert.pem"
echo "  Key: ${SSL_DIR}/key.pem"


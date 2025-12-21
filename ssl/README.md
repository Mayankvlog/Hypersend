# SSL Certificates Directory

This directory contains SSL certificates for `zaply.in.net`.

## Setup

Run the setup script before starting docker-compose:

```bash
bash scripts/setup-ssl.sh
```

Or manually generate self-signed certificates:

```bash
mkdir -p ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout ssl/key.pem \
  -out ssl/cert.pem \
  -subj '/CN=zaply.in.net/O=Hypersend/C=US'
```

## Production (Let's Encrypt)

For production, use Let's Encrypt certificates:

```bash
# Install certbot (if not already installed)
sudo apt-get update
sudo apt-get install certbot

# Generate certificates
sudo certbot certonly --standalone -d zaply.in.net

# Copy to ssl directory
sudo cp /etc/letsencrypt/live/zaply.in.net/fullchain.pem ssl/cert.pem
sudo cp /etc/letsencrypt/live/zaply.in.net/privkey.pem ssl/key.pem
sudo chmod 644 ssl/cert.pem
sudo chmod 600 ssl/key.pem
```

## Files

- `cert.pem` - SSL certificate (fullchain.pem for Let's Encrypt)
- `key.pem` - SSL private key


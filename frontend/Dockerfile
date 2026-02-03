FROM debian:bookworm AS build

# ✅ SECURITY: Use build args for flexibility and security updates

# Development: override with API_BASE_URL=http://localhost:8080/api/v1 in docker-compose build args
ARG API_BASE_URL=http://localhost:8000/api/v1

# LOGIC FIX: Add VALIDATE_CERTIFICATES build arg for flexible SSL configuration
# Production default: true (enforce valid SSL certificates)
# Development: set to false to allow self-signed certs
ARG VALIDATE_CERTIFICATES=true
# dist-upgrade ensures all security patches including critical/high severity CVEs are applied
# This ensures all CVEs in the base image layers are remediated before Flutter installation
RUN apt-get update && \
    apt-get dist-upgrade -y && \
    apt-get install -y --no-install-recommends \
    curl git unzip xz-utils zip ca-certificates && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /var/cache/apt/*

RUN git clone --depth 1 --branch 3.35.6 https://github.com/flutter/flutter.git /opt/flutter

ENV FLUTTER_HOME=/opt/flutter
ENV PATH="$FLUTTER_HOME/bin:$PATH"
ENV FLUTTER_SUPPRESS_ANALYTICS=true

RUN flutter precache --web && flutter config --enable-web

WORKDIR /app
COPY pubspec.yaml pubspec.lock ./
RUN rm -rf .pub-cache && flutter pub get

COPY . .

# ✅ CRITICAL FIX: Clean + Build with PROPER dart-define
RUN rm -rf build/ && flutter clean
# CRITICAL FIX: Build without source maps for production (reduces bundle size and 404 errors)
# Source maps are only needed for development debugging
# In production, they expose source code and cause 404 errors when not properly served
RUN flutter build web --release \
    --no-source-maps \
    --no-tree-shake-icons \
    --dart-define=API_BASE_URL=${API_BASE_URL} \
    --dart-define=VALIDATE_CERTIFICATES=${VALIDATE_CERTIFICATES} \
    --dart-define=ENVIRONMENT=production

# ==============================
# NGINX Production Server
# ==============================
FROM nginx:alpine

# ✅ SECURITY: Apply comprehensive security updates to nginx base image
# Update alpine package manager and apply all security patches
RUN apk update && \
    apk upgrade && \
    apk add --no-cache ca-certificates && \
    rm -rf /var/cache/apk/*

# Copy Flutter build
COPY --from=build /app/build/web /usr/share/nginx/html

# ✅ PRODUCTION NGINX CONFIG - Flutter Web Optimized + Security Headers
# Use conf.d/default.conf (standard nginx:alpine location) instead of custom nginx.conf
RUN printf '%s\n' \
    'server {' \
    '    listen 80;' \
    '    listen [::]:80;' \
    '    server_name _;' \
    '    root /usr/share/nginx/html;' \
    '    index index.html;' \
    '    add_header X-Content-Type-Options "nosniff" always;' \
    '    add_header X-Frame-Options "SAMEORIGIN" always;' \
    '    add_header X-XSS-Protection "1; mode=block" always;' \
    '    add_header Referrer-Policy "strict-origin-when-cross-origin" always;' \
    '    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;' \
    '    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;' \
    '    types {' \
    '        text/html html htm;' \
    '        text/css css;' \
    '        application/javascript js mjs;' \
    '        application/wasm wasm;' \
    '        image/png png;' \
    '        image/jpeg jpeg jpg;' \
    '        image/webp webp;' \
    '        image/svg+xml svg svgz;' \
    '        image/x-icon ico;' \
    '        font/woff woff;' \
    '        font/woff2 woff2;' \
    '        font/ttf ttf;' \
    '        font/otf otf;' \
    '        application/json json;' \
    '        application/manifest+json webmanifest;' \
    '    }' \
    '    gzip on;' \
    '    gzip_vary on;' \
    '    gzip_proxied any;' \
    '    gzip_comp_level 6;' \
    '    gzip_types text/plain text/css text/xml text/javascript application/javascript application/json application/xml image/svg+xml;' \
    '    location = /health {' \
    '        add_header Content-Type "text/plain";' \
    '        return 200 "healthy";' \
    '        access_log off;' \
    '    }' \
    '    location ~* \.(js|css|png|jpg|jpeg|webp|gif|ico|svg|woff|woff2|ttf|otf|wasm)$ {' \
    '        expires 365d;' \
    '        add_header Cache-Control "public, immutable";' \
    '        add_header X-Content-Type-Options "nosniff" always;' \
    '        access_log off;' \
    '    }' \
    '    location /canvaskit/ {' \
    '        expires 365d;' \
    '        add_header Cache-Control "public, immutable";' \
    '        access_log off;' \
    '    }' \
    '    location ~ ^/(index\.html|flutter_service_worker\.js)$ {' \
    '        expires -1;' \
    '        add_header Cache-Control "no-cache, no-store, must-revalidate";' \
    '        add_header Service-Worker-Allowed "/" always;' \
    '    }' \
    '    location ~* \.map$ {' \
    '        add_header Cache-Control "no-cache, no-store, must-revalidate";' \
    '        try_files $uri =404;' \
    '        access_log off;' \
    '    }' \
    '    location / {' \
    '        try_files $uri $uri/ /index.html;' \
    '        add_header Cache-Control "no-cache, no-store, must-revalidate";' \
    '    }' \
    '}' \
    > /etc/nginx/conf.d/default.conf

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://127.0.0.1/health || exit 1

CMD ["nginx", "-g", "daemon off;"]

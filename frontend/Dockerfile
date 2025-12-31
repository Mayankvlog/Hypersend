FROM debian:bookworm-slim AS build

ARG API_BASE_URL=https://zaply.in.net/api/v1

RUN apt-get update && apt-get install -y \
    curl git unzip xz-utils zip \
    && rm -rf /var/lib/apt/lists/*

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
RUN flutter build web --release \
    --no-tree-shake-icons \
    --dart-define=API_BASE_URL=${API_BASE_URL} \
    --dart-define=ENVIRONMENT=production

# ==============================
# NGINX Production Server
# ==============================
FROM nginx:alpine

# Copy Flutter build
COPY --from=build /app/build/web /usr/share/nginx/html

# ✅ PRODUCTION NGINX CONFIG - Flutter Web Optimized
RUN printf '%s\n' \
    'server {' \
    '    listen 80;' \
    '    listen [::]:80;' \
    '    server_name _;' \
    '    root /usr/share/nginx/html;' \
    '    index index.html;' \
    '' \
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
    '' \
    '    gzip on;' \
    '    gzip_vary on;' \
    '    gzip_proxied any;' \
    '    gzip_comp_level 6;' \
    '    gzip_types text/plain text/css text/xml text/javascript application/javascript application/json application/xml image/svg+xml;' \
    '' \
    '    location = /health {' \
    '        add_header Content-Type "text/plain";' \
    '        return 200 "healthy";' \
    '        access_log off;' \
    '    }' \
    '' \
    '    location ~* \.(js|css|png|jpg|jpeg|webp|gif|ico|svg|woff|woff2|ttf|otf|wasm)$ {' \
    '        expires 365d;' \
    '        add_header Cache-Control "public, immutable";' \
    '        add_header X-Content-Type-Options "nosniff" always;' \
    '        access_log off;' \
    '    }' \
    '' \
    '    location /canvaskit/ {' \
    '        expires 365d;' \
    '        add_header Cache-Control "public, immutable";' \
    '        access_log off;' \
    '    }' \
    '' \
    '    location ~ ^/(index\.html|flutter_service_worker\.js)$ {' \
    '        expires -1;' \
    '        add_header Cache-Control "no-cache, no-store, must-revalidate";' \
    '        add_header Service-Worker-Allowed "/" always;' \
    '    }' \
    '' \
    '    location / {' \
    '        try_files $uri $uri/ /index.html;' \
    '        add_header Cache-Control "no-cache, no-store, must-revalidate";' \
    '    }' \
    '' \
    '    error_page 404 /index.html;' \
    '}' \
    > /etc/nginx/conf.d/default.conf

EXPOSE 80
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://127.0.0.1/health || exit 1

CMD ["nginx", "-g", "daemon off;"]

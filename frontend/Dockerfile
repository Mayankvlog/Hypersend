# ==============================
# Flutter Web Build - Multi-stage
# ==============================
FROM debian:bookworm-slim AS build

ARG API_BASE_URL=https://zaply.in.net/api/v1
ARG BUILD_ID=1

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
RUN rm -rf .pub-cache && flutter pub get --verbose

COPY . .

# Clean and build
RUN rm -rf build/ && flutter clean

RUN flutter build web --release \
    --no-tree-shake-icons \
    --dart-define=API_BASE_URL=${API_BASE_URL}

# ==============================
# Serve with NGINX
# ==============================
FROM nginx:alpine

# Remove default config
RUN rm /etc/nginx/conf.d/default.conf

# Copy Flutter build
COPY --from=build /app/build/web /usr/share/nginx/html

# Create minimal nginx config for Flutter SPA
RUN printf '%s\n' 'server {' \
    '    listen 80;' \
    '    server_name _;' \
    '    ' \
    '    location /health {' \
    '        add_header Content-Type "text/plain";' \
    '        return 200 "healthy\n";' \
    '    }' \
    '    ' \
    '    location / {' \
    '        root /usr/share/nginx/html;' \
    '        try_files $uri $uri/ /index.html;' \
    '    }' \
    '}' > /etc/nginx/conf.d/default.conf

EXPOSE 80 443

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1/health || exit 1

CMD ["nginx", "-g", "daemon off;"]

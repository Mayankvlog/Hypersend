# Flutter Web Build - Multi-stage
FROM debian:bookworm-slim AS build

ARG API_BASE_URL=https://zaply.in.net/api/v1

RUN apt-get update && apt-get install -y curl git unzip xz-utils zip && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch 3.35.6 https://github.com/flutter/flutter.git /opt/flutter

ENV FLUTTER_HOME=/opt/flutter
ENV PATH="$FLUTTER_HOME/bin:$PATH"
ENV FLUTTER_SUPPRESS_ANALYTICS=true

RUN /opt/flutter/bin/flutter precache --web && /opt/flutter/bin/flutter config --enable-web

WORKDIR /app
# Copy dependency definitions first to utilize cache
COPY pubspec.yaml pubspec.lock ./

# Install dependencies
RUN /opt/flutter/bin/flutter pub get

# Copy the rest of the code
COPY . .

# Build web app - web-only build doesn't need platform configs
# Use ARG for API_BASE_URL - passed from docker-compose or build args
# Removed 'flutter clean' as it's a fresh container and causes issues if files aren't there yet/we want to keep the pub cache
# Use auto web renderer to optimize for different browsers and reduce WebGL warnings
RUN /opt/flutter/bin/flutter build web --release --no-tree-shake-icons --dart-define=API_BASE_URL=${API_BASE_URL} --web-renderer auto

# Serve with Nginx
FROM nginx:alpine
COPY --from=build /app/build/web /usr/share/nginx/html

# Create custom nginx config with proper headers and CORS support
RUN echo 'server {' > /etc/nginx/conf.d/default.conf && \
    echo '    listen 80;' >> /etc/nginx/conf.d/default.conf && \
    echo '    listen [::]:80;' >> /etc/nginx/conf.d/default.conf && \
    echo '    root /usr/share/nginx/html;' >> /etc/nginx/conf.d/default.conf && \
    echo '    index index.html;' >> /etc/nginx/conf.d/default.conf && \
    echo '' >> /etc/nginx/conf.d/default.conf && \
    echo '    # Gzip compression' >> /etc/nginx/conf.d/default.conf && \
    echo '    gzip on;' >> /etc/nginx/conf.d/default.conf && \
    echo '    gzip_types text/plain text/css text/javascript application/javascript application/json;' >> /etc/nginx/conf.d/default.conf && \
    echo '    gzip_min_length 1024;' >> /etc/nginx/conf.d/default.conf && \
    echo '' >> /etc/nginx/conf.d/default.conf && \
    echo '    # Cache control for assets' >> /etc/nginx/conf.d/default.conf && \
    echo '    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {' >> /etc/nginx/conf.d/default.conf && \
    echo '        expires 1y;' >> /etc/nginx/conf.d/default.conf && \
    echo '        add_header Cache-Control "public, immutable";' >> /etc/nginx/conf.d/default.conf && \
    echo '    }' >> /etc/nginx/conf.d/default.conf && \
    echo '' >> /etc/nginx/conf.d/default.conf && \
    echo '    # Health check endpoint' >> /etc/nginx/conf.d/default.conf && \
    echo '    location /health {' >> /etc/nginx/conf.d/default.conf && \
    echo '        return 200 "healthy\n";' >> /etc/nginx/conf.d/default.conf && \
    echo '        add_header Content-Type text/plain;' >> /etc/nginx/conf.d/default.conf && \
    echo '    }' >> /etc/nginx/conf.d/default.conf && \
    echo '' >> /etc/nginx/conf.d/default.conf && \
    echo '    # SPA routing - fallback to index.html for all routes' >> /etc/nginx/conf.d/default.conf && \
    echo '    location / {' >> /etc/nginx/conf.d/default.conf && \
    echo '        try_files $uri $uri/ /index.html;' >> /etc/nginx/conf.d/default.conf && \
    echo '        add_header Cache-Control "no-cache, no-store, must-revalidate";' >> /etc/nginx/conf.d/default.conf && \
    echo '    }' >> /etc/nginx/conf.d/default.conf && \
    echo '}' >> /etc/nginx/conf.d/default.conf

EXPOSE 80
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://127.0.0.1/health || exit 1
CMD ["nginx", "-g", "daemon off;"]

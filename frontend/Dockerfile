# Flutter Web Build - Multi-stage
FROM debian:bookworm-slim AS build

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
# Removed 'flutter clean' as it's a fresh container and causes issues if files aren't there yet/we want to keep the pub cache
RUN /opt/flutter/bin/flutter build web --release --no-tree-shake-icons

# Serve with Nginx
FROM nginx:alpine
COPY --from=build /app/build/web /usr/share/nginx/html

# Create nginx config to listen on port 8550
RUN echo 'server { listen 8550; root /usr/share/nginx/html; index index.html; location / { try_files $uri $uri/ /index.html; } location /health { return 200 "healthy\n"; add_header Content-Type text/plain; } }' > /etc/nginx/conf.d/default.conf

EXPOSE 8550
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8550/health || exit 1
CMD ["nginx", "-g", "daemon off;"]

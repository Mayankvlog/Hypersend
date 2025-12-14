# Flutter Web Build - Multi-stage
FROM debian:bookworm-slim AS build

RUN apt-get update && apt-get install -y curl git unzip xz-utils zip && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch 3.35.6 https://github.com/flutter/flutter.git /opt/flutter

ENV FLUTTER_HOME=/opt/flutter
ENV PATH="$FLUTTER_HOME/bin:$PATH"
ENV FLUTTER_SUPPRESS_ANALYTICS=true

RUN /opt/flutter/bin/flutter precache --web && /opt/flutter/bin/flutter config --enable-web

RUN useradd -m -u 1000 flutter && chown -R flutter:flutter $FLUTTER_HOME
USER flutter

WORKDIR /app
COPY . .
RUN /opt/flutter/bin/flutter pub get && /opt/flutter/bin/flutter build web --release

# Serve with Nginx
FROM nginx:alpine
COPY --from=build /app/build/web /usr/share/nginx/html
EXPOSE 8550
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8550/ || exit 1
CMD ["nginx", "-g", "daemon off;"]

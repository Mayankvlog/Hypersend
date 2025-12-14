# Multi-stage Flutter build for web deployment
FROM debian:bookworm-slim AS build

# Install Flutter dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    unzip \
    xz-utils \
    zip \
    libglu1-mesa \
    && rm -rf /var/lib/apt/lists/*

# Install Flutter SDK
ENV FLUTTER_VERSION=3.35.6
ENV FLUTTER_HOME=/opt/flutter
ENV PATH="$FLUTTER_HOME/bin:$PATH"
ENV FLUTTER_SUPPRESS_ANALYTICS=true

RUN git clone --depth 1 --branch ${FLUTTER_VERSION} https://github.com/flutter/flutter.git ${FLUTTER_HOME} \
    && flutter precache --web \
    && flutter config --enable-web

# Create non-root user to run flutter
RUN useradd -m -u 1000 flutter_builder && \
    chown -R flutter_builder:flutter_builder ${FLUTTER_HOME}

USER flutter_builder

# Set working directory
WORKDIR /app

# Copy all project files (including lib/)
COPY --chown=flutter_builder:flutter_builder . .

# Get dependencies
RUN flutter pub get

# Build web app
RUN flutter build web --release

# Production stage - serve with nginx
FROM nginx:alpine

# Copy built web app
COPY --from=build /app/build/web /usr/share/nginx/html

# Expose port
EXPOSE 8550

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8550/ || exit 1

# Start nginx
CMD ["nginx", "-g", "daemon off;"]
FROM python:3.12-slim

# Security labels
LABEL org.opencontainers.image.source="https://github.com/your-org/r3d-proxy" \
      org.opencontainers.image.description="R3D Red Team Proxy with Enterprise Security" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app

ARG MONGODB_CRYPT_VERSION=8.0.0

# Install build deps + download tools (removed after use for minimal attack surface)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    unzip \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Nuclei (best-effort, amd64 only)
RUN (curl -sSL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | python3 -c "import sys,json;print(json.load(sys.stdin)['tag_name'].lstrip('v'))")_linux_amd64.zip -o /tmp/nuclei.zip && \
    unzip -o /tmp/nuclei.zip -d /usr/local/bin/ nuclei && rm -f /tmp/nuclei.zip) || true

# MongoDB Crypt Shared Library for CSFLE / Queryable Encryption
# Always uses ubuntu2204 builds — they're glibc-compatible with Debian slim
# and available for both x86_64 and aarch64.
RUN mkdir -p /opt/mongodb/lib && \
    ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then ARCH="x86_64"; fi && \
    if [ "$ARCH" = "arm64" ]; then ARCH="aarch64"; fi && \
    echo "Downloading crypt_shared for architecture: $ARCH" && \
    curl -L -o /tmp/mongo_crypt.tgz \
      "https://downloads.mongodb.com/linux/mongo_crypt_shared_v1-linux-${ARCH}-enterprise-ubuntu2204-${MONGODB_CRYPT_VERSION}.tgz" && \
    tar -xzf /tmp/mongo_crypt.tgz -C /tmp && \
    find /tmp -name "mongo_crypt_v1.so" -exec cp {} /opt/mongodb/lib/ \; && \
    chmod 755 /opt/mongodb/lib/mongo_crypt_v1.so && \
    rm -rf /tmp/mongo_crypt* && \
    echo "crypt_shared installed at /opt/mongodb/lib/mongo_crypt_v1.so"

ENV CRYPT_SHARED_LIB_PATH=/opt/mongodb/lib/mongo_crypt_v1.so

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py graph_builder.py entrypoint.sh ./
COPY core/ ./core/
COPY routers/ ./routers/
COPY reports/ ./reports/
COPY static/ ./static/
COPY payloads/ ./payloads/

# Remove curl/unzip after downloads (reduce attack surface)
RUN apt-get remove -y curl unzip && apt-get autoremove -y

# Create non-root user for application
RUN groupadd -r r3d --gid=1000 && \
    useradd -r -g r3d --uid=1000 --home-dir=/app --shell=/sbin/nologin r3d && \
    chown -R r3d:r3d /app && \
    chmod +x entrypoint.sh

# Create writable directories (for read-only root filesystem support)
RUN mkdir -p /app/phish_cache /tmp/r3d && \
    chown -R r3d:r3d /app/phish_cache /tmp/r3d

# Switch to non-root user
USER r3d

EXPOSE 4000

# Healthcheck defined in docker-compose.yml (verifies full app readiness, not
# just HTTP 200). Keeping a basic fallback here for standalone `docker run`.
HEALTHCHECK --interval=30s --timeout=5s --start-period=45s --retries=3 \
  CMD python3 -c "import urllib.request,json; r=json.loads(urllib.request.urlopen('http://localhost:4000/health').read()); exit(0 if r.get('status')=='ok' else 1)" || exit 1

ENTRYPOINT ["./entrypoint.sh"]

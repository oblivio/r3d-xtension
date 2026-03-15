FROM python:3.12-slim

WORKDIR /app

ARG MONGODB_CRYPT_VERSION=8.0.0

# Install build deps + download tools (curl kept for nuclei + crypt_shared)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    unzip \
    libssl-dev \
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
RUN chmod +x entrypoint.sh

EXPOSE 4000

ENTRYPOINT ["./entrypoint.sh"]

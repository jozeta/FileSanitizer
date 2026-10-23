FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    media-types \
    mailcap \
    libmagic1 \
    curl \
    gcc \
    libc6-dev \
    tesseract-ocr \
    tesseract-ocr-eng \
    binutils \
    nmap \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Install checksec v3 (slimm609/checksec) — binary security analysis tool (multi-arch: amd64 / arm64)
ARG TARGETARCH
RUN ARCH="${TARGETARCH:-$(dpkg --print-architecture)}" && \
    case "${ARCH}" in \
        amd64|x86_64) CHECKSEC_ARCH="amd64" ;; \
        arm64|aarch64) CHECKSEC_ARCH="arm64" ;; \
        *) CHECKSEC_ARCH="$(dpkg --print-architecture)" ;; \
    esac && \
    echo "Installing checksec for architecture: ${CHECKSEC_ARCH}" && \
    if curl -fsSL "https://github.com/slimm609/checksec/releases/download/3.2.0/checksec_3.2.0_${CHECKSEC_ARCH}.deb" -o /tmp/checksec.deb && dpkg -i /tmp/checksec.deb; then \
        rm -f /tmp/checksec.deb; \
    else \
        echo "Debian package install failed or unavailable for ${CHECKSEC_ARCH}, falling back to standalone checksec script..." && \
        curl -fsSL "https://raw.githubusercontent.com/slimm609/checksec.sh/master/checksec" -o /usr/local/bin/checksec && \
        chmod +x /usr/local/bin/checksec; \
    fi

# Install ProjectDiscovery tools: subfinder and dnsx (multi-arch: amd64 / arm64)
RUN ARCH="${TARGETARCH:-$(dpkg --print-architecture)}" && \
    case "${ARCH}" in \
        amd64|x86_64) PD_ARCH="amd64" ;; \
        arm64|aarch64) PD_ARCH="arm64" ;; \
        *) PD_ARCH="$(dpkg --print-architecture)" ;; \
    esac && \
    echo "Installing subfinder and dnsx for architecture: ${PD_ARCH}" && \
    curl -fsSL "https://github.com/projectdiscovery/subfinder/releases/download/v2.17.0/subfinder_2.17.0_linux_${PD_ARCH}.zip" -o /tmp/subfinder.zip && \
    python3 -m zipfile -e /tmp/subfinder.zip /tmp/subfinder_bin && \
    mv /tmp/subfinder_bin/subfinder /usr/local/bin/subfinder && \
    chmod +x /usr/local/bin/subfinder && \
    rm -rf /tmp/subfinder* && \
    curl -fsSL "https://github.com/projectdiscovery/dnsx/releases/download/v1.3.1/dnsx_1.3.1_linux_${PD_ARCH}.zip" -o /tmp/dnsx.zip && \
    python3 -m zipfile -e /tmp/dnsx.zip /tmp/dnsx_bin && \
    mv /tmp/dnsx_bin/dnsx /usr/local/bin/dnsx && \
    chmod +x /usr/local/bin/dnsx && \
    rm -rf /tmp/dnsx*

# Create non-root user and configure network capabilities for Nmap reconnaissance
RUN groupadd -g 1001 appgroup && \
    useradd -u 1001 -g appgroup -s /bin/bash -m appuser && \
    setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap || true

WORKDIR /app

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --no-compile -r requirements.txt

# Copy backend code
COPY app ./app
COPY tests ./tests

# Create jobs workspace directory with correct permissions
RUN mkdir -p /jobs && chown -R appuser:appgroup /jobs /app

USER appuser

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    JOBS_DIR=/jobs

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

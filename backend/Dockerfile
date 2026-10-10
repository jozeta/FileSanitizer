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
    && rm -rf /var/lib/apt/lists/*

# Install checksec v3 (slimm609/checksec) — binary security analysis tool
ARG TARGETARCH=arm64
RUN ARCH="${TARGETARCH}" && \
    curl -fsSL "https://github.com/slimm609/checksec/releases/download/3.2.0/checksec_3.2.0_${ARCH}.deb" -o /tmp/checksec.deb && \
    dpkg -i /tmp/checksec.deb && \
    rm /tmp/checksec.deb

# Create non-root user
RUN groupadd -g 1001 appgroup && \
    useradd -u 1001 -g appgroup -s /bin/bash -m appuser

WORKDIR /app

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --no-compile -r requirements.txt

# Copy backend code
COPY app ./app

# Create jobs workspace directory with correct permissions
RUN mkdir -p /jobs && chown -R appuser:appgroup /jobs /app

USER appuser

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    JOBS_DIR=/jobs

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

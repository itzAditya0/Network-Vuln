# Multi-stage Dockerfile for Network Vulnerability Scanner
# Uses minimal base image, non-root user, health checks

# === Build Stage ===
FROM python:3.11-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Build wheels
RUN pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt

# === Production Stage ===
FROM python:3.11-slim

# Security: Non-root user
RUN groupadd -r vulnscanner && useradd -r -g vulnscanner vulnscanner

WORKDIR /app

# Install runtime dependencies (nmap)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    libpq5 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy wheels from builder
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/* && rm -rf /wheels

# Copy application code
COPY src/ ./src/
COPY config/ ./config/
COPY templates/ ./templates/
COPY database/ ./database/
COPY main.py .

# Create directories with proper permissions
RUN mkdir -p reports logs \
    && chown -R vulnscanner:vulnscanner /app

# Switch to non-root user
USER vulnscanner

# Environment
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import src; print('healthy')" || exit 1

# Default command
ENTRYPOINT ["python", "main.py"]
CMD ["--help"]

# Ports
EXPOSE 9090

# SSL Analyzer - Docker Container
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ ./src/
COPY examples/ ./examples/
COPY tests/ ./tests/
COPY README.md LICENSE ./

# Create non-root user for security
RUN useradd -m -u 1000 analyzer && \
    chown -R analyzer:analyzer /app
USER analyzer

# Set Python path
ENV PYTHONPATH=/app/src

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.path.insert(0, '/app/src'); from ssl_analyzer import parse_url; parse_url('google.com')" || exit 1

# Default command
ENTRYPOINT ["python", "src/ssl_analyzer.py"]

# Labels for metadata
LABEL maintainer="Samuel Tan <samuel@sammtan.com>"
LABEL description="Professional SSL/TLS Certificate Analyzer"
LABEL version="1.0.0"
LABEL org.opencontainers.image.title="SSL Analyzer"
LABEL org.opencontainers.image.description="Comprehensive SSL/TLS certificate analysis tool"
LABEL org.opencontainers.image.url="https://github.com/sammtan/ssl-analyzer"
LABEL org.opencontainers.image.documentation="https://github.com/sammtan/ssl-analyzer/blob/main/README.md"
LABEL org.opencontainers.image.source="https://github.com/sammtan/ssl-analyzer"
LABEL org.opencontainers.image.licenses="MIT"
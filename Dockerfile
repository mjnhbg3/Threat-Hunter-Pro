# =============================================================================
# RAG-Enhanced Threat Hunter Pro - Multi-stage Docker Build
# =============================================================================
# This Dockerfile creates optimized, secure images for both development and 
# production environments with multi-architecture support and security hardening.

# =============================================================================
# Base Python Image with Security Hardening
# =============================================================================
FROM python:3.11-slim as base

# Build arguments for metadata and configuration
ARG BUILD_DATE
ARG VERSION
ARG VCS_REF
ARG TARGETPLATFORM
ARG BUILDPLATFORM

# Security and optimization environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore \
    DEBIAN_FRONTEND=noninteractive

# Create non-root user early for security
RUN groupadd -r appuser --gid=1000 && \
    useradd -r -g appuser --uid=1000 --home-dir=/app --shell=/sbin/nologin appuser

# Install system dependencies with security considerations
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build essentials (minimal set)
    build-essential=12.9 \
    # Network tools for health checks
    curl=7.88.1-10+deb12u* \
    wget=1.21.3-1+b1 \
    # Version control (minimal)
    git=1:2.39.2-1.1 \
    # Security updates
    ca-certificates \
    # Clean up to reduce attack surface
    && apt-get upgrade -y \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/* \
    && rm -rf /var/tmp/*

# Create secure application directory structure
WORKDIR /app
RUN mkdir -p /app/data /app/logs /app/backups /app/cache \
    && chown -R appuser:appuser /app

# Security: Set proper file permissions
RUN chmod 755 /app && \
    chmod 700 /app/data /app/logs /app/backups /app/cache

# =============================================================================
# Development Dependencies Stage with Security
# =============================================================================
FROM base as dev-deps

# Install development tools with version pinning
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Development and debugging tools
    vim-tiny=2:9.0.1378-2 \
    htop=3.2.2-2 \
    procps=2:4.0.2-3 \
    # Network debugging
    netcat-traditional=1.10-47 \
    # Clean up
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/* \
    && rm -rf /var/tmp/*

# Copy requirements with integrity verification
COPY requirements.txt .
RUN sha256sum requirements.txt

# Install Python dependencies with security considerations
RUN pip install --no-cache-dir --upgrade pip==23.3.* setuptools==69.0.* wheel==0.42.* && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir \
    # Testing frameworks
    pytest==7.4.* \
    pytest-cov==4.1.* \
    pytest-asyncio==0.21.* \
    pytest-benchmark==4.0.* \
    # Code quality tools
    black==23.12.* \
    flake8==6.1.* \
    mypy==1.8.* \
    bandit==1.7.* \
    # Development tools
    ipython==8.18.* \
    jupyter==1.0.* \
    # Security scanning
    safety==2.3.*

# Download spaCy model with verification
RUN python -m spacy download en_core_web_sm && \
    python -c "import spacy; nlp = spacy.load('en_core_web_sm'); print('✅ spaCy model loaded successfully')"

# Verify installed packages
RUN pip check && pip list --format=freeze > /app/dev-requirements-lock.txt

# =============================================================================
# Production Dependencies Stage with Security Hardening
# =============================================================================
FROM base as prod-deps

# Copy requirements with integrity verification
COPY requirements.txt .
RUN sha256sum requirements.txt

# Install production dependencies with security considerations
RUN pip install --no-cache-dir --upgrade pip==23.3.* setuptools==69.0.* wheel==0.42.* && \
    pip install --no-cache-dir -r requirements.txt && \
    # Verify dependencies
    pip check && \
    # Create lock file for reproducible builds
    pip list --format=freeze > /app/prod-requirements-lock.txt && \
    # Security: Remove pip cache and temporary files
    rm -rf ~/.cache/pip/* /tmp/* /var/tmp/*

# Download and verify spaCy model
RUN python -m spacy download en_core_web_sm && \
    python -c "import spacy; nlp = spacy.load('en_core_web_sm'); print('✅ spaCy model loaded successfully')" && \
    # Clean up model download cache
    rm -rf /tmp/*

# Security: Remove build dependencies to reduce attack surface
RUN apt-get update && apt-get remove -y \
    build-essential \
    git \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# =============================================================================
# Development Stage with Security and Debugging
# =============================================================================
FROM dev-deps as development

# Copy application code with proper ownership
COPY --chown=appuser:appuser . .

# Security: Ensure proper file permissions
RUN find /app -type f -name "*.py" -exec chmod 644 {} \; && \
    find /app -type f -name "*.sh" -exec chmod 755 {} \; && \
    find /app -type d -exec chmod 755 {} \; && \
    # Ensure sensitive directories have restricted permissions
    chmod 700 /app/data /app/logs /app/backups /app/cache

# Switch to non-root user for security
USER appuser

# Create runtime directories as non-root user
RUN mkdir -p /app/data/threat_hunter_db \
    /app/logs \
    /app/backups \
    /app/cache \
    /app/runtime

# Expose port (documentation only - actual port binding happens at runtime)
EXPOSE 8000

# Enhanced health check for development
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=5 \
    CMD curl -f http://localhost:8000/health || \
        (echo "Health check failed at $(date)" && exit 1)

# Security: Add container metadata
LABEL org.opencontainers.image.title="RAG-Enhanced Threat Hunter Pro (Development)" \
      org.opencontainers.image.description="Development container for RAG-Enhanced Threat Hunter Pro" \
      org.opencontainers.image.version="${VERSION:-dev}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.vendor="Threat Hunter Pro Team" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.url="https://github.com/${GITHUB_REPOSITORY:-threat-hunter-pro}" \
      org.opencontainers.image.source="https://github.com/${GITHUB_REPOSITORY:-threat-hunter-pro}" \
      security.non-root="true" \
      security.no-new-privileges="true"

# Development command with hot reloading and debugging
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload", "--log-level", "debug"]

# =============================================================================
# Production Stage with Maximum Security
# =============================================================================
FROM prod-deps as production

# Copy application code with proper ownership
COPY --chown=appuser:appuser . .

# Security hardening: Remove development and sensitive files
RUN rm -rf \
    tests/ \
    docs/ \
    .git/ \
    .gitignore \
    .env.example \
    docker-compose*.yml \
    Dockerfile* \
    README.md \
    .github/ \
    .pytest_cache/ \
    __pycache__/ \
    *.pyc \
    *.pyo \
    .coverage \
    htmlcov/ \
    .mypy_cache/ \
    .bandit \
    # Remove any potential secrets or config files
    *.key \
    *.pem \
    *.p12 \
    .env* \
    config.ini \
    secrets.json

# Security: Ensure proper file permissions
RUN find /app -type f -name "*.py" -exec chmod 644 {} \; && \
    find /app -type f -name "*.sh" -exec chmod 755 {} \; && \
    find /app -type d -exec chmod 755 {} \; && \
    # Restrict sensitive directories
    chmod 700 /app/data /app/logs /app/backups /app/cache && \
    # Make application files immutable where possible
    find /app -type f \( -name "*.py" -o -name "*.json" \) ! -path "/app/data/*" ! -path "/app/logs/*" ! -path "/app/backups/*" -exec chmod 444 {} \;

# Switch to non-root user for security
USER appuser

# Create runtime directories as non-root user
RUN mkdir -p /app/data/threat_hunter_db \
    /app/logs \
    /app/backups \
    /app/cache \
    /app/runtime

# Expose port (documentation only)
EXPOSE 8000

# Production-grade health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=5 \
    CMD curl -f --max-time 5 http://localhost:8000/health || exit 1

# Security: Add comprehensive container metadata
LABEL org.opencontainers.image.title="RAG-Enhanced Threat Hunter Pro (Production)" \
      org.opencontainers.image.description="Production container for RAG-Enhanced Threat Hunter Pro with enhanced security" \
      org.opencontainers.image.version="${VERSION:-latest}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.vendor="Threat Hunter Pro Team" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.url="https://github.com/${GITHUB_REPOSITORY:-threat-hunter-pro}" \
      org.opencontainers.image.source="https://github.com/${GITHUB_REPOSITORY:-threat-hunter-pro}" \
      org.opencontainers.image.documentation="https://github.com/${GITHUB_REPOSITORY:-threat-hunter-pro}/docs" \
      security.non-root="true" \
      security.no-new-privileges="true" \
      security.hardened="true" \
      security.minimal-surface="true"

# Production command with performance optimization
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4", "--worker-class", "uvicorn.workers.UvicornWorker", "--access-log", "--log-level", "info"]

# =============================================================================
# Service-Specific Stages
# =============================================================================

# Vector Store Service
FROM prod-deps as vector-store-service

# Install additional dependencies for vector operations
RUN pip install --no-cache-dir \
    faiss-cpu \
    sentence-transformers \
    redis \
    numpy

# Copy vector store service code
COPY services/vector_store/ /app/

# Create data directory
RUN mkdir -p /app/data && chown -R appuser:appuser /app

USER appuser
EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=5 \
    CMD curl -f http://localhost:8001/health || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]

# Search Service
FROM prod-deps as search-service

# Install additional dependencies for search operations
RUN pip install --no-cache-dir \
    bm25s \
    scikit-learn \
    redis \
    numpy

# Copy search service code
COPY services/search_service/ /app/

# Create data directory
RUN mkdir -p /app/data && chown -R appuser:appuser /app

USER appuser
EXPOSE 8002

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=5 \
    CMD curl -f http://localhost:8002/health || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8002"]

# Summary Store Service
FROM prod-deps as summary-store-service

# Install additional dependencies for summary operations
RUN pip install --no-cache-dir \
    redis \
    zstandard

# Copy summary store service code
COPY services/summary_store/ /app/

# Create data directory
RUN mkdir -p /app/data && chown -R appuser:appuser /app

USER appuser
EXPOSE 8003

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=5 \
    CMD curl -f http://localhost:8003/health || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8003"]

# =============================================================================
# Build Arguments and Labels
# =============================================================================

# Build arguments
ARG BUILD_DATE
ARG VERSION
ARG VCS_REF

# Labels for metadata
LABEL maintainer="Threat Hunter Pro Team" \
      org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.name="threat-hunter-pro" \
      org.label-schema.description="RAG-Enhanced Threat Hunter Pro with AI-powered security analysis" \
      org.label-schema.version=$VERSION \
      org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.vcs-url="https://github.com/your-org/threat-hunter-pro" \
      org.label-schema.schema-version="1.0"
# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /app

# Install build deps for chromadb / sentence-transformers native extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM python:3.12-slim

WORKDIR /app

# Runtime-only system libs
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application source
COPY . .

# Writable runtime directories (logs, chroma_db, data)
RUN mkdir -p data/input data/samples data/chroma_db logs static \
    && chmod -R 777 data logs static

# Expose dashboard port
EXPOSE 8888

# Health check — hits the FastAPI /health endpoint (add one if missing, or use /)
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8888/ || exit 1

# Default: Ollama runs in a sibling container, override via env
ENV OLLAMA_HOST=http://ollama:11434 \
    WEB_HOST=0.0.0.0 \
    WEB_PORT=8888 \
    LOG_LEVEL=INFO

CMD ["python", "main.py"]

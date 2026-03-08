FROM python:3.11-slim

# System deps: git (GitPython), curl (healthcheck), build tools (tree-sitter C extension)
RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        curl \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (cached layer)
COPY pyproject.toml ./
# Stub src so pip install -e . can resolve the package location
RUN mkdir -p src/postura && touch src/postura/__init__.py
RUN pip install --no-cache-dir -e ".[dev]"

# Copy full source (overwrites the stub)
COPY src/ src/
COPY evaluation/ evaluation/

# Default: API server. Override in docker-compose for the worker.
CMD ["uvicorn", "postura.api.app:app", "--host", "0.0.0.0", "--port", "8000"]

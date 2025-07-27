# Use multi-stage build for smaller final image
FROM python:3.9-slim as builder

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    POETRY_VERSION=1.5.1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create and set working directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Install the package
RUN pip install --no-cache-dir -e .

# Second stage
FROM python:3.9-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Create non-root user
RUN useradd -m -u 1000 appuser

# Create necessary directories
RUN mkdir -p /app/data /app/logs /app/models

# Set permissions
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Create and set working directory
WORKDIR /app

# Copy from builder
COPY --from=builder --chown=appuser:appuser /usr/local/lib/python3.9/site-packages /usr/local/lib/python3.9/site-packages
COPY --from=builder --chown=appuser:appuser /app /app

# Expose port for API
EXPOSE 8000

# Set entry point and default command
ENTRYPOINT ["python", "-m", "scripts.api.app"]
CMD ["--host", "0.0.0.0", "--port", "8000"]

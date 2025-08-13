FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    libc-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip
RUN pip install --upgrade pip

# Copy requirements first to leverage Docker cache
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY backend /app/backend

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV DEBUG=true
ENV HOST=0.0.0.0
ENV PORT=8000

# Create non-root user
RUN useradd -m appuser \
    && mkdir -p /app/logs \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 9000

# Default command (development). For production, override to remove --reload and set DEBUG=false
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "9000", "--reload"]

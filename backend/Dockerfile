FROM python:3.9-slim

WORKDIR /app/backend

# Install Node.js and npm
RUN apt-get update && \
    apt-get install -y nodejs npm && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install retire globally
RUN npm install -g retire

# Copy requirements first to leverage Docker cache
COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy the whole project
COPY . /app

# Set PYTHONPATH so 'backend' is importable
ENV PYTHONPATH=/app

# Create necessary directories
RUN mkdir -p /app/logs

EXPOSE 8000

# Command to run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"] 
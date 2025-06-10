# scanner-backend/Dockerfile

# 1) Base image
FROM python:3.11-slim AS base
WORKDIR /app

# 2) System deps
RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc libpq-dev \
 && rm -rf /var/lib/apt/lists/*

# 3) Copy and install Python deps via pip
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir celery

# 4) Copy your app source
COPY app/ /app/app/

# 5) Expose and run
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# Install system dependencies (curl for healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Create persistent storage directories
RUN mkdir -p /app/data /app/exports

EXPOSE 8000

# Default command: launch the FastAPI Web Dashboard & REST API
CMD ["uvicorn", "src.api:app", "--host", "0.0.0.0", "--port", "8000"]

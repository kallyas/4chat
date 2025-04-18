FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy application code
COPY 4chat/server /app/server
COPY requirements-server.txt /app/

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements-server.txt

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    REDIS_HOST=redis \
    HOST=0.0.0.0

# Expose port
EXPOSE 8765

# Run the server
CMD ["python", "server/main.py"]

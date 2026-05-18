# Attack Engine Dockerfile
FROM python:3.12-slim-bookworm

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpcap-dev \
    git \
    golang-go \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Build Go Engine
RUN cd src/vectors/l7_application/go_engine && \
    go mod download && \
    go build -o ../../../../bin/go_engine.exe .

# Set entrypoint
ENTRYPOINT ["python", "main.py"]

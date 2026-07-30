# syntax = docker/dockerfile:1.7
# Multi-stage build — keeps the final image small.

# ---------- Build stage ----------
FROM python:3.12-slim AS builder

WORKDIR /build

COPY requirements.txt ./
RUN pip install --no-cache-dir --user -r requirements.txt

COPY . .
RUN pip install --no-cache-dir --user .

# ---------- Runtime stage ----------
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Copy Python user site from builder
COPY --from=builder /root/.local /root/.local

# Make sure scripts in .local are in PATH
ENV PATH=/root/.local/bin:$PATH

WORKDIR /data

ENTRYPOINT ["python", "-m", "netscan"]
CMD ["--help"]

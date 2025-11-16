FROM ubuntu:20.04

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && \
    apt-get install -y \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Copy binary and scripts
WORKDIR /app
COPY TTMPA/ttmpa.ks /app/ttmpa.ks
COPY test_dynamic.py /app/test_dynamic.py

# Make binary executable
RUN chmod +x /app/ttmpa.ks

# Run tests
CMD ["python3", "test_dynamic.py"]



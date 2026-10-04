FROM python:3.11-slim

# Install system dependencies (security analysis & networking utilities)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    dnsutils \
    iputils-ping \
    whois \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency specifications and install
COPY pyproject.toml .
RUN pip install --no-cache-dir .

# Copy application code
COPY . .

# Create volume directories
RUN mkdir -p data logs reports screenshots config

ENV PYTHONUNBUFFERED=1
ENV BUGBOUNTY_DATABASE_URL=sqlite:///data/bugbounty.db

ENTRYPOINT ["bugbounty"]
CMD ["--help"]

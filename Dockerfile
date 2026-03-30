FROM python:3.11-slim

# Install system deps for yara-python
RUN apt-get update && apt-get install -y \
    gcc \
    libssl-dev \
    libjansson-dev \
    libmagic-dev \
    automake \
    libtool \
    make \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1
ENV DJANGO_SETTINGS_MODULE=scanner.settings

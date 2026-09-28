FROM python:3.12-slim

ARG APP_VERSION=0.0.0-dev
ENV APP_VERSION=${APP_VERSION} \
    DATABASE_PATH=/data/secureflow.db \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

LABEL org.opencontainers.image.title="secureflow" \
      org.opencontainers.image.version="${APP_VERSION}"

WORKDIR /srv

# pull in Debian security patches that landed after the base image was built
# (keeps Trivy happy without pinning to a new base image every week)
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# run as an unprivileged user - no reason for the API to be root
RUN useradd --create-home --uid 10001 secureflow \
    && mkdir -p /data && chown secureflow:secureflow /data

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY app ./app

USER secureflow
EXPOSE 8000
VOLUME ["/data"]

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health', timeout=2)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

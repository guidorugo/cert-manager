# Base image pinned by digest (H2). python:3.13.14-slim-trixie.
# Update via Dependabot (docker ecosystem) or re-resolve the tag's digest.
FROM python:3.13-slim@sha256:bf503bb2243c5aad0aa951544dd60d165f992646441d35dea90893703fc26251 AS builder

WORKDIR /build
# build-essential + libffi-dev let python-pkcs11 (a C extension) compile if a
# wheel is unavailable; these stay in the builder stage and never reach the
# final image.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libffi-dev \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
# --require-hashes enforces the hash-locked lockfile (I1): every artifact must
# match a pinned sha256, and every dependency (incl. transitive) must be pinned.
RUN pip install --no-cache-dir --require-hashes --prefix=/install -r requirements.txt

FROM python:3.13-slim@sha256:bf503bb2243c5aad0aa951544dd60d165f992646441d35dea90893703fc26251

WORKDIR /app

# softhsm2 provides libsofthsm2.so + softhsm2-util (token init); opensc provides
# pkcs11-tool for diagnostics. Only exercised when KEY_BACKEND=softhsm.
RUN apt-get update && apt-get install -y --no-install-recommends \
        softhsm2 opensc \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local

COPY app/ app/
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

RUN mkdir -p /app/data

EXPOSE 5000

ENTRYPOINT ["./entrypoint.sh"]

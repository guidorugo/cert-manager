FROM python:3.13-slim AS builder

WORKDIR /build
# build-essential + libffi-dev let python-pkcs11 (a C extension) compile; these
# stay in the builder stage and never reach the final image.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libffi-dev \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.13-slim

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

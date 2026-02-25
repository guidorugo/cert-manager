FROM python:3.13-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.13-slim

WORKDIR /app

COPY --from=builder /install /usr/local

COPY app/ app/
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

RUN mkdir -p /app/data

EXPOSE 5000

ENTRYPOINT ["./entrypoint.sh"]

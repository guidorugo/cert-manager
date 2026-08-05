#!/bin/bash
set -e

echo "Starting Certificate Manager..."

# A2: restrict permissions on new files (SQLite DB + WAL) to owner-only, and
# tighten any pre-existing DB files so the database (encrypted CA keys, password
# hashes, audit log) is not world-readable on the host bind-mount.
umask 077

# Run database initialization via Python
python -c "from app import create_app; create_app()"

# Tighten permissions on the data directory and any existing DB files.
chmod 700 /app/data 2>/dev/null || true
find /app/data -type f -name '*.db*' -exec chmod 600 {} + 2>/dev/null || true

echo "Database initialized."

# Start gunicorn
exec gunicorn \
    --bind 0.0.0.0:5000 \
    --workers 2 \
    --timeout 120 \
    "app:create_app()"

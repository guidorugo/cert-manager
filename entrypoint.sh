#!/bin/bash
set -e

echo "Starting Certificate Manager..."

# Run database initialization via Python
python -c "from app import create_app; create_app()"

echo "Database initialized."

# Start gunicorn
exec gunicorn \
    --bind 0.0.0.0:5000 \
    --workers 2 \
    --timeout 120 \
    "app:create_app()"

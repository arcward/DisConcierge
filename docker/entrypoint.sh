#!/bin/sh
set -e

# Check if SSL certificates exist, if not, create self-signed ones
if [ ! -f "$DC_API_SSL_CERT" ] || [ ! -f "$DC_API_SSL_KEY" ]; then
    echo "SSL certificates not found. Generating self-signed certificates..."
    openssl req -x509 -newkey rsa:4096 -keyout "$DC_API_SSL_KEY" -out "$DC_API_SSL_CERT" -days 365 -nodes -subj "/CN=localhost"
    echo "Self-signed certificates generated."
else
    echo "Using existing SSL certificates."
fi

# Start the application
exec "$@"

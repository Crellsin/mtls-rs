#!/bin/bash

# Generate test certificates for mTLS testing
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="$SCRIPT_DIR"

# Create directories
mkdir -p "$CERTS_DIR/ca"
mkdir -p "$CERTS_DIR/server"
mkdir -p "$CERTS_DIR/client"

# Generate CA private key and certificate
echo "Generating CA key and certificate..."
openssl genrsa -out "$CERTS_DIR/ca/ca.key" 2048
openssl req -x509 -new -nodes -key "$CERTS_DIR/ca/ca.key" -sha256 -days 3650 \
  -out "$CERTS_DIR/ca/ca.crt" -subj "/C=US/ST=Test/L=Test/O=Test CA/CN=Test CA"

# Generate server key and certificate signing request (CSR)
echo "Generating server key and CSR..."
openssl genrsa -out "$CERTS_DIR/server/server.key" 2048
openssl req -new -key "$CERTS_DIR/server/server.key" -out "$CERTS_DIR/server/server.csr" \
  -subj "/C=US/ST=Test/L=Test/O=Test Server/CN=localhost"

# Sign server certificate with CA
echo "Signing server certificate..."
openssl x509 -req -in "$CERTS_DIR/server/server.csr" -CA "$CERTS_DIR/ca/ca.crt" \
  -CAkey "$CERTS_DIR/ca/ca.key" -CAcreateserial -out "$CERTS_DIR/server/server.crt" \
  -days 3650 -sha256

# Generate client key and certificate signing request (CSR)
echo "Generating client key and CSR..."
openssl genrsa -out "$CERTS_DIR/client/client.key" 2048
openssl req -new -key "$CERTS_DIR/client/client.key" -out "$CERTS_DIR/client/client.csr" \
  -subj "/C=US/ST=Test/L=Test/O=Test Client/CN=Test Client"

# Sign client certificate with CA
echo "Signing client certificate..."
openssl x509 -req -in "$CERTS_DIR/client/client.csr" -CA "$CERTS_DIR/ca/ca.crt" \
  -CAkey "$CERTS_DIR/ca/ca.key" -CAcreateserial -out "$CERTS_DIR/client/client.crt" \
  -days 3650 -sha256

# Create combined PEM files for server and client
cat "$CERTS_DIR/server/server.crt" "$CERTS_DIR/server/server.key" > "$CERTS_DIR/server/server.pem"
cat "$CERTS_DIR/client/client.crt" "$CERTS_DIR/client/client.key" > "$CERTS_DIR/client/client.pem"

# Copy CA certificate to server and client directories for convenience
cp "$CERTS_DIR/ca/ca.crt" "$CERTS_DIR/server/ca.crt"
cp "$CERTS_DIR/ca/ca.crt" "$CERTS_DIR/client/ca.crt"

echo "Certificates generated successfully in $CERTS_DIR"
echo "CA certificate: $CERTS_DIR/ca/ca.crt"
echo "Server certificate: $CERTS_DIR/server/server.crt"
echo "Server key: $CERTS_DIR/server/server.key"
echo "Client certificate: $CERTS_DIR/client/client.crt"
echo "Client key: $CERTS_DIR/client/client.key"

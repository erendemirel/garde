#!/bin/bash
set -e

# Function to log messages with timestamps
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

log "Starting certificate generation"

# Create certs directory if it doesn't exist
mkdir -p certs

# Generate certificates with auth-service in the SAN field
log "Generating certificates with auth-service in the SAN field..."

# Generate CA certificate
log "Generating CA certificate..."
cat > certs/ca.cnf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = TestCA

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = auth-service
IP.1 = 127.0.0.1
EOF

openssl req -x509 -newkey rsa:4096 -days 365 -nodes -keyout certs/ca-key.pem -out certs/ca-cert.pem -config certs/ca.cnf

# Generate server certificate request
log "Generating server certificate request..."
cat > certs/server.cnf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = auth-service

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = auth-service
IP.1 = 127.0.0.1
EOF

openssl req -newkey rsa:4096 -nodes -keyout certs/server-key.pem -out certs/server-req.pem -config certs/server.cnf

# Sign the certificate
log "Signing server certificate..."
openssl x509 -req -in certs/server-req.pem -days 60 -CA certs/ca-cert.pem -CAkey certs/ca-key.pem -CAcreateserial -out certs/server-cert.pem -extfile certs/server.cnf -extensions v3_req

# Generate client certificate for mTLS
log "Generating client certificate..."
cat > certs/client.cnf << EOF
[req]
distinguished_name = req_distinguished_name
prompt = no

[req_distinguished_name]
CN = auth-service
EOF

openssl req -newkey rsa:4096 -nodes -keyout certs/client-key.pem -out certs/client-req.pem -config certs/client.cnf

# Sign the client certificate
openssl x509 -req -in certs/client-req.pem -days 60 -CA certs/ca-cert.pem -CAkey certs/ca-key.pem -CAcreateserial -out certs/client-cert.pem

# Clean up config files
rm -f certs/ca.cnf certs/server.cnf certs/client.cnf

# Set permissions (this is primarily for Unix-like systems)
if [[ "$OSTYPE" != "msys"* && "$OSTYPE" != "cygwin"* && "$OSTYPE" != "win"* ]]; then
    chmod -R 755 certs
fi

log "Certificate generation completed successfully"
log "Certificates are available in the 'certs' directory:"
log "  - CA certificate: certs/ca-cert.pem"
log "  - Server certificate: certs/server-cert.pem"
log "  - Server key: certs/server-key.pem"
log "  - Client certificate: certs/client-cert.pem"
log "  - Client key: certs/client-key.pem" 
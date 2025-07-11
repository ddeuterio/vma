#!/bin/bash

PEM_FILE="/etc/certs/cert.pem"
KEY_FILE="/etc/certs/key.pem"
DAYS_LEFT=7
SUBJECT="/C=ES/ST=MAD/L=MAD/O=VMA/CN=vma.local"
KEY_BITS=2048
CERT_DAYS=365

# Check if PEM file exists
if [ ! -f "$PEM_FILE" ]; then
    echo "PEM file not found, generating new self-signed certificate."
    openssl req -x509 -newkey rsa:$KEY_BITS -keyout "$KEY_FILE" -out "$PEM_FILE" \
        -days $CERT_DAYS -nodes -subj "$SUBJECT"
    exit 0
fi

# Check if certificate expires within DAYS_LEFT days
openssl x509 -checkend $((DAYS_LEFT * 86400)) -noout -in "$PEM_FILE"
if [ $? -ne 0 ]; then
    echo "Certificate is expiring within $DAYS_LEFT days. Renewing..."
    # Backup old certificate
    cp "$PEM_FILE" "${PEM_FILE}.bak_$(date +%Y%m%d%H%M%S)"
    # Generate new self-signed certificate (key and cert in one PEM)
    openssl req -x509 -newkey rsa:$KEY_BITS -keyout "$KEY_FILE" -out "$PEM_FILE" \
        -days $CERT_DAYS -nodes -subj "$SUBJECT"
    echo "New self-signed certificate generated and saved to $PEM_FILE"
    nginx -s reload
    echo "nginx reloaded"
else
    echo "Certificate is valid for more than $DAYS_LEFT days. No action taken."
fi

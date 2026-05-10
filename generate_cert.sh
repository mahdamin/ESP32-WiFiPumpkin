#!/bin/bash
# generate_cert.sh - Create a self-signed SSL certificate for helloworld.com
# This certificate will be embedded in the ESP32 firmware

DOMAIN="helloworld.com"
CERT_FILE="cert.pem"
KEY_FILE="key.pem"
CSR_FILE="cert.csr"
DAYS=365

echo "════════════════════════════════════════════════════════"
echo "Generating Self-Signed SSL Certificate"
echo "Domain: $DOMAIN"
echo "Validity: $DAYS days"
echo "════════════════════════════════════════════════════════"

# Generate private key
echo "[1] Generating private key..."
openssl genrsa -out $KEY_FILE 2048

# Generate CSR (Certificate Signing Request)
echo "[2] Generating certificate signing request..."
openssl req -new \
    -key $KEY_FILE \
    -out $CSR_FILE \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=$DOMAIN"

# Generate self-signed certificate
echo "[3] Generating self-signed certificate..."
openssl x509 -req \
    -days $DAYS \
    -in $CSR_FILE \
    -signkey $KEY_FILE \
    -out $CERT_FILE \
    -extfile <(printf "subjectAltName=DNS:$DOMAIN,DNS:www.$DOMAIN")

# Verify certificate
echo ""
echo "[4] Certificate Information:"
openssl x509 -in $CERT_FILE -text -noout | grep -A 5 "Subject:\|Issuer:\|Not Before:\|Not After:\|DNS:"

# Combine cert + key for ESP32
echo ""
echo "[5] Creating combined PEM file..."
cat $CERT_FILE $KEY_FILE > server.pem

# Display the PEM files (for embedding in C code)
echo ""
echo "════════════════════════════════════════════════════════"
echo "IMPORTANT: Copy these for embedding in the C code:"
echo "════════════════════════════════════════════════════════"
echo ""
echo "--- CERTIFICATE (cert.pem) ---"
cat $CERT_FILE
echo ""
echo "--- PRIVATE KEY (key.pem) ---"
cat $KEY_FILE
echo ""

# Convert to C string format (for easier embedding)
echo "════════════════════════════════════════════════════════"
echo "C String Format (for embedding):"
echo "════════════════════════════════════════════════════════"
echo ""
echo "static const char server_cert[] = {"
cat $CERT_FILE | openssl enc -base64 -A | od -An -tx1 | awk '{for(i=1;i<=NF;i++)printf "0x%s, ", $i; print ""}'
echo "};"
echo ""

# Display file paths
echo ""
echo "✅ Files created:"
echo "   - $CERT_FILE (certificate)"
echo "   - $KEY_FILE (private key)"
echo "   - $CSR_FILE (signing request, can be deleted)"
echo "   - server.pem (combined)"
echo ""
echo "📌 Next steps:"
echo "   1. Copy cert.pem and key.pem content to the C code"
echo "   2. Or use the provided Python helper: python3 cert_to_c.py"
echo ""
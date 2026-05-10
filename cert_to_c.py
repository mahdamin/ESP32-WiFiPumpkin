#!/usr/bin/env python3
"""
cert_to_c.py - Convert SSL certificate and key to C code format
Usage: python3 cert_to_c.py cert.pem key.pem > certs.h
"""

import sys
import os

def file_to_c_string(filename):
    """Convert a file to a C string constant"""
    if not os.path.exists(filename):
        print(f"Error: File not found: {filename}", file=sys.stderr)
        return None
    
    with open(filename, 'r') as f:
        content = f.read()
    
    # Escape special characters for C
    content = content.replace('\\', '\\\\')
    content = content.replace('"', '\\"')
    content = content.replace('\n', '\\n')
    
    return content

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 cert_to_c.py cert.pem key.pem", file=sys.stderr)
        print("This will output C code to include in your ESP32 firmware", file=sys.stderr)
        sys.exit(1)
    
    cert_file = sys.argv[1]
    key_file = sys.argv[2]
    
    cert_content = file_to_c_string(cert_file)
    key_content = file_to_c_string(key_file)
    
    if not cert_content or not key_content:
        sys.exit(1)
    
    # Generate C header file
    output = '''/* ════════════════════════════════════════════════════════
   SSL Certificate and Key for HTTPS on ESP32
   Auto-generated from:
   - Certificate: {}
   - Private Key: {}
   Generated for: helloworld.com
   ═════════════════════════════════════════════════════ */

#ifndef CERT_KEY_H
#define CERT_KEY_H

/* Self-signed certificate for helloworld.com */
static const char server_cert_pem[] =
"{}";

/* Private key for the certificate */
static const char server_key_pem[] =
"{}";

#endif /* CERT_KEY_H */
'''.format(cert_file, key_file, cert_content, key_content)
    
    print(output)
    print("", file=sys.stderr)
    print("✅ C header generated! Save the output to 'certs.h'", file=sys.stderr)
    print("", file=sys.stderr)
    print("Example:", file=sys.stderr)
    print("  python3 cert_to_c.py cert.pem key.pem > certs.h", file=sys.stderr)
    print("", file=sys.stderr)
    print("Then include in your C file:", file=sys.stderr)
    print('  #include "certs.h"', file=sys.stderr)

if __name__ == '__main__':
    main()
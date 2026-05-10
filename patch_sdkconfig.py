#!/usr/bin/env python3
import re, os, glob

# Find sdkconfig wherever it is
candidates = glob.glob("sdkconfig") + glob.glob("sdkconfig.*") + \
             glob.glob("**\\sdkconfig", recursive=True) + \
             glob.glob("**/sdkconfig", recursive=True)

print("Files found:", candidates)

# Pick the plain sdkconfig (no extension)
sdkconfig_path = None
for c in candidates:
    if os.path.basename(c) == "sdkconfig":
        sdkconfig_path = c
        break

if not sdkconfig_path:
    # Just list everything in current dir so user can see
    print("\nAll files in current directory:")
    for f in os.listdir("."):
        print(" ", f)
    exit(1)

print(f"Using: {sdkconfig_path}")

with open(sdkconfig_path, 'r') as f:
    content = f.read()

changes = {
    "CONFIG_LWIP_MAX_SOCKETS":           "16",
    "CONFIG_HTTPD_MAX_REQ_HDR_LEN":      "1024",
    "CONFIG_HTTPD_MAX_URI_LEN":          "512",
    "CONFIG_LWIP_TCPIP_TASK_STACK_SIZE": "4096",
}

for key, val in changes.items():
    pattern = rf'^{key}=.*$'
    replacement = f'{key}={val}'
    if re.search(pattern, content, re.MULTILINE):
        content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
        print(f"Updated: {key}={val}")
    else:
        content += f'\n{key}={val}\n'
        print(f"Added:   {key}={val}")

with open(sdkconfig_path, 'w') as f:
    f.write(content)

print("\nDone. Now run: idf.py build")
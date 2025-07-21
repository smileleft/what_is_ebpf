#!/bin/bash
echo "[*] Sending HTTP GET request to localhost..."
curl -v http://localhost/ 2>&1 | grep -i "HTTP"


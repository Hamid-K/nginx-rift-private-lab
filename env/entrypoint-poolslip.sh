#!/usr/bin/env bash
set -euo pipefail

cd /app
python3 server.py >/dev/null 2>&1 &
exec /nginx-src/build/nginx -p /app -c /app/nginx-poolslip.conf

#!/usr/bin/env bash
set -euo pipefail

cd /app
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:detect_odr_violation=0:abort_on_error=1:disable_coredump=1:symbolize=1}"
exec /nginx-src/objs/nginx -p /app -c /app/nginx-njs-fetch-proxy.conf

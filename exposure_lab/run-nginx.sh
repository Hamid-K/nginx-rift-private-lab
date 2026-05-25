#!/bin/sh
set -eu

WORKDIR="${WORKDIR:-/work}"
CONF="${NGINX_CONF:-/work/nginx.conf}"

mkdir -p /tmp/rift-exposure-client-body \
    /tmp/rift-exposure-proxy \
    /tmp/rift-exposure-fastcgi \
    /tmp/rift-exposure-uwsgi \
    /tmp/rift-exposure-scgi

export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=1:disable_coredump=1:symbolize=1}"

exec /nginx-src/build/nginx -p "${WORKDIR}" -c "${CONF}" -g 'daemon off; master_process off;'


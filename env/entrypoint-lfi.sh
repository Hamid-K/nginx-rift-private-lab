#!/bin/bash
cd /app

sed -i \
  -e 's/^user = .*/user = nobody/' \
  -e 's/^group = .*/group = nogroup/' \
  -e 's/^listen.owner = .*/listen.owner = nobody/' \
  -e 's/^listen.group = .*/listen.group = nogroup/' \
  /etc/php/8.1/fpm/pool.d/www.conf

python3 server.py &>/dev/null &
php-fpm8.1 -D
# CTF mode intentionally leaves ASLR enabled. The attacker must recover
# process-specific bases through the exposed web primitives.
exec /nginx-src/build/nginx -p /app -c "${NGINX_CONF:-/app/nginx-lfi.conf}"

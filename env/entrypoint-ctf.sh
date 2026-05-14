#!/bin/bash
cd /app

python3 server.py &>/dev/null &
runuser -u nobody -- php -S 0.0.0.0:19324 -t /app/leak &>/dev/null &

# CTF mode leaves ASLR policy untouched and keeps the vulnerable nginx
# configuration identical to the original PoC. The PHP leak surface is a
# separate local web app running as the same UID as nginx workers.
exec /nginx-src/build/nginx -p /app -c /app/nginx.conf

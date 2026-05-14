#!/usr/bin/env bash
set -euxo pipefail

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y \
  gcc make libpcre2-dev libssl-dev zlib1g-dev \
  util-linux python3 curl git php-fpm

if [ ! -d /nginx-src/.git ]; then
  git clone https://github.com/nginx/nginx.git /nginx-src
fi

cd /nginx-src
git fetch --all --tags
git checkout 98fc3bb78

if [ ! -x /nginx-src/build/nginx ]; then
  ./auto/configure \
    --builddir=build \
    --with-cc-opt='-g -O2 -fno-omit-frame-pointer' \
    --with-ld-opt='-Wl,-z,relro -Wl,-z,now' \
    --with-http_ssl_module --with-http_v2_module
  make -j"$(nproc)"
fi

mkdir -p /app/logs /app/tmp
cp /vagrant/env/nginx-lfi.conf /app/nginx-lfi.conf
cp /vagrant/env/server.py /app/server.py
cp /vagrant/env/lfi.php /app/lfi.php
cp /vagrant/env/phpinfo.php /app/phpinfo.php
chown -R nobody:nogroup /app/tmp

# Keep the CTF core-dump primitive local and LFI-readable. Stock Ubuntu routes
# cores through apport, which hides them from the web-only experiment.
systemctl disable --now apport || true
cat >/etc/sysctl.d/99-nginx-rift-core.conf <<'SYSCTL'
kernel.core_pattern = core
kernel.core_uses_pid = 0
fs.suid_dumpable = 2
SYSCTL
sysctl -w kernel.core_pattern=core
sysctl -w kernel.core_uses_pid=0
sysctl -w fs.suid_dumpable=2

sed -i \
  -e 's/^user = .*/user = nobody/' \
  -e 's/^group = .*/group = nogroup/' \
  -e 's/^listen.owner = .*/listen.owner = nobody/' \
  -e 's/^listen.group = .*/listen.group = nogroup/' \
  /etc/php/8.1/fpm/pool.d/www.conf

cat >/etc/systemd/system/nginx-rift-backend.service <<'UNIT'
[Unit]
Description=Nginx Rift toy backend
After=network.target

[Service]
WorkingDirectory=/app
ExecStart=/usr/bin/python3 /app/server.py
Restart=always

[Install]
WantedBy=multi-user.target
UNIT

cat >/etc/systemd/system/nginx-rift.service <<'UNIT'
[Unit]
Description=Nginx Rift vulnerable nginx
After=network.target php8.1-fpm.service nginx-rift-backend.service
Requires=php8.1-fpm.service nginx-rift-backend.service

[Service]
WorkingDirectory=/app
ExecStart=/nginx-src/build/nginx -p /app -c /app/nginx-lfi.conf
ExecReload=/bin/kill -HUP $MAINPID
KillMode=mixed
LimitCORE=infinity
Restart=always

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl restart php8.1-fpm
systemctl enable --now nginx-rift-backend
systemctl restart nginx-rift || systemctl start nginx-rift
systemctl enable nginx-rift

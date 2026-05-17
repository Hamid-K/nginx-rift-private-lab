# Nginx Rift CTF Experiment Log

Last updated: 2026-05-15 05:32:17 CEST

## 2026-05-14

### Branch And Baseline Setup

- Created/continued branch `ctf-remote-aslr-lfi`.
- Kept the original Nginx Rift PoC path available through `env/Dockerfile`, `env/docker-compose.yml`, `env/nginx.conf`, `env/entrypoint.sh`, and `poc.py`.
- Pinned the Docker service to `linux/amd64` because the exploit and target binary are x86_64-specific while the host is arm64.
- Extended `poc.py` with optional `--heap-base`, `--libc-base`, and `--system-addr` arguments so baseline runs can be reproduced without editing source.

### Original PoC Reproduction

- Brought up the default lab with `docker compose -f env/docker-compose.yml up -d --build --force-recreate`.
- Ran `./poc.py --host 127.0.0.1 --port 19321 --cmd 'echo rift-default-ok > /tmp/rift_default_marker'`.
- Verified with Docker lab introspection that `/tmp/rift_default_marker` exists and contains `rift-default-ok`.
- Conclusion: the original ASLR-disabled/default-layout PoC still achieves command execution in this environment.

### Same-Port PHP LFI Overlay

- Added `env/Dockerfile.lfi`, `env/docker-compose.lfi.yml`, `env/nginx-lfi.conf`, `env/entrypoint-lfi.sh`, `env/lfi.php`, and `env/phpinfo.php`.
- Configured nginx and PHP-FPM workers to run as `nobody:nogroup` so the PHP local-file-read primitive can read same-UID nginx worker `/proc/<pid>` files.
- Confirmed `lfi.php?file=/proc/self/status` returns PHP-FPM process status with UID `65534`.
- Confirmed the nginx pid file is readable through LFI at `/app/tmp/nginx.pid`.
- Confirmed the nginx worker PID can be discovered through `/proc/<master>/task/<master>/children` and status checks.
- Confirmed `lfi.php?file=/proc/<nginx-worker>/maps` exposes nginx image mappings and libc mappings for the nginx worker.

### Remote Address Derivation Driver

- Added `ctf_remote_exploit.py`.
- The driver uses HTTP-only primitives to:
  - read phpinfo as a hint source,
  - discover the PHP UID,
  - discover the same-UID nginx worker PID,
  - read nginx worker maps,
  - derive the nginx writable image mapping,
  - derive libc base and libc path,
  - read libc via LFI,
  - parse the ELF dynamic symbol table for `system`,
  - build PoC candidates without hardcoded ASLR base addresses,
  - verify proof through LFI instead of Docker.
- First same-port run derived the expected addresses and `system()` address, but all attempts produced worker disruption without a marker file.

### Diagnostic Side-Port Variant

- Added `env/Dockerfile.ctf`, `env/docker-compose.ctf.yml`, and `env/entrypoint-ctf.sh` as a diagnostic mode.
- This mode exposes vulnerable nginx on `19321` and a same-UID PHP built-in server on `19324`.
- The side-port driver run also derived nginx worker maps and `system()` through HTTP, but it produced worker disruption without proof.
- User correctly pointed out that this topology is less realistic because normal deployments commonly expose PHP through the same nginx instance/port. Treat this mode as diagnostic only.

### ASLR And Platform Observation

- The CTF entrypoints leave `randomize_va_space` untouched; LFI showed `/proc/sys/kernel/randomize_va_space` as `2`.
- `/proc/<nginx-worker>/personality` showed `00000000`, not `ADDR_NO_RANDOMIZE`.
- Despite that, nginx/libc mappings appeared fixed across restarts on this host.
- Explanation: non-native Docker is running an amd64 container under emulation on an arm64 host. Do not over-interpret fixed-looking addresses from this lab host as normal Linux ASLR behavior.

### Core-Dump Observation

- The original nginx config includes `worker_rlimit_core 500M` and `working_directory tmp`.
- After crashes, `/app/tmp/core` exists in the container and is owned by the nginx worker user.
- This creates a potential LFI-assisted path: trigger one crash, read the core through LFI, locate the sprayed payload address, then retry with a computed cleanup pointer.
- Caveat: this is a powerful lab primitive but not guaranteed realistic. Production systems often disable core dumps, redirect them, or restrict access.

### Documentation And Version-Control Change

- Added living docs:
  - `docs/CTF_PLAN.md`
  - `docs/CTF_EXPERIMENT_LOG.md`
  - `docs/CTF_TESTS.md`
  - `docs/CTF_FINDINGS.md`
- Committed the first stable checkpoint: `12956c1` (`Add CTF remote LFI lab checkpoint`).
- Next step is same-port core-guided testing.

### Same-Port Core-Guided Attempt 1

- Ran `./ctf_remote_exploit.py --host 127.0.0.1 --port 19321 --core-guided --tries-per-candidate 10 --verbose`.
- The driver again derived nginx worker maps and `system()` through same-port HTTP-only LFI.
- Probe crash produced an LFI-readable core.
- Core search found two URI-safe sprayed-body addresses:
  - `0x5555556b3477`
  - `0x555555754a77`
- Retrying those addresses produced worker disruption but no LFI-visible marker proof.
- Current interpretation: core reading and sprayed-body discovery work, but the recovered fake-structure address is not yet sufficient as the overwrite target. The PoC likely requires a more precise relationship between the cleanup pointer, preread buffer layout, and sprayed body.

### PoC Mechanics Review

- Reviewed `poc.py` and the disclosure writeup.
- Confirmed the URI overwrite target should be the address of a fake `ngx_pool_cleanup_s` structure.
- Confirmed `data_addr` should be the fake structure address plus 24 bytes, because the command string follows `handler`, `data`, and `next`.
- The first core-guided attempt therefore used the correct address type in principle.
- New hypothesis: reading the large core through the same nginx/PHP path perturbs the fresh worker before final exploitation. Added a default worker-reset crash after core parsing and before trying core-derived addresses.

### Same-Port Core-Guided Attempt 2: Worker Reset

- Ran the same core-guided command after adding a post-core-read worker reset.
- The driver found the same two URI-safe sprayed-body addresses:
  - `0x5555556b3477`
  - `0x555555754a77`
- The driver reset the worker after parsing the core and before final attempts.
- Result remained worker disruption without marker proof.
- Current interpretation: the final failure is not simply caused by LFI core-read traffic perturbing the next worker. Next step is inspecting the crash core for the overwritten victim pool/cleanup pointer bytes.

### Native Architecture Track Decision

- User asked whether switching to ARM would help, then suggested a real Ubuntu VM through Vagrant on a lab x86_64 hypervisor.
- Decision: stay x86_64 and use Vagrant for the realism track.
- Rationale:
  - ARM64 removes non-native amd64 Docker runtime artifacts but invalidates the original x86_64 PoC heap candidates and changes libc/codegen/layout.
  - A real x86_64 Ubuntu VM removes the non-native Docker emulation caveat while preserving the architecture the PoC was tuned for.
- An ARM64 overlay briefly built during exploration, then the lab was returned to the x86_64 same-port CTF image and the ARM overlay was removed from the branch.

### Vagrant ESXi Attempt 1

- Added `Vagrantfile`, `vagrant/provision.sh`, and `docs/VAGRANT_ESXI.md`.
- Confirmed hypervisor SSH key authentication works.
- Confirmed `vagrant validate` succeeds when an ESXi password spec is syntactically available.
- Ran `vagrant up --provider=vmware_esxi`.
- Vagrant downloaded `generic/ubuntu2204` VMware box and started the ESXi build.
- `ovftool` prompted for an ESXi password despite SSH key auth; this is expected for this provider because `ovftool` does not use SSH keys.
- Killed the launch before any VM was created. `vagrant status` reports `not created`, and `vim-cmd vmsvc/getallvms` shows no `nginx-rift-lab` VM.
- Next VM launch requires `ESXI_PASSWORD_SPEC=env:ESXI_PASSWORD`, `ESXI_PASSWORD_SPEC=file:/path`, or an interactive `prompt:` run.

### Vagrant ESXi Launch And Manual Provision

- User clarified that the password prompt was intended for `ovftool` operations, not SSH to `a lab hypervisor`.
- Kept provider SSH key-based and provided the `ovftool` password through an environment-backed prompt.
- Launched the VM through `vagrant up --provider=vmware_esxi`.
- ESXi created a VM with guest IP `<target-host>`.
- Vagrant provider guest communication did not complete cleanly, but direct Vagrant-key SSH to `vagrant@<target-host>` worked.
- Synced the repo manually to `/vagrant` and ran `sudo bash /vagrant/vagrant/provision.sh`.
- Provisioning installed/build the nginx target, PHP-FPM, same-port LFI/phpinfo routes, and systemd services.
- Smoke test passed:
  - `http://<target-host>:19321/` returned `ok`.
  - PHP-FPM LFI `/proc/self/status` showed UID/GID `65534`.
  - `/proc/sys/kernel/randomize_va_space` returned `2`.
  - guest architecture is `x86_64`.

### VM Core-Dump Provisioning Fix

- First VM core-guided run failed to read `/app/tmp/core`.
- Guest checks showed Ubuntu routed cores through apport:
  - `/proc/sys/kernel/core_pattern` was an apport pipe.
  - the shell `ulimit -c` was `0`.
- Updated `vagrant/provision.sh` to:
  - disable apport for the lab,
  - set `kernel.core_pattern=core`,
  - set `kernel.core_uses_pid=0`,
  - set `fs.suid_dumpable=2`,
  - make `/app/tmp` owned by `nobody:nogroup`.
- Re-ran provisioning on the VM.
- LFI confirmed:
  - `/proc/sys/kernel/core_pattern` is `core`,
  - `/proc/sys/fs/suid_dumpable` is `2`,
  - `/proc/sys/kernel/randomize_va_space` remains `2`.

### VM Core-Guided Attempt 1

- Patched `ctf_remote_exploit.py` so core-guided mode can generate a probe core using URI-safe bogus address `0x303030303030` when the current ASLR layout has no legacy URI-safe candidates.
- Ran `./ctf_remote_exploit.py --host <target-host> --port 19321 --core-guided --tries-per-candidate 2 --proof-delay 0.25 --verbose`.
- The driver derived over HTTP:
  - nginx worker PID,
  - nginx writable image mapping,
  - worker heap ranges,
  - libc base/path,
  - `system()` offset and absolute address from LFI-read libc.
- The current VM master layout produced `0 / 20` URI-safe legacy candidates.
- The core probe created an LFI-readable `/app/tmp/core`, but the first search reported no URI-safe sprayed-body hits.
- Added driver instrumentation to distinguish total core hits from URI-safe hits.

### VM Core-Guided Attempt 2: URI Safety Accounting

- Re-ran the VM core-guided driver after instrumentation.
- Result:
  - `Core-guided sprayed-body addresses: 0 URI-safe / 20 total`
  - sample unsafe hits included `0x55d484df7477`, `0x55d484dfdeb7`, and `0x55d484e5e1b7`.
- Interpretation: core-guided LFI can recover sprayed fake-structure addresses on the VM, but this ASLR layout makes all recovered addresses unusable for the PoC's six-byte URI overwrite path.
- No marker proof has been achieved on the real x86_64 VM.

### VM ASLR Candidate Sampling

- Added `--derive-only` to `ctf_remote_exploit.py` so the driver can print target facts without sending exploit attempts.
- Sampled 12 fresh nginx master layouts on the VM using lab-control service restarts.
- Results:
  - samples `1..12` all had `0 / 20` URI-safe legacy cleanup candidates.
  - observed nginx writable image mappings included `0x55c59b3ce000`, `0x55ab22265000`, `0x55e693dbc000`, `0x555da1ccc000`, `0x55a02cf5a000`, `0x5559cdd81000`, `0x55cbe7f0e000`, `0x558fd8411000`, `0x5559c6dfa000`, `0x56040dbbe000`, `0x5558fcaae000`, and `0x55e899590000`.
- A tight restart loop briefly hit systemd's start-rate limit; `systemctl reset-failed nginx-rift` restored the service, and sampling continued with a slower stop/start cadence.
- Interpretation: real x86_64 ASLR does vary the target bases as expected, and the current PoC candidate model is usually blocked by the URI-safe byte filter before the exploit reaches the cleanup-object precision problem.

### File-Read Primitive Clarification

- User asked whether the limitation is the LFI vector and whether a proper arbitrary local file download bug changes the conclusion.
- Clarified finding: the lab LFI already behaves like a strong file-download primitive for the relevant files, including ranged reads.
- Strong arbitrary file read helps with target fingerprinting, downloading exact binaries/libraries, reading `/proc/<pid>/maps` when permissions allow, and reading accessible crash cores.
- It does not automatically expose live heap contents. `/proc/<pid>/mem` is not normally readable through ordinary file-read bugs, and `/proc/<pid>/maps` does not contain object contents.
- Current VM blocker therefore remains address usability and heap/object precision, not simple inability to download local files.

### Strategy Pivot: Partial Cleanup Pointer Overwrite

- User offered several routes to continue, including finding a new primitive, using a twin VM, or discovering a way to correlate/process ASLR.
- Chosen first candidate: partial pointer overwrite using a common nginx web behavior.
- Source review notes:
  - `ngx_create_pool()` initializes `pool->cleanup = NULL`.
  - `ngx_destroy_pool()` calls `c->handler(c->data)` for each `pool->cleanup` entry.
  - `ngx_pool_cleanup_add()` prepends cleanup records to `pool->cleanup`.
  - `ngx_create_temp_file()` registers a pool cleanup record, and nginx request body buffering can create temp files for large request bodies.
- Hypothesis: the original PoC targets a NULL cleanup pointer in an incomplete victim request pool, requiring a full six-byte fake-structure address in the URI. If the victim request has already registered a real cleanup pointer, we can overwrite only the low 2-4 bytes and inherit the unsafe high bytes from nginx's legitimate cleanup pointer.
- This would turn the blocker from "all six pointer bytes must be URI-safe" into "only the overwritten low bytes must be URI-safe and the fake structure must be near the real cleanup record."

### Partial Overwrite Geometry Experiments

- Added `/victim_upload` to the nginx lab config to force large request-body buffering and a real request-pool cleanup entry.
- Parameterized the PoC and CTF driver with:
  - `--target-len`,
  - `--upload-victim`,
  - `--victim-body-len`,
  - `--a-count`,
  - `--plus-count`.
- Added core pattern inspection to the CTF driver.
- VM run with full six-byte safe candidates still produced worker disruption without marker proof.
- Diagnostic safe marker `QWXYZV` plus upload victim showed:
  - marker lands in the generated overflow/request area,
  - upload victim creates a plausible request pool with non-NULL `pool->cleanup`,
  - the cleanup field is after the marker, initially about `0xf50` bytes away.
- Increasing `plus_count` moves the marker, but the request geometry changes at allocator/header-buffer thresholds:
  - with `client_header_buffer_size 2048`, the stable crash path stopped near `plus_count=1640`, still about `0x763` bytes short.
  - with `client_header_buffer_size 4096`, stable crash path extended to around `plus_count=2610`, but still remained about `0xc15` bytes short before another allocation/layout transition.
- Changing victim upload body size did not move the cleanup-bearing request pool in this setup.
- Request-pool-size sampling showed smaller pools did not preserve the same crash path; larger pools moved the cleanup field farther away.
- Direct `/proc/<nginx-worker>/mem` through PHP LFI was tested and returned 404 with `ptrace_scope=1`, so live worker memory is not available through the current file-read primitive.
- Pulled nginx structure offsets from the matching source/build:
  - `sizeof(ngx_pool_t)=80`,
  - `ngx_pool_t.cleanup=64`,
  - `sizeof(ngx_http_request_t)=1352`,
  - `ngx_http_request_t.signature=0`,
  - `ngx_http_request_t.pool=88`,
  - `ngx_http_request_t.cleanup=1136`.
- User reminded to consult nginx source and use live debug on the clone VM when weird-machine behavior changes unexpectedly. Next step is debug-first analysis of request allocation transitions rather than blind parameter sweeps.
- Source check in `ngx_http_alloc_large_header_buffer()` explains the observed geometry discontinuities: when the request line exhausts the active header buffer, nginx allocates/copies into `large_client_header_buffers` from the connection pool. The overflow then moves relative to request-pool objects, so increasing `plus_count` is not a linear write-length control across the threshold.
- Next geometry control should tune `large_client_header_buffers` and request sequencing with live debugging, not only `plus_count`.
- Tested `large_client_header_buffers 4 16384`; the transition still occurred after the stable `plus_count=2600` path. The cleanup-bearing victim pool disappeared from recognizable core scans for larger plus counts.
- Current partial-overwrite blocker: a non-NULL cleanup pointer exists, but the accessible overflow geometry reaches nearby request/pool memory, not the cleanup pointer field itself.
- Correction: no second clone VM has been created yet. All ESXi VM tests so far used the single VM at `<target-host>`. A separate clone/twin VM must be created before using live debugger output as non-target oracle data.

## 2026-05-15

### Debug Twin VM

- User fixed the ESXi NIC/port-group issue.
- Created/provisioned a separate debug/twin VM at `<debug-host>:19321` for live-debugging and layout experiments.
- Kept the original target VM at `<target-host>:19321` as the CTF target.
- Installed `gdb` and set `kernel.yama.ptrace_scope=0` only on the debug/twin VM.
- Added `debug/gdb_trace_request.gdb` to trace request allocations, rewrite copy positions, cleanup registration, request freeing, and pool destruction.
- Rule clarification: gdb and direct SSH-derived offsets from `<debug-host>` are allowed for source/layout understanding, but target exploitation against `<target-host>` must still use HTTP/LFI primitives or version/distro facts.

### Slot-Scan Core Probe

- Added a slot-probe spray body that writes a unique nonce at many 8-byte-aligned offsets inside the 4000-byte POST body.
- Added core scanning that finds these nonce records in an LFI-readable core and maps them back to candidate fake-cleanup structure addresses and body offsets.
- Default 6-byte mode on the debug VM found thousands of sprayed slots in the core, but zero URI-safe addresses.
- 3-byte mode also produced zero URI-safe candidates in the tested layout.
- 2-byte mode produced hundreds of URI-safe low-byte candidates, but trying the first candidate batch still gave worker disruption without marker proof.
- Current interpretation: slot recovery works, but a 2-byte partial overwrite must be filtered against the victim cleanup pointer's preserved high bytes. Trying arbitrary low-byte-safe sprayed slots is too broad and mostly points the cleanup pointer to the wrong 64 KiB window.

### Live Debug Geometry Results

- GDB tracing on the debug/twin VM confirmed the vulnerable copy location, the upload victim cleanup registration, and the later crash site.
- With the repo/default config (`request_pool_size 7920`, `connection_pool_size 4096`, `client_header_buffer_size 4096`, `large_client_header_buffers 4 16384`) and `a_count=349`, `plus_count=2600`, the marker landed roughly 3123 bytes before the victim `pool->cleanup` slot.
- Increasing `plus_count` moved the marker linearly only up to a narrow threshold. Past the threshold nginx switched allocation/copy geometry, and the overflow moved into malloc metadata or other request/log objects instead of the desired cleanup slot.
- Reducing `connection_pool_size` was the strongest layout lever:
  - `request_pool_size=4096`, `connection_pool_size=1536`, `a_count=128`, `plus_count=2800` left about a 160-byte gap.
  - `request_pool_size=4096`, `connection_pool_size=1472`, `a_count=128`, `plus_count=2800` left about a 96-byte gap.
  - `request_pool_size=4096`, `connection_pool_size=1456`, `a_count=128`, `plus_count=2800` left about an 80-byte gap.
- Literal prefix padding in `set $original_endpoint` can shift the marker slightly without increasing attacker URI length:
  - With `connection_pool_size=1456`, an 11-byte literal prefix before `$1` reduced the stable gap to about 69 bytes.
  - At 12 bytes and beyond, the allocation path changed and the target disappeared from the stable crash geometry.
- Varying spray count did not materially change this best stable gap once enough sprays were present.
- Changing `client_header_buffer_size` away from 4096 either increased the gap or moved into a bad layout.
- `connection_pool_size` must be a multiple of 16; invalid intermediate values fail nginx config validation.

### Split-Capture Experiment

- Tried changing the vulnerable route to split the capture into `$1` plus a final six-byte `$2`, with a literal suffix between them:
  - Intended effect: preserve the old request-line allocation path while shifting only the final overwritten bytes toward the cleanup slot.
  - Implementation used `location ~ ^/api/(.*)(......)$` because the unquoted `{6}` regex form was rejected by nginx config parsing in this context.
- Result: the layout moved to a bad/large-allocation path; core hits were not usable for the intended escaped-copy position, and the nearest recognizable pools were far away.
- Current status: abandoned as the primary path unless source review reveals a better way to split captures without changing the vulnerable script engine behavior.

### Worker Crash And Brute Force Note

- A bounded brute-force path is acceptable if each attempt is remote-only, uses HTTP/LFI-derived facts, and has a clear success proof.
- Nginx worker crashes are normally recovered by the master spawning a replacement worker, so single attempts are not permanent process loss.
- Practical caveats remain: rapid repeated crashes are service disruption, master start-rate/systemd limits can be hit in lab control scenarios, and core dumps can fill disk if enabled.

### Cleanup-Window Filter And Delayed Upload Test

- Added cleanup-window filtering for partial overwrite slot scans:
  - scan the LFI-readable core for plausible `ngx_pool_t` objects,
  - collect non-NULL `pool->cleanup` pointers,
  - for partial overwrites, keep only sprayed fake-structure slots whose preserved high bytes match an observed cleanup pointer window.
- Default single-capture debug run (`target_len=2`, upload victim, `a_count=349`, `plus_count=2600`) found:
  - 737 URI-safe slot candidates out of 9940 slot markers,
  - 4 plausible cleanup-bearing pools,
  - 0 cleanup pointers whose low bytes matched the probe overwrite,
  - 125 slot candidates matching some observed cleanup pointer window,
  - no marker proof from the first 20 filtered attempts.
- Interpretation: the default layout still crashes before proving control of `pool->cleanup`; brute-forcing low bytes here is mostly noise.
- Added `--delay-victim-body` so the victim upload headers are sent before the overflow and the large body is sent after the overflow.
- Default delayed-upload run found:
  - 737 URI-safe slot candidates,
  - 2 plausible cleanup-bearing pools,
  - 0 cleanup pointers with probe low bytes,
  - 0 safe slots matching observed cleanup windows.
- Tuned near-miss delayed-upload run (`request_pool_size=4096`, `connection_pool_size=1456`, 11-byte set-prefix, `a_count=128`, `plus_count=2800`) found:
  - 940 URI-safe slot candidates,
  - 2 plausible cleanup-bearing pools,
  - 0 cleanup pointers with probe low bytes,
  - 0 safe slots matching observed cleanup windows.
- Live gdb on the tuned delayed-upload run showed the worker segfaults in `ngx_http_request_handler()` immediately after the vulnerable copy and before the delayed body can register a temp-file cleanup.
- Current conclusion: delayed upload is not useful unless another layout lever avoids the earlier request/log corruption.

### HTTP/2 Connection-Pool Cleanup Path

- Source review found that HTTP/2 setup registers a cleanup on the connection pool (`ngx_http_v2_pool_cleanup`), giving a non-NULL `pool->cleanup` before the vulnerable HTTP/1 request can corrupt the neighboring connection-pool objects.
- Enabled HTTP/2 on the same public port in the CTF lab with `listen 19321 http2;`. Plain HTTP/1.1 on the same port still reaches `/`, `/api/...`, `/lfi.php`, and `/phpinfo.php`.
- Added `--h2-victim` to the PoC/driver:
  - opens an HTTP/2 connection on the same nginx listener,
  - sends the HTTP/2 preface and SETTINGS frame,
  - sends a standards-compliant unknown extension frame carrying the same 4000-byte probe/fake-structure body,
  - leaves the connection alive as the corruption victim.
- Added corrupted/probe pool scanning for cores:
  - normal `ngx_pool_t` validation fails after the overwrite because `d.last`, `d.end`, `large`, and related fields are corrupted,
  - the new scanner specifically looks for pool-like 16-byte-aligned objects whose `cleanup` field has the probe low bytes and whose `log` pointer still maps to writable memory.
- GDB calibration on the debug clone:
  - `a_count=128`, `plus_count=962` reached the HTTP/2 connection pool but left the overwrite one byte misaligned.
  - `a_count=127`, `plus_count=962` aligned the low-2-byte partial overwrite on `pool->cleanup`.
- Debug clone win:
  - command: `./ctf_remote_exploit.py --host <debug-host> --port 19321 --core-guided --target-len 2 --h2-victim --a-count 127 --plus-count 962 --tries-per-candidate 1 --max-core-hits 100 --proof-delay 0.25 --core-delay 2 --verbose`
  - result: recovered one corrupted/probe pool and matched safe h2-body slots in the same 64 KiB window.
  - first final candidate executed the marker command and was verified through LFI.
- Target VM win:
  - deployed the updated branch lab config to `<target-host>` as lab setup.
  - ran the same command against the target VM, using only HTTP/LFI facts during exploitation.
  - target facts derived remotely included worker PID `15474`, nginx rw mapping `0x562f58677000`, libc base `0x7fca6acfa000`, and `system()` `0x7fca6ad4ad70`.
  - probe found `1` corrupted/probe pool with cleanup `0x562f58b23030`.
  - filter found `266` matching safe slots in that preserved high-byte window.
  - first final candidate `0x562f58b23627` at body offset `80` executed the marker command.
- Target repeat after clean service restart:
  - worker PID `15554`, nginx rw mapping `0x561281df2000`, libc base `0x7f576434f000`, `system()` `0x7f576439fd70`.
  - probe found `1` corrupted/probe pool and `45` matching safe slots.
  - first final candidate `0x5612824f777a` at body offset `0` executed the marker command.
- CTF status: won under the updated lab rules. The final exploit did not use target-side gdb, SSH-derived offsets, or hardcoded ASLR bases.

### Demo PoC Technical Improvement Pass

- Added `demo_ctf_exploit_v1_1.py` as a separate runner, preserving the known-good exploit and demo scripts.
- v1.1 adds remote preflight checks, PID-correlated core parsing, nonce freshness checks, bounded geometry auto-calibration, structured JSON artifacts, and candidate ranking against corrupted/probe cleanup pools.
- Fixed v1.1 reset behavior so a non-base calibrated geometry is also used for the pre-final reset crash.
- Validated v1.1 on target VM `<target-host>`:
  - ASLR remained enabled with `randomize_va_space=2`.
  - pre-probe worker PID `2394` matched the core PID.
  - probe core contained `1010` URI-safe slots out of `10437`.
  - the first ranked candidate `0x5641c34f4627` at body offset `80` executed the marker command.
  - artifact: `artifacts/demo_v1_1_20260515-050301.json`.
- Added `demo_ctf_exploit_v1_2.py` as the next minor-version runner.
- v1.2 adds remote OS/kernel fingerprinting, git/argv artifact metadata, pre-reset worker PID capture, reset-core re-scanning, strict `--require-reset-core` mode, and worker-recovery waits between failed final candidates.
- Validated v1.2 with `--require-reset-core` on target VM `<target-host>`:
  - pre-probe worker PID `2473` matched the first core.
  - pre-reset worker PID `2474` matched the reset core.
  - reset core contained `1204` URI-safe slots out of `10437`.
  - reset-core filtering produced `155` ranked matching slots.
  - the first reset-core candidate `0x56389b17277a` at body offset `0` executed the marker command.
  - artifact: `artifacts/demo_v1_2_20260515-050555.json`.
- Current preferred recording command:

```bash
./demo_ctf_exploit_v1_2.py --host <target-host> --port 19321 --clear --require-reset-core
```

### Continued Demo PoC Improvement Pass

- Added `demo_ctf_exploit_v1_3.py`.
- v1.3 re-derives target facts before each calibration probe, records target snapshots, enforces strict core PID matching by default, and checks pre-reset/final layout stability for nginx image, libc, and `system()`.
- Validated v1.3 on target VM `<target-host>`:
  - initial worker PID `2602`.
  - reset core PID `2604` matched the expected pre-reset worker.
  - reset core contained `928` URI-safe slots out of `10437`.
  - pre-reset and final worker layouts kept stable nginx/libc bases and `system()` address.
  - first final candidate `0x557f3875677a` at body offset `0` executed the marker command.
  - artifact: `artifacts/demo_v1_3_20260515-051328.json`.
- Added `demo_ctf_exploit_v1_4.py`.
- v1.4 adds strict preflight checks for ASLR/core/nginx topology and filters impossible final candidates before trying them.
- Validated v1.4 on target VM `<target-host>`:
  - strict preflight passed with ASLR enabled, `core_pattern=core`, `suid_dumpable=2`, and one nginx worker.
  - reset core PID `2681` matched the expected worker.
  - candidate sanity filter kept `45` candidates and dropped `0`.
  - first final candidate `0x55b9f862777a` at body offset `0` executed the marker command.
  - artifact: `artifacts/demo_v1_4_20260515-051517.json`.
- Added `demo_ctf_exploit_v1_5.py`.
- v1.5 adds bounded campaign mode with `--rounds` and per-round artifact records.
- Validated v1.5 with `--rounds 2` on target VM `<target-host>`:
  - round 1 reset core PID `2759` matched the expected worker.
  - reset core contained `928` URI-safe slots out of `10437`.
  - candidate sanity filter kept `166` candidates and dropped `0`.
  - first final candidate `0x557c5768677a` at body offset `0` executed the marker command.
  - round 2 was not needed.
  - artifact: `artifacts/demo_v1_5_20260515-051730.json`.
- Current preferred recording command:

```bash
./demo_ctf_exploit_v1_5.py --host <target-host> --port 19321 --clear --require-reset-core --rounds 2
```

### v1.6 Reliability And Research Features

- Added `demo_ctf_exploit_v1_6.py`.
- Implemented hardened command construction:
  - default token proof uses quoted marker/token values,
  - `--exec-cmd` runs an arbitrary lab command and captures stdout/stderr plus return code metadata into the marker file,
  - raw `--cmd` remains available for low-level experiments.
- Implemented automatic cleanup support:
  - `--cleanup-delay` schedules delayed marker deletion,
  - `--cleanup-core` includes `/app/tmp/core` in delayed cleanup,
  - stale marker checks run before exploitation.
- Implemented negative-path mode:
  - `--negative-test bad-candidate --negative-test-only --expected-fail` sends an intentionally bad final candidate and records `negative_pass` when no proof appears.
- Implemented remote binary fingerprinting:
  - nginx and libc SHA-256 values are computed through ranged LFI reads,
  - ELF build IDs are parsed from remote binaries.
- Implemented best-effort multi-worker handling:
  - `--worker-mode correlate` can continue in multi-worker topologies,
  - strict core PID matching remains the primary evidence gate.
- Added `summarize_demo_artifacts.py` to summarize JSON artifacts.
- Added `known_layout_patterns.json` and `docs/KNOWN_LAYOUT_PATTERNS.md` as a seed reliability knowledge base. This is explicitly a hint source, not a replacement for live ASLR derivation.
- Validated v1.6 negative path on target VM `<target-host>`:
  - reset core PID `2850` matched the expected worker.
  - reset core contained `1010` URI-safe slots out of `10437`.
  - candidate sanity filter kept `160` candidates and dropped `6`.
  - bad candidate `0x303030303030` produced no marker proof.
  - artifact: `artifacts/demo_v1_6_20260515-053017.json`.
- Validated v1.6 arbitrary command execution and fingerprinting on target VM `<target-host>`:
  - nginx build ID `060e053ab1fa1a2876b7fe0ff4eff0cc777857b6`, SHA-256 `14bebe8937678598b8ebb8449f8c155478a4c49894c9467ce51d54a79352f08f`.
  - libc build ID `095c7ba148aeca81668091f718047078d57efddb`, SHA-256 `c53819710b163d3f1d2541778590d58d3ef31cb0ed75adcbe059faac68c1e72d`.
  - reset core PID `2913` matched the expected worker.
  - first final candidate `0x55a491955627` at body offset `80` executed `id`.
  - captured output: `uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)`.
  - delayed cleanup removed both the marker and `/app/tmp/core`; both returned HTTP `404` through LFI after the delay.
  - artifact: `artifacts/demo_v1_6_20260515-053037.json`.
- Current preferred recording command:

```bash
./demo_ctf_exploit_v1_6.py --host <target-host> --port 19321 --clear --require-reset-core --rounds 2 --exec-cmd id
```

### v1.7/v1.8 Demo Runner Pass

- Added `demo_ctf_exploit_v1_7.py` as a more autonomous recording runner:
  - `--cmd` is the default command-capture path,
  - reset-core use, binary fingerprinting, cleanup, strict preflight, and two exploit rounds are selected by default,
  - command output is printed as the final terminal section with wrapping/truncation.
- Validated v1.7 on target VM `<target-host>`:
  - OS `Ubuntu 22.04.3 LTS`, nginx `1.31.0`, PHP `8.1.2-1ubuntu2.23`, libc `2.35-0ubuntu3.13`,
  - nginx build ID `060e053ab1fa1a2876b7fe0ff4eff0cc777857b6`,
  - libc build ID `095c7ba148aeca81668091f718047078d57efddb`,
  - first final candidate `0x55e4210b2127` at body offset `1376` executed the requested command,
  - artifact: `artifacts/demo_v1_7_20260515-054057.json`.
- Added `demo_ctf_exploit_v1_8.py` as the current operator-facing runner:
  - compact output by default,
  - `-v` for detailed probe/candidate trace,
  - focused colored `--help` plus full `--advanced-help`,
  - CVE/bug/fixed-release context in help and start banner,
  - modular HTTP file-read adapter with a default query-param vector and a custom `--file-read-template`,
  - `--target-profile generic` for non-lab CTF apps where this fork's nginx config assertions should not apply.
- Smoke-tested the file-read adapter against `<target-host>`:
  - default query-param adapter read `randomize_va_space=2`,
  - template adapter `http://{host}:{port}/lfi.php?file={path_url}{range_query}` read `randomize_va_space=2`.
- Validated v1.8 compact mode on target VM:
  - command: `./demo_ctf_exploit_v1_8.py --host <target-host> --cmd 'id; uname -a; seq 1 20' --fast --artifact-dir artifacts`,
  - selected geometry `A=127`, `plus=962`,
  - fresh reset core produced `60` candidates before final filtering,
  - first winning address `0x55e4210b2127`, body offset `1376`,
  - artifact: `artifacts/demo_v1_8_20260515-055614.json`.
- Validated v1.8 template-backed mode end-to-end:
  - command used `--file-read-template 'http://{host}:{port}/lfi.php?file={path_url}{range_query}'`,
  - first winning address `0x55e4210b2127`, body offset `1376`,
  - captured `id` output as `uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)`,
  - artifact: `artifacts/demo_v1_8_20260515-055639.json`.
- Current preferred recording command:

```bash
./demo_ctf_exploit_v1_8.py --host <target-host> --port 19321 --cmd id --clear
```

### v1.9 Command Output Rendering

- Added `demo_ctf_exploit_v1_9.py`.
- v1.9 keeps the v1.8 compact/default behavior and modular file-read adapter, but changes the final command-output renderer:
  - no border,
  - no per-line `|` prefix,
  - no forced text wrapping,
  - final command output is plain terminal text in a high-contrast color when color is enabled.
- Updated v1.9 target parsing so `--host` accepts `HOST:PORT`; `--port` is still accepted as a fallback/override.
- Validated that `phpinfo()` is not required by running with `--phpinfo-path ''`:
  - the start banner reported `phpinfo disabled`,
  - PHP version/API fields reported `not learned`,
  - OS/nginx/libc/kernel fingerprints were still learned from file reads and headers,
  - exploit still won through the LFI/core-guided path.
- Validated command:

```bash
./demo_ctf_exploit_v1_9.py --host <target-host>:19321 --cmd 'ls -la /app/tmp' --fast --artifact-dir artifacts --phpinfo-path ''
```

- Observed:
  - selected geometry `A=127`, `plus=962`,
  - reset core produced `60` matched candidates before final filtering,
  - first winning address `0x55e4210b2127`, body offset `1376`,
  - artifact: `artifacts/demo_v1_9_20260515-060251.json`.
- Current preferred recording command:

```bash
./demo_ctf_exploit_v1_9.py --host <target-host>:19321 --cmd id --clear
```

- Validated `HOST:PORT` parsing in a live exploit run:

```bash
./demo_ctf_exploit_v1_9.py --host <target-host>:19321 --cmd id --fast --rounds 1 --artifact-dir artifacts --phpinfo-path ''
```

- Observed:
  - stage `[04]` is now `Remote command verification setup`,
  - first winning address `0x55e4210b2127`, body offset `1376`,
  - artifact: `artifacts/demo_v1_9_20260515-060834.json`.

### v2 Assessment-First Rifter

- Added `nginx_rifter.py` as the v2 entry point for real-world-oriented assessment.
- Default mode is non-exploitative:
  - HTTP and cleartext HTTP/2 probing,
  - modular HTTP file-read profiling,
  - small text, binary, ranged-read, `/proc/self/status`, and `/proc/self/maps` checks,
  - nginx worker discovery through pid files and `/proc`,
  - remote libc `system()` derivation,
  - nginx/libc SHA-256 and ELF build-ID fingerprinting,
  - nginx config discovery from master cmdline plus common paths,
  - vulnerable `rewrite` + `set` route candidate detection,
  - exploit-chain viability matrix.
- `--exploit --cmd ...` is explicit. Older v2 builds handed off to `demo_ctf_exploit_v1_9.py`; the current build integrates that path directly in `nginx_rifter.py`.
- Validated default assessment:

```bash
./nginx_rifter.py --target <target-host>:19321 --artifact-dir artifacts --no-color --output artifacts/nginx_rifter_20260515-v2-final.json
```

- Observed:
  - HTTP `200`, server `nginx/1.31.0`, HTTP/2 cleartext available,
  - file-read primitive supports small text, binary, ranged reads, `/proc/self/status`, and `/proc/self/maps`,
  - nginx worker maps readable, libc base and `system()` derived,
  - nginx build ID `060e053ab1fa1a2876b7fe0ff4eff0cc777857b6`,
  - libc build ID `095c7ba148aeca81668091f718047078d57efddb`,
  - config discovery found `/app/nginx-lfi.conf`,
  - vulnerable candidate: `location ~ ^/api/(.*)$`, `rewrite ^/api/(.*)$ /internal?migrated=true`, `set $original_endpoint PPPPPPPPPPP$1`,
  - verdict `ready-with-lab-like-core-leak`.
- Validated template-backed assessment:

```bash
./nginx_rifter.py --target <target-host>:19321 \
  --file-read-template 'http://{host}:{port}/lfi.php?file={path_url}{range_query}' \
  --artifact-dir artifacts --no-color --output artifacts/nginx_rifter_20260515-v2-template.json
```

- Validated explicit exploit mode:

```bash
./nginx_rifter.py --target <target-host>:19321 --artifact-dir artifacts --no-color --exploit --cmd id --fast --exploit-rounds 1 --phpinfo-path ''
```

- Historical v2 behavior wrote a rifter assessment artifact and a separate demo exploit artifact; current `nginx_rifter.py` writes exploit derivation and runtime state into the same selected artifact.

### v2.1 Self-Contained Rifter Refactor

- Refactored `nginx_rifter.py` so it no longer imports or shells out to prior PoC/demo scripts:
  - removed imports from `demo_ctf_exploit_v1_9.py`, `ctf_remote_exploit.py`, and `poc.py`,
  - inlined the HTTP file-read adapter, nginx worker discovery, ELF/libc symbol parsing, fingerprint helpers, HTTP/2 probe, spray/trigger helpers, and core slot/pool scanners,
  - replaced the previous `demo_ctf_exploit_v1_9.py` subprocess bridge with an integrated exploit path that reuses the same target adapter and artifact file.
- Kept default behavior assessment-first. `--exploit --cmd ...` is still explicit, and `--derive-only` now validates the integrated exploit discovery path without sending crash probes.
- Docker verification was used when the VM lab was unavailable:
  - assessment path passed against `127.0.0.1:19321`,
  - template-backed file-read path passed,
  - integrated `--derive-only` passed and recorded exploit derivation metadata in the artifact,
  - bounded integrated exploit smoke test generated a crash/core, parsed core program headers, and exercised slot/pool scanning.
- Docker realism note:
  - the Docker LFI topology models the common same-host nginx/PHP-FPM plus web-file-read scenario,
  - it is not being modified to fake the Vagrant proof conditions,
  - the successful ASLR-bypass chain still depends on a readable nginx worker crash core, which is not a default Ubuntu/nginx production assumption.

Validation commands:

```bash
python3 -m py_compile nginx_rifter.py

./nginx_rifter.py --target 127.0.0.1:19321 --no-color \
  --artifact-dir artifacts \
  --output artifacts/nginx_rifter_selfcontained_docker_assess.json

./nginx_rifter.py --target 127.0.0.1:19321 \
  --file-read-template 'http://{host}:{port}/lfi.php?file={path_url}{range_query}' \
  --no-color --artifact-dir artifacts \
  --output artifacts/nginx_rifter_selfcontained_docker_template.json

./nginx_rifter.py --target 127.0.0.1:19321 --exploit --derive-only \
  --cmd id --no-color --phpinfo-path '' \
  --artifact-dir artifacts \
  --output artifacts/nginx_rifter_selfcontained_docker_derive2.json
```

Bounded smoke command:

```bash
docker compose -f env/docker-compose.yml -f env/docker-compose.lfi.yml exec -T nginx rm -f /app/tmp/core

timeout 90 ./nginx_rifter.py --target 127.0.0.1:19321 \
  --exploit --cmd id --no-color --phpinfo-path '' \
  --artifact-dir artifacts \
  --output artifacts/nginx_rifter_selfcontained_docker_exploit_smoke.json \
  --exploit-rounds 1 --no-auto-calibrate --max-slot-hits 1 \
  --max-cleanup-pools 1 --max-core-hits 1 --core-delay 1 --cleanup-delay 0
```

Observed bounded smoke result:

```text
probe crash observed: True
core load segments: 37
slot hits: 0 URI-safe / 1 total
cleanup pools: 1
probe/corrupt pools: 1
matched candidates: 0
exhausted integrated exploit candidates without marker proof
```

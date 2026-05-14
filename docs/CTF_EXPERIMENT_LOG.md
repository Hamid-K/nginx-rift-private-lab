# Nginx Rift CTF Experiment Log

Last updated: 2026-05-15 01:16:56 CEST

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
- Explanation: Docker Desktop is running an amd64 container under emulation on an arm64 host. Do not over-interpret fixed-looking addresses from this lab host as normal Linux ASLR behavior.

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

- User asked whether switching to ARM would help, then suggested a real Ubuntu VM through Vagrant on the `Ultra` ESXi host.
- Decision: stay x86_64 and use Vagrant for the realism track.
- Rationale:
  - ARM64 removes Docker Desktop amd64 emulation artifacts but invalidates the original x86_64 PoC heap candidates and changes libc/codegen/layout.
  - A real x86_64 Ubuntu VM removes the Docker Desktop emulation caveat while preserving the architecture the PoC was tuned for.
- An ARM64 overlay briefly built during exploration, then the lab was returned to the x86_64 same-port CTF image and the ARM overlay was removed from the branch.

### Vagrant ESXi Attempt 1

- Added `Vagrantfile`, `vagrant/provision.sh`, and `docs/VAGRANT_ESXI.md`.
- Confirmed `root@ultra.home` SSH key authentication works.
- Confirmed `vagrant validate` succeeds when an ESXi password spec is syntactically available.
- Ran `vagrant up --provider=vmware_esxi`.
- Vagrant downloaded `generic/ubuntu2204` VMware box and started the ESXi build.
- `ovftool` prompted for an ESXi password despite SSH key auth; this is expected for this provider because `ovftool` does not use SSH keys.
- Killed the launch before any VM was created. `vagrant status` reports `not created`, and `vim-cmd vmsvc/getallvms` shows no `nginx-rift-lab` VM.
- Next VM launch requires `ESXI_PASSWORD_SPEC=env:ESXI_PASSWORD`, `ESXI_PASSWORD_SPEC=file:/path`, or an interactive `prompt:` run.

### Vagrant ESXi Launch And Manual Provision

- User clarified that the password prompt was intended for `ovftool` operations, not SSH to `Ultra`.
- Kept SSH to `root@ultra.home` key-based and used a hidden macOS prompt only to populate `ESXI_PASSWORD` for the Vagrant/`ovftool` path.
- Launched the VM through `vagrant up --provider=vmware_esxi`.
- ESXi created VMID `24` with guest IP `192.168.1.205`.
- Vagrant provider guest communication did not complete cleanly, but direct Vagrant-key SSH to `vagrant@192.168.1.205` worked.
- Synced the repo manually to `/vagrant` and ran `sudo bash /vagrant/vagrant/provision.sh`.
- Provisioning installed/build the nginx target, PHP-FPM, same-port LFI/phpinfo routes, and systemd services.
- Smoke test passed:
  - `http://192.168.1.205:19321/` returned `ok`.
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
- Ran `./ctf_remote_exploit.py --host 192.168.1.205 --port 19321 --core-guided --tries-per-candidate 2 --proof-delay 0.25 --verbose`.
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
- Correction: no second clone VM has been created yet. All ESXi VM tests so far used the single VM at `192.168.1.205`. A separate clone/twin VM must be created before using live debugger output as non-target oracle data.

## 2026-05-15

### Debug Twin VM

- User fixed the ESXi NIC/port-group issue.
- Created/provisioned a separate debug/twin VM at `192.168.1.89:19321` for live-debugging and layout experiments.
- Kept the original target VM at `192.168.1.205:19321` as the CTF target.
- Installed `gdb` and set `kernel.yama.ptrace_scope=0` only on the debug/twin VM.
- Added `debug/gdb_trace_request.gdb` to trace request allocations, rewrite copy positions, cleanup registration, request freeing, and pool destruction.
- Rule clarification: gdb and direct SSH-derived offsets from `192.168.1.89` are allowed for source/layout understanding, but target exploitation against `192.168.1.205` must still use HTTP/LFI primitives or version/distro facts.

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
  - command: `./ctf_remote_exploit.py --host 192.168.1.89 --port 19321 --core-guided --target-len 2 --h2-victim --a-count 127 --plus-count 962 --tries-per-candidate 1 --max-core-hits 100 --proof-delay 0.25 --core-delay 2 --verbose`
  - result: recovered one corrupted/probe pool and matched safe h2-body slots in the same 64 KiB window.
  - first final candidate executed the marker command and was verified through LFI.
- Target VM win:
  - deployed the updated branch lab config to `192.168.1.205` as lab setup.
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

# Nginx Rift CTF Experiment Log

Last updated: 2026-05-14 23:14:41 CEST

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

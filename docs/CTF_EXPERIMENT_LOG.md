# Nginx Rift CTF Experiment Log

Last updated: 2026-05-14 23:06:13 CEST

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

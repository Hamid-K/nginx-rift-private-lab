# Nginx Rift CTF Experiment Log

Last updated: 2026-05-14 22:59:05 CEST

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
- Next step is to commit this checkpoint before continuing core-guided testing.

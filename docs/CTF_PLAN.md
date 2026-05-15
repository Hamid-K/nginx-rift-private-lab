# Nginx Rift CTF Plan

Last updated: 2026-05-15 06:37:15 CEST

## Goal

Determine whether the Nginx Rift PoC can be made into a remote-only exploit chain that calculates the required runtime addresses through realistic web primitives instead of hardcoded local offsets.

The authoritative CTF topology is same-port:

- Vulnerable nginx routes: `http://127.0.0.1:19321/api/...` and `/spray`
- PHP local-file-read vector: `http://127.0.0.1:19321/lfi.php?file=...`
- PHP info disclosure vector: `http://127.0.0.1:19321/phpinfo.php`
- PHP-FPM and nginx workers run as the same non-root UID so the PHP LFI can attempt to read nginx worker `/proc` files.

The side-port PHP variant in `env/docker-compose.ctf.yml` is diagnostic only. It is useful for isolating address-derivation behavior, but it is not the primary realism target.

Native x86_64 VM is the preferred ASLR-realism track:

- Use Vagrant to run the x86_64 lab on a real Ubuntu VM on the `Ultra` ESXi host.
- This removes Docker Desktop amd64 emulation effects on this arm64 host while preserving the published PoC architecture.
- Docker remains useful for fast local iteration; Vagrant is for validating ASLR/layout conclusions.

## Rules

- Exploit inputs must be learned through HTTP-accessible primitives.
- Do not use `docker exec`, local debuggers, or container filesystem reads to supply exploit offsets.
- Docker introspection is allowed only for lab control, sanity checks, and post-test verification while developing.
- A run only counts as a CTF win when the exploit creates a marker and the marker is verified through the PHP LFI endpoint.

## Current Checklist

- [x] Create branch `ctf-remote-aslr-lfi`.
- [x] Preserve the original PoC lab path.
- [x] Add explicit address arguments to `poc.py` for controlled baseline tests.
- [x] Add same-port PHP LFI/phpinfo lab overlay.
- [x] Confirm same-UID PHP LFI can read nginx worker maps.
- [x] Add `ctf_remote_exploit.py` to derive worker PID, nginx mapping, libc base, and `system()` through HTTP.
- [x] Re-baseline original PoC and verify real command execution, not just worker crash.
- [x] Add ranged LFI reads for large local files.
- [x] Run first same-port core-guided CTF mode.
- [x] Inspect PoC mechanics to determine whether the recovered sprayed-body address is the correct overwrite target or only an input to another pointer calculation.
- [x] Test worker reset after LFI core read to avoid final attempts running on a heap perturbed by core extraction.
- [x] Inspect crash core for the overwritten victim pool and cleanup pointer bytes.
- [x] Add Vagrant x86_64 Ubuntu track for ASLR-realism experiments.
- [x] Launch ESXi VM using an `ovftool`-usable ESXi password source.
- [x] Smoke-test same-port LFI/phpinfo on the x86_64 Ubuntu VM.
- [x] Configure the VM to produce local `/app/tmp/core` files for the core-guided lab path.
- [x] Patch core-guided mode so it can generate a probe core even when ASLR yields no legacy URI-safe candidates.
- [x] Add derive-only mode for non-destructive remote ASLR layout sampling.
- [x] Sample fresh VM nginx master layouts for URI-safe candidate availability.
- [x] Decide whether core dumps are in-scope as a realistic LFI-assisted primitive or only a lab amplifier.
- [x] If core-guided mode succeeds in a later iteration, repeat from a clean service restart to prove reproducibility.
- [x] Achieve marker-verified CTF win against the debug clone with HTTP/LFI-only exploit inputs.
- [x] Achieve marker-verified CTF win against the target VM with HTTP/LFI-only exploit inputs.
- [x] Add separate v1.1 demo runner with preflight, artifacts, core PID freshness, and calibration.
- [x] Add separate v1.2 demo runner that requires and uses reset-core candidates before final exploitation.
- [x] Add separate v1.3 demo runner with strict core PID checks and layout drift detection.
- [x] Add separate v1.4 demo runner with strict preflight and final candidate sanity filtering.
- [x] Add separate v1.5 demo runner with bounded multi-round campaign mode.
- [x] Add separate v1.6 demo runner with cleanup, negative-path mode, remote binary fingerprinting, arbitrary command capture, and multi-worker correlation option.
- [x] Add separate v1.7/v1.8 demo runners with autonomous defaults, compact output, verbose trace mode, final command-output rendering, CVE-aware banner/help, and modular file-read vector support.
- [x] Add separate v1.9 demo runner with plain final command output and verified no-phpinfo mode.
- [x] Update v1.9 target parsing so `--host` accepts `HOST:PORT` and `--port` can be omitted.
- [x] Add `nginx_rifter.py` v2 assessment-first tool with modular file-read profiling, nginx config discovery, viability matrix, and explicit exploit handoff.
- [x] Add demo artifact summarizer.
- [x] Add seed known-pattern reliability knowledge base.
- [x] If core-guided mode fails, document the remaining missing primitive precisely.
- [x] Commit first stable checkpoint before deeper changes: `12956c1`.

## Next Actions

1. Use `nginx_rifter.py --target <target>:<port> --file-read-template '<template>'` as the default assessment entry point.
2. Use `demo_ctf_exploit_v1_9.py --host 192.168.1.205:19321 --cmd id --clear` for the recorded exploit-only terminal demo.
3. Preserve `nginx_rifter.py`, updated docs, and v2 artifacts in version control.
4. Summarize the research answer: this is exploitable in the updated lab with ASLR enabled when a strong local-file-read primitive can also read crash cores; phpinfo or `/proc/<pid>/maps` alone is not enough for this exact chain.

Current status: won in the updated HTTP/2 same-port lab. A debug/twin VM exists at `192.168.1.89`, separate from the target VM at `192.168.1.205`. The final target win used no target-side debugger or SSH-derived offsets.

## Current Strategy

The winning strategy is a core-guided partial overwrite against an HTTP/2 connection-pool cleanup:

1. Enable HTTP/2 on the same nginx listener so the same worker/port handles the leak surface, vulnerable route, and h2 victim.
2. Use an unknown HTTP/2 extension frame as the victim body carrier, leaving binary fake-cleanup structures in the h2 connection pool.
3. Use an HTTP/LFI-readable crash core only as a CTF leak primitive to recover h2-body slots and the corrupted connection pool's preserved high bytes.
4. Filter 2-byte-safe slot candidates to those matching the corrupted cleanup pointer high-byte window.
5. Retry with the fake cleanup structure at the recovered h2-body offset.

This still does not count as a realistic default-production exploit path unless core dumps are enabled and readable. It is, however, a legitimate lab answer to whether a strong PHP local-file-read primitive plus a common web behavior can remove the current ASLR blocker without hardcoding target offsets.

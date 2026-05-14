# Nginx Rift CTF Plan

Last updated: 2026-05-15 00:01:04 CEST

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
- [ ] Inspect crash core for the overwritten victim pool and cleanup pointer bytes.
- [x] Add Vagrant x86_64 Ubuntu track for ASLR-realism experiments.
- [x] Launch ESXi VM using an `ovftool`-usable ESXi password source.
- [x] Smoke-test same-port LFI/phpinfo on the x86_64 Ubuntu VM.
- [x] Configure the VM to produce local `/app/tmp/core` files for the core-guided lab path.
- [x] Patch core-guided mode so it can generate a probe core even when ASLR yields no legacy URI-safe candidates.
- [x] Add derive-only mode for non-destructive remote ASLR layout sampling.
- [x] Sample fresh VM nginx master layouts for URI-safe candidate availability.
- [ ] Decide whether core dumps are in-scope as a realistic LFI-assisted primitive or only a lab amplifier.
- [ ] If core-guided mode succeeds in a later iteration, repeat from a clean container to prove reproducibility.
- [x] If core-guided mode fails, document the remaining missing primitive precisely.
- [x] Commit first stable checkpoint before deeper changes: `12956c1`.

## Next Actions

1. Test partial overwrite against a victim request whose request pool has a real non-NULL `pool->cleanup` pointer.
2. Add a realistic victim route that forces request-body temp-file buffering, because nginx registers a pool cleanup for temp files.
3. Use an LFI-readable crash core to recover the original cleanup pointer high bytes and sprayed fake-structure locations.
4. Try 2-4 byte cleanup-pointer overwrites so unsafe high bytes are inherited from nginx's real cleanup pointer rather than sent through the URI.
5. If partial overwrite fails, fall back to twin-VM tuning and deeper crash-core parsing of victim `ngx_pool_t` structures.

Current status: initial partial-overwrite geometry is instrumented, but not won. Cores show the upload victim does create a non-NULL cleanup pointer, while the overflow marker remains short of the cleanup field before nginx changes allocation path. Only one ESXi VM exists right now, so any live debugger work still needs a separate clone/twin VM before it can count as non-target oracle work.

## Current Strategy

The best candidate is a hybrid of options 2 and 4 from the prompt: use a common web behavior, large upload/request-body buffering, to create a legitimate cleanup entry in the victim request pool, then exploit the overflow as a partial pointer overwrite. This may bypass the current full six-byte URI-safe address blocker because bytes above the overwrite remain from nginx's real cleanup pointer.

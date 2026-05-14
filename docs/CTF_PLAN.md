# Nginx Rift CTF Plan

Last updated: 2026-05-14 23:06:13 CEST

## Goal

Determine whether the Nginx Rift PoC can be made into a remote-only exploit chain that calculates the required runtime addresses through realistic web primitives instead of hardcoded local offsets.

The authoritative CTF topology is same-port:

- Vulnerable nginx routes: `http://127.0.0.1:19321/api/...` and `/spray`
- PHP local-file-read vector: `http://127.0.0.1:19321/lfi.php?file=...`
- PHP info disclosure vector: `http://127.0.0.1:19321/phpinfo.php`
- PHP-FPM and nginx workers run as the same non-root UID so the PHP LFI can attempt to read nginx worker `/proc` files.

The side-port PHP variant in `env/docker-compose.ctf.yml` is diagnostic only. It is useful for isolating address-derivation behavior, but it is not the primary realism target.

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
- [ ] Decide whether core dumps are in-scope as a realistic LFI-assisted primitive or only a lab amplifier.
- [ ] If core-guided mode succeeds in a later iteration, repeat from a clean container to prove reproducibility.
- [x] If core-guided mode fails, document the remaining missing primitive precisely.
- [x] Commit first stable checkpoint before deeper changes: `12956c1`.

## Next Actions

1. Compare core-derived fake-structure addresses against the original preread candidate set and inspect the crash core for overwritten victim pool evidence.
2. Determine whether the six-byte target lands at the intended cleanup pointer or corrupts an earlier/later field in same-port mode.
3. Commit the next stable checkpoint after this result is documented.

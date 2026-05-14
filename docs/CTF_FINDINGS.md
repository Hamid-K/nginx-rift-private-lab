# Nginx Rift CTF Findings

Last updated: 2026-05-14 22:59:05 CEST

## Working Findings

### PHP LFI Can Leak The Right Class Of ASLR Data If It Can Read The Nginx Worker Proc Files

In the same-UID lab, PHP LFI can read `/proc/<nginx-worker>/maps`. That is enough to recover:

- the nginx binary mapping layout,
- the writable nginx image mapping used by the PoC as `heap_base`,
- libc base,
- libc path.

Reading the libc file through LFI is enough to parse the ELF dynamic symbol table and compute `system()` without local access to the target filesystem.

### `/proc/self/maps` Is Not The Nginx Worker

For PHP behind nginx, `/proc/self/maps` from PHP is the PHP-FPM worker process, not nginx. It does not directly reveal nginx worker mappings.

The useful primitive is reading `/proc/<nginx-worker-pid>/maps`, which requires:

- discovering or guessing the worker PID,
- same UID or permissive `/proc` policy,
- no hardening that hides process details.

The lab discovers the worker PID through LFI-readable nginx pid file and `/proc/<master>/task/<master>/children`.

### Root Master Maps Are Not Readable In The Same-UID PHP Scenario

The nginx master runs as root. The PHP process running as `nobody` cannot read the root master process maps. The exploitable target is the non-root worker process.

### phpinfo Helps, But It Is Not Enough Alone

phpinfo is useful for deployment hints such as SAPI, filesystem paths, loaded configuration, and environment. It does not itself reveal nginx worker process maps or the nginx worker heap/request layout.

phpinfo becomes much more useful when combined with an LFI/local-file-read primitive that can access the relevant `/proc/<pid>` files.

### The Current Missing Piece Is Not libc ASLR

The remote driver already derives the nginx worker maps, libc base, libc file, and `system()` address over HTTP. In the same-port and diagnostic modes, failures so far are worker crashes without command-execution proof.

That points to the request/heap landing problem: the original PoC uses hardcoded preread/request-pool layout candidates. Adding PHP/FastCGI routes and same-port leak traffic changes or perturbs the vulnerable worker layout enough that those candidates are no longer sufficient.

### Core Dumps May Turn LFI Into A Stronger Primitive

The lab currently produces `/app/tmp/core` after nginx worker crashes. Because the core is local-file-readable, an attacker with LFI may be able to:

1. trigger a controlled crash containing a unique sprayed token,
2. read the core dump through LFI,
3. locate the sprayed fake structure in memory,
4. retry with the computed cleanup pointer.

This is a plausible lab CTF path but a realism caveat. Many production systems disable core dumps, write them outside web-readable paths, or restrict access through service managers and kernel settings.

### Platform Caveat

The host is arm64 while the target container is `linux/amd64`. Docker Desktop emulation appears to make addresses stable even with `randomize_va_space=2` and normal process personality. This is acceptable for developing the address-derivation logic, but it is not a clean measurement of real x86_64 Linux ASLR entropy.

## Current Research Answer Draft

Under the current constraints, LFI/phpinfo-style primitives are enough to remove the libc/PIE ASLR uncertainty if they can read the nginx worker's `/proc/<pid>/maps` and the mapped libc file.

They are not, by themselves, enough to make the existing PoC reliably exploit same-port nginx remotely. The remaining hard requirement is a way to recover or stabilize the target request-pool/sprayed-body address. The next experiment tests whether an LFI-readable core dump supplies that missing primitive.

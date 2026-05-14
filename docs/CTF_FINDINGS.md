# Nginx Rift CTF Findings

Last updated: 2026-05-14 23:33:29 CEST

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

### Arbitrary File Download Is Stronger Than Classic LFI, But Does Not Remove Every Blocker

The current lab LFI is already closer to arbitrary local file download than to a weak include-only bug: it can read full files, supports ranged reads, and has downloaded `/proc/<nginx-worker>/maps`, the target libc, and LFI-readable core files.

That means the current blocker is not file-read bandwidth. A full arbitrary file-read/download primitive improves reliability for:

- downloading the exact nginx binary and shared libraries,
- reading nginx config, pid files, logs, and environment,
- reading `/proc/<nginx-worker>/maps` when permissions allow it,
- reading crash cores if the service writes them somewhere readable.

It still does not automatically provide live nginx heap contents. `/proc/<pid>/maps` gives memory ranges and mapped-file bases, not allocator state or object contents. `/proc/<pid>/mem` is normally protected by ptrace-style permission checks and is not equivalent to ordinary file download. Without a readable core, debugger access, or another memory disclosure primitive, arbitrary local file read can solve ASLR base discovery but not necessarily the exact cleanup-object/heap-placement problem.

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

First same-port core-guided result: the driver successfully located two sprayed-body addresses in the core, but using them directly as overwrite targets did not execute the marker command. The remaining unknown is the exact pointer relationship needed by the corrupted nginx cleanup object.

PoC mechanics review confirmed that a fake-structure address is the correct value to write into the victim pool `cleanup` pointer, while the fake structure's `data` field should point 24 bytes later at the command string. The next hypothesis is not pointer type, but worker state: large same-port LFI reads may perturb the fresh worker before the final retry.

Worker-reset testing did not change the outcome. The stronger current hypothesis is that same-port mode changes where the overflow lands relative to the victim pool, so a valid fake cleanup address still does not become a valid `pool->cleanup` pointer at the exact destruction point.

### Platform Caveat

The host is arm64 while the target container is `linux/amd64`. Docker Desktop emulation appears to make addresses stable even with `randomize_va_space=2` and normal process personality. This is acceptable for developing the address-derivation logic, but it is not a clean measurement of real x86_64 Linux ASLR entropy.

The better realism track is a real x86_64 Ubuntu VM via Vagrant, not ARM64. That removes Docker Desktop/Rosetta effects while preserving the architecture and libc family the published PoC targets.

For the installed `vagrant-vmware-esxi` provider, SSH key auth is not enough for the full VM creation path. The provider's SSH operations can use keys, but `ovftool` still needs ESXi password authentication for uploading/importing a VM.

### VM ASLR Result So Far

The x86_64 Ubuntu VM removes the Docker Desktop emulation caveat. In the VM:

- `uname -m` is `x86_64`.
- `/proc/sys/kernel/randomize_va_space` is `2`.
- same-port PHP-FPM still runs as UID `65534`.
- LFI can read the same-UID nginx worker maps and the mapped libc file.
- The driver computes `system()` from the target libc through LFI, not from local files.

The first VM ASLR layout produced zero URI-safe legacy candidate addresses. After enabling local core dumps, the core-guided probe recovered 20 sprayed fake-structure addresses from `/app/tmp/core`, but all 20 were URI-unsafe for the six-byte overwrite path. That is a stronger and more realistic limitation than the Docker result, where emulation-stable addresses happened to include URI-safe candidates.

Current implication: for the VM path, the blocker is not merely finding the sprayed structure. The exploit also needs a way to make or select a sprayed fake-structure address whose low six bytes survive the nginx URI processing constraint. Worker crashes alone do not change the master process layout, so replacement workers are expected to inherit the same broad ASLR layout.

Fresh-master sampling strengthens this: 12 VM nginx master restarts produced 12 layouts with zero URI-safe legacy cleanup candidates. This is lab-control sampling, not an attacker primitive, but it shows that even with full remote derivation of PIE/libc bases, the PoC's address-byte constraint is a major reliability barrier on normal x86_64 ASLR.

## Current Research Answer Draft

Under the current constraints, LFI/phpinfo-style primitives are enough to remove the libc/PIE ASLR uncertainty if they can read the nginx worker's `/proc/<pid>/maps` and the mapped libc file.

They are not, by themselves, enough to make the existing PoC reliably exploit same-port nginx remotely. The remaining hard requirement is a way to recover or stabilize the exact cleanup-object target, not merely one copy of the sprayed fake structure. The first core-guided experiment recovered sprayed body addresses but still did not produce marker proof.

On the real x86_64 VM, an additional constraint appeared: even when core-guided recovery finds the sprayed fake structures, the resulting addresses may all be URI-unsafe. That makes the current chain unreliable under normal ASLR unless another primitive can influence heap placement, select a URI-safe target, or avoid the six-byte URI-safety constraint.

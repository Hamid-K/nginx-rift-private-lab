# Coreless ASLR Bypass Findings

This file records candidate vectors and conclusions for replacing the readable crash-core primitive.

## Summary

Status: coreless replacement proven in Docker with a standard procfs memory-read primitive.

The successful replacement is not a new NGINX response leak. It is a same-UID local-file-read escalation into `/proc/<nginx-worker>/mem`, verified through the HTTP LFI endpoint. When readable, `/proc/<worker>/mem` is stronger than a crash core because it exposes live worker memory without requiring non-standard core-dump policy.

## Candidate Matrix

| ID | Class | Candidate | Default? | Leak value | Status |
| --- | --- | --- | --- | --- | --- |
| S1 | Source audit | Direct NGINX response leak in rewrite/HTTP2/range/body/upstream/error paths | No credible candidate found | None | Failed |
| B1 | Brute force | Static known-offset candidates, 6-byte overwrite | Uses known lab geometry only | 5 candidates in Docker | Failed |
| B2 | Brute force | Bounded live-memory candidate campaign | Requires proc-mem disclosure | 115 full-address candidates; candidate 1 won | Passed |
| L1 | Standard LFI | `/proc/<nginx-worker>/maps` and libc binary | Same UID and procfs ptrace access | PIE/libc bases and `system()` | Passed, partial |
| L2 | Standard LFI | `/proc/<nginx-worker>/mem` at mapped offsets | Same UID, large-offset LFI, ptrace policy permits read | Live heap/body/pool contents | Passed |

## Proven Coreless Chain

1. Use LFI to read `/proc/self/status` and identify the web-app UID.
2. Use LFI to read the nginx pid file and `/proc/<master>/task/<master>/children`.
3. Use LFI to read `/proc/<worker>/maps` for a same-UID nginx worker.
4. Derive nginx/libc bases and `system()` from maps plus the LFI-read libc ELF.
5. Send the normal NGINX Rift probe body while keeping the worker state live.
6. Use LFI to read `/proc/<worker>/mem` at writable mapped ranges.
7. Scan live memory for nonce-marked fake-cleanup slots.
8. Use a full 6-byte URI-safe overwrite to point cleanup directly at a recovered slot.
9. Try bounded final candidates.

Successful Docker proof:

```text
live mem slots: 115 safe / 2485 total
live mem pools: cleanup=14 probe=0 overwritten=0 matches=115
final candidate 1: addr=0x5555556b2127 slot=3072
coreless win via /proc/<pid>/mem candidate 1
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
```

Artifacts:

- transcript: `artifacts/coreless_proc_mem_win_20260518.txt`
- asciicast: `artifacts/coreless_proc_mem_win_20260518.cast`
- gif: `artifacts/coreless_proc_mem_win_20260518.gif`

Official nginx Docker permission check:

```text
nginx_version=nginx version: nginx/1.30.1
os_release=Debian GNU/Linux 13
worker_uid=101
same_uid_mem_read=n=8 hex=7f454c4602010100
different_uid_maps=Permission denied
different_uid_open=Permission denied
```

Artifact: `artifacts/official_nginx_proc_mem_verify_20260518.txt`

## Realism

This is substantially more realistic than readable crash cores in same-UID container deployments, but it is still permission-dependent.

- Same UID is common for nginx plus PHP-FPM on Ubuntu (`www-data`) and common for apps deliberately colocated with official nginx images if the vulnerable app runs as the nginx worker user.
- `/proc/<pid>/maps`, `/proc/<pid>/auxv`, and `/proc/<pid>/stat` protected fields are commonly readable for same-UID processes when procfs/Yama policy allows ptrace-style access.
- `/proc/<pid>/mem` is ptrace-gated and must be verified on the target class. It worked in the Docker lab and in same-UID checks against the standard nginx Docker image model when reading mapped offsets.
- `/proc/<pid>/mem` requires the LFI primitive to support large 64-bit offsets or an equivalent range/read API.
- Different-UID app processes should fail against nginx worker maps/mem under default procfs protections.

## Source Audit Conclusion

The NGINX source audit did not find a remotely observable direct memory leak in the reviewed areas. The reviewed modules generally emit exact input/upstream/file bytes or static responses. Pointer-bearing debug logs exist, but `--with-debug` and debug `error_log` are non-default and are not counted.

## Non-Goals

- Do not count readable crash cores as success.
- Do not count target-side debugger or shell data as exploit oracle data.
- Do not count hardcoded ASLR bases as success.

# NGINX Rift

RCE Proof of concept for **CVE-2026-42945**, a critical heap buffer overflow in NGINX's `ngx_http_rewrite_module` introduced in 2008. The bug enables unauthenticated remote code execution against servers using `rewrite` and `set` directives.

This vulnerability — along with three other memory corruption issues (CVE-2026-42946, CVE-2026-40701, CVE-2026-42934) — was autonomously discovered by [depthfirst](https://depthfirst.com)'s security analysis system after a single click of onboarding the NGINX source.

> Want to find issues like this in your own code? Try the same system at **<https://depthfirst.com/open-defense>**.

## The Bug (TL;DR)

NGINX's script engine uses a two-pass process: first compute the required buffer size, then copy data in. The `is_args` flag is set on the main engine when a `rewrite` replacement contains `?`, but the length-calculation pass runs on a freshly zeroed sub-engine. So:

- **Length pass** sees `is_args = 0` → returns raw capture length.
- **Copy pass** sees `is_args = 1` → calls `ngx_escape_uri` with `NGX_ESCAPE_ARGS`, expanding each escapable byte to 3 bytes.

The copy overflows the undersized heap buffer with attacker-controlled URI data. Exploitation uses cross-request heap feng shui to corrupt an adjacent `ngx_pool_t`'s `cleanup` pointer (sprayed via POST bodies, since URI bytes can't contain null bytes), redirecting it to a fake `ngx_pool_cleanup_s` invoking `system()` on pool destruction.

Read more about this bug in our [technical write-up](https://depthfirst.com/research/nginx-rift-achieving-nginx-rce-via-an-18-year-old-vulnerability).

## Affected & Fixed Versions

| Product | Affected | Fixed in |
| --- | --- | --- |
| NGINX Open Source | 0.6.27 – 1.30.0 | 1.31.0, 1.30.1 |
| NGINX Plus | R32 – R36 | R36 P4, R35 P2, R32 P6 |

Full vendor advisory: <https://my.f5.com/manage/s/article/K000160932>

## Private Research Fork: ASLR-Enabled Remote Lab Chain

![ASLR-enabled remote exploit demo](nginx-aslr-demo.gif)

This fork keeps the original disclosure PoC intact, but adds a second research track focused on a more realistic question:

> Can the bug be exploited against a real x86_64 Linux VM with ASLR enabled, without relying on hardcoded Docker/lab offsets?

The answer in this lab is **yes, with important constraints**. The working chain does not disable ASLR and does not use the original hardcoded heap/libc addresses. Instead, it derives runtime state through same-port HTTP-accessible primitives and uses a core-guided partial overwrite to select the correct heap target for the final attempt.

The winning topology is intentionally same-port:

- vulnerable route: `/api/...`
- PHP local-file-read route: `/lfi.php?file=...`
- phpinfo hint route: `/phpinfo.php`
- HTTP/2 victim connection: same nginx listener and worker
- proof verification: marker file read back through the PHP LFI endpoint

The remote driver performs the following high-level steps:

1. Uses PHP LFI to read PHP identity, nginx pid files, nginx worker `/proc/<pid>/maps`, and the mapped libc file.
2. Parses the target libc over LFI to compute the absolute `system()` address for that worker.
3. Uses a URI-safe probe overwrite to generate an nginx worker core file.
4. Reads the core file through LFI and locates sprayed fake-cleanup slots.
5. Uses an HTTP/2 connection-pool cleanup record as the partial-overwrite target.
6. Filters candidate fake structures to the same preserved high-byte window as the corrupted cleanup pointer.
7. Retries once with a two-byte cleanup-pointer partial overwrite and verifies command execution through LFI.

This is not the same as the original deterministic Docker demo. The real x86_64 VM path leaves normal Linux ASLR enabled and recomputes process-specific addresses on each run. The exploit was validated against the Vagrant/ESXi Ubuntu lab after clean service restarts.

### Scope And Caveats

This fork is a controlled research lab. The ASLR-enabled chain relies on strong conditions that are not default assumptions for production deployments:

- PHP must expose a useful local-file-read primitive.
- PHP must be able to read same-UID nginx worker `/proc/<pid>/maps`.
- The lab enables local worker core dumps and leaves `/app/tmp/core` readable through the LFI primitive.
- HTTP/2 is enabled on the same nginx listener to provide the connection-pool cleanup target used by the final chain.

`phpinfo()` and `/proc/<pid>/maps` are enough to recover PIE/libc base addresses, but they are not enough by themselves to recover the exact heap object/window needed for this exploit. In this fork, the readable crash core is the extra memory disclosure that makes the final target selection reliable.

## Usage

Tested on Ubuntu 24.04.3 LTS.

Original ASLR-disabled Docker reproduction:

1. `./setup.sh` — build the container.
2. `docker compose -f env/docker-compose.yml up` — start the vulnerable NGINX server.
3. `python3 poc.py --shell` — pop a shell.

For the local Docker reproduction flow, see [LAB.md](LAB.md).

ASLR-enabled VM research chain:

```bash
./ctf_remote_exploit.py --host 192.168.1.205 --port 19321 \
  --core-guided --target-len 2 --h2-victim \
  --a-count 127 --plus-count 962 \
  --tries-per-candidate 1 --max-core-hits 100
```

Recording-friendly terminal demo:

```bash
./demo_ctf_exploit_v1_9.py --host 192.168.1.205:19321 --cmd id --clear
```

`demo_ctf_exploit_v1_9.py` is the current operator-facing runner. By default it uses the best-tested lab path, keeps console output to key stages and evidence, prints detailed target fingerprints, and leaves captured command output as the final terminal block. Pass `-v` for probe/candidate-level trace output. The final command output is printed as plain terminal text, without borders or per-line prefixes.

The default file-read primitive is this fork's PHP route:

```text
/lfi.php?file=<path>&offset=<n>&length=<n>
```

For a different known-vulnerable CTF app or testing platform, the file-read vector is modular:

```bash
./demo_ctf_exploit_v1_9.py --host 192.168.1.205:19321 --cmd id \
  --target-profile generic \
  --file-read-template 'http://{host}:{port}/download?path={path_url}{range_query}'
```

The template supports `{host}`, `{port}`, `{path_url}`, `{offset}`, `{length}`, and `{range_query}`. The generic profile skips this fork's lab-specific nginx config assertions, but the exploit still needs the same underlying capabilities: readable nginx worker `/proc` maps, readable libc, readable crash core, and a compatible vulnerable nginx/HTTP/2 layout. `phpinfo()` is optional; use `--phpinfo-path ''` to disable it.

Additional lab notes and run logs are under `docs/`, especially:

- `docs/CTF_PLAN.md`
- `docs/CTF_FINDINGS.md`
- `docs/CTF_TESTS.md`
- `docs/CTF_EXPERIMENT_LOG.md`
- `docs/DEMO_POC_IMPROVEMENTS.md`
- `docs/KNOWN_LAYOUT_PATTERNS.md`
- `docs/VAGRANT_ESXI.md`

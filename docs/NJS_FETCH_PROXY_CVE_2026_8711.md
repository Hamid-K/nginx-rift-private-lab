# NGINX JavaScript Fetch Proxy Vulnerability Track

Started: 2026-05-20
Scope: separate from CVE-2026-42945/Rift and separate from the `nginx/1.31.1` default-module video hunt.

## Public Signal

- CVE: `CVE-2026-8711`.
- Component: NGINX JavaScript (`njs`) HTTP/stream modules.
- Required pattern: `js_fetch_proxy` contains at least one client-controlled NGINX variable, and a handler invokes `ngx.fetch()`.
- Public description: heap buffer overflow in the NGINX worker process, causing worker restart; code execution is discussed for systems without ASLR.

## Source Finding

Local source: `/tmp/nginx-njs-src`.

Upstream fix commit:

- `2bf4601a94c2a22b715d74e6d92dedb1850d56d3`
- Title: `Fetch: fixed heap buffer overflow in proxy URL credentials.`
- Released in tag `0.9.9`.
- Introduced by `dea8318` / njs `0.9.4` according to the commit message.

Root cause from source:

- `ngx_js_parse_proxy_url()` decoded proxy URL username and password into fixed 128-byte buffers.
- The encoded input length was bounded by the URL length, not 128 bytes.
- `ngx_unescape_uri()` can write one output byte per input byte, so a raw credential longer than 128 bytes overflows before the post-decode length check.
- The fix allocates decoded username/password buffers using `user_len` and `pass_len` instead of `128`.

Relevant files:

- `/tmp/nginx-njs-src/nginx/ngx_js.c`
- `/tmp/nginx-njs-src/nginx/ngx_http_js_module.c`
- `/tmp/nginx-njs-src/nginx/ngx_stream_js_module.c`

## Fit To Screenshot

The XorNinja screenshot appears consistent with a separate NGINX/njs bug family, not Rift:

- Target is AArch64 Ubuntu 25.10.
- Exploit output prints `libc_leak`, `heap_leak`, `system`, and `libc_delta`.
- The payload obtains a root shell inside the container.
- Public CVE timing and source patch align with a fresh NGINX JavaScript heap overflow.

This is still an inference. The screenshot alone does not prove the exact bug or module.

## Next Lab Plan

1. Build a dedicated Docker lab with NGINX + njs `0.9.8` or the parent of `2bf4601a`.
2. Configure a deliberately vulnerable `js_fetch_proxy` using a client-controlled variable, for example a request header.
3. Add a minimal `js_content` handler that calls `ngx.fetch()`.
4. First reproduce only worker crash/ASAN evidence with oversized proxy credentials.
5. Compare patched `0.9.9` behavior under the same request.

Constraints:

- Keep this lane separate from the Rift PoC and the `nginx/1.31.1` default-module hunt.
- Do not weaken ASLR or kernel ptrace policy for any exploitability claim.
- Record milestone runs with asciinema and GIF once a live lab is in place.

## 2026-05-20 Docker ASAN Reproduction

Branch: `research/njs-fetch-proxy-cve-2026-8711`.

Lab files:

- `env/Dockerfile.njs-fetch-proxy`
- `env/nginx-njs-fetch-proxy.conf`
- `env/njs-fetch-proxy.js`
- `env/entrypoint-njs-fetch-proxy.sh`
- `tools/njs_fetch_proxy_probe.py`
- `tools/njs_fetch_proxy_asan_repro.py`

Builds:

- Vulnerable: NGINX `eff110885412737aec9b953067b6a670bffdbfa0` + njs `0.9.8`, ASAN enabled.
- Fixed: same NGINX revision + njs `0.9.9`, ASAN enabled.
- ASLR was left enabled. The ASAN runtime needed `detect_odr_violation=0` so NGINX could load the dynamic njs module; heap overflow detection stayed enabled.

Runtime:

- Vulnerable container: `njs-fetch-proxy-098-asan`, host port `19411`.
- Fixed container: `njs-fetch-proxy-099-asan`, host port `19421`.

Verified behavior:

- Benign `ngx.fetch()` through `js_fetch_proxy` succeeds on both versions and the local proxy endpoint receives `Proxy-Authorization`.
- On njs `0.9.8`, raw 512-byte username/password values in the client-controlled query parameters close the trigger connection. The master process starts a replacement worker.
- The vulnerable logs show `AddressSanitizer: heap-buffer-overflow` in `ngx_unescape_uri()` called from `ngx_js_parse_proxy_url()`.
- On njs `0.9.9`, the same request returns HTTP 200 from the proxy endpoint and no fresh ASAN signature appears.

Artifacts:

- `artifacts/njs_fetch_proxy_cve_2026_8711_asan_repro_20260520.cast`
- `artifacts/njs_fetch_proxy_cve_2026_8711_asan_repro_20260520.gif`

Current ASLR-bypass status:

- Crash reproduction is confirmed.
- No ASLR bypass claim has been made yet on this branch.
- Next work item is to audit whether this overflow can be turned into a remotely observable leak or reliable code execution primitive without weakening ASLR.

## 2026-05-20 Non-ASAN Behavior Sweep

Tool:

- `tools/njs_fetch_proxy_len_sweep.py`

Runtime:

- Vulnerable non-ASAN image: `njs-fetch-proxy-098`, host port `19431`.
- ASLR was left enabled.

Observed over HTTP:

- Credential lengths up to 127 bytes reach the local proxy endpoint and return `PROXY:Basic ...`.
- Any tested username or password length of 128 bytes or more returns the fixed 28-byte JS error body: `failed to evaluate proxy URL`.
- The target remains externally healthy after each request because the NGINX master process starts a replacement worker when a worker dies.

Observed in local container logs:

- Some over-127 requests only log `js_fetch_proxy username/password invalid or too long`.
- Larger or differently shaped overflows corrupt allocator state and the worker exits after the HTTP response has already been sent.
- Crash signatures in the non-ASAN run included glibc `free(): invalid next size (normal)` and worker exits by signal.

Artifacts:

- `artifacts/njs_fetch_proxy_cve_2026_8711_len_sweep_20260520.cast`
- `artifacts/njs_fetch_proxy_cve_2026_8711_len_sweep_20260520.gif`

ASLR-bypass implication from this sweep:

- The standard HTTP response does not include pointer-bearing data.
- The remotely visible result is a boundary oracle (`<=127` reaches proxy, `>=128` returns fixed error) plus an optional worker-restart oracle.
- This does not by itself bypass ASLR. Turning this into ASLR-bypassing exploitation would require either an additional memory disclosure primitive or a reliable address-independent corruption target.

## ASLR Bypass Audit Notes

Source constraints:

- `ngx.fetch()` allocates the fetch object from the request pool before evaluating `js_fetch_proxy`.
- The dynamic proxy URL is generated through `ngx_http_complex_value()` and stored in the request pool.
- njs `0.9.8` then allocates fixed 128-byte `decoded_user` and `decoded_pass` buffers in the same request pool.
- If raw decoded username length exceeds 127, the function returns before password decode and before `ngx_js_build_proxy_auth_header()`.
- If raw decoded password length exceeds 127, the function returns before `ngx_js_build_proxy_auth_header()`.

Practical consequence:

- The overlong credential path does not normally reach proxy connection setup, resolver processing, origin fetch, or proxy auth header reflection.
- Valid credentials are reflected through `Proxy-Authorization`, but only attacker-controlled bytes are reflected.
- Parse failure is surfaced to JavaScript as the fixed message `failed to evaluate proxy URL`.

Current candidate list:

- Real: crash/restart oracle.
- Real: proxy-reachability and 127-byte boundary oracle.
- Real but not a leak: `Proxy-Authorization` reflection for valid credentials.
- Weak: allocator-state survival oracle through request-pool or glibc metadata corruption.
- Not found yet: an HTTP-only address leak in the standard NGINX+njs path.

Next tests:

- Let the independent pool-corruption side-track finish source review.
- If a specific corrupted follow-on allocation target is identified, add a dedicated HTTP-only harness for that target.
- If no target is identified, document the result as crash-only without ASLR bypass for the standard deployment model, while keeping the branch available for any new external hint.

## Pool-Corruption Side-Track Result

Independent source and HTTP-only review did not find an intrinsic pointer leak in the standard `js_fetch_proxy` overflow path.

Confirmed:

- Username overflow around the low hundreds can return the fixed `500 failed to evaluate proxy URL` response and then kill the worker on cleanup.
- Password overflow has a similar fixed-error/crash boundary at larger sizes.
- Keepalive survival versus EOF is a real allocator-state oracle, but it exposes pool-tail phase, not an address.
- Because NGINX request-pool metadata lives before pool allocations, the forward overflow from `decoded_user` or `decoded_pass` does not directly overwrite the owning pool header.

Current verdict for the standalone CVE:

- Crash/restart: confirmed.
- Fixed boundary/proxy-reachability oracle: confirmed.
- Direct HTTP memory leak: not found.
- Standalone ASLR bypass: not proven.

## ASLR Bypass Composition: Same-Worker File Read

The lab now also includes an intentionally vulnerable njs file-read endpoint:

- Config: `location /file_read { js_content njs_fetch_proxy.file_read; }`
- Implementation: `env/njs-fetch-proxy.js` imports `fs` and calls `fs.readFileSync(r.args.path)`.
- Tool: `tools/njs_fetch_proxy_maps_leak.py`

This is not part of the CVE itself. It models a second bug class in the same NGINX worker process. Because njs handlers execute inside the NGINX worker, reading `/proc/self/maps` leaks the exact address space of the process that contains the vulnerable `js_fetch_proxy` code path.

Verified over HTTP:

- `/proc/sys/kernel/randomize_va_space` returned `2`, so ASLR was enabled.
- `/proc/self/maps` returned live mappings for:
  - NGINX executable
  - `ngx_http_js_module.so`
  - libc
  - dynamic loader
  - writable anonymous mappings
  - stack

Artifacts:

- `artifacts/njs_fetch_proxy_cve_2026_8711_maps_leak_20260520.cast`
- `artifacts/njs_fetch_proxy_cve_2026_8711_maps_leak_20260520.gif`

Important boundary:

- This same-worker file-read composition is ASLR-bypass-relevant because it leaks the NGINX worker's own maps.
- A file-read bug in a separate PHP-FPM worker would normally leak the PHP-FPM process maps, not the NGINX worker maps, and would not directly bypass ASLR for this njs/NGINX-worker overflow.

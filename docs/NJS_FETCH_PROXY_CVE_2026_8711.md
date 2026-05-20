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

- `/tmp/nginx-njs-0.9.8-src/nginx/ngx_js.c` for the vulnerable source
- `/tmp/nginx-njs-src/nginx/ngx_js.c` for the fixed `0.9.9` checkout
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

## Rejected Path: File Read / LFI

File-read and LFI primitives are out of scope for this CVE-2026-8711 track.
They were useful for the original Rift lab, but they must not be used as the
ASLR-bypass answer for the new vulnerability tracks.

Removed from the active lab:

- The intentionally vulnerable njs `/file_read` endpoint.
- The `fs.readFileSync(r.args.path)` helper in `env/njs-fetch-proxy.js`.
- The `tools/njs_fetch_proxy_maps_leak.py` PoC and its demo artifacts.

Constraint going forward:

- ASLR leak/bypass candidates must be remote HTTP behavior generated by the
  vulnerable NGINX/njs code path or by a separate NGINX-side memory disclosure.
- Do not rely on `/proc/self/maps`, `/proc/<pid>/maps`, local file reads,
  phpinfo, PHP-FPM LFI, coredumps, ptrace, debugger output, or host/container
  introspection for the two new vulnerability tracks.

## 2026-05-20 Remote-Only Keepalive Oracle

Tool:

- `tools/njs_fetch_proxy_keepalive_oracle.py`

Runtime:

- Rebuilt vulnerable non-ASAN image from the cleaned config, with no auxiliary
  file-read route.
- Container: `njs-fetch-proxy-098`, host port `19431`.
- Inputs and observations were HTTP-only. The run did not inspect Docker logs,
  procfs, coredumps, target files, or local worker state.

Observed over HTTP:

- Username and password lengths up to `127` bytes produce normal proxy traffic
  and the same TCP keepalive connection remains usable.
- Lengths at and above `128` return the fixed error response
  `failed to evaluate proxy URL`.
- Username overflows around `192` bytes and above return the fixed error, then
  the same keepalive connection closes before a follow-up `GET /` can complete.
  A fresh connection remains healthy, so the master/worker service recovers.
- Password overflows are less direct: most tested lengths return the fixed error
  and preserve the keepalive connection; a narrow larger region can produce no
  first response before the fresh health check recovers.
- Percent-encoded credentials produce the same decoded-length boundary: decoded
  lengths through `127` survive, decoded lengths at and above `128` enter the
  invalid/overflow path, and larger decoded username values reproduce the
  keepalive-loss signal.

Implication:

- This is a real remote crash/survival oracle for allocator-state corruption in
  the vulnerable code path.
- It is not yet an ASLR bypass. The signal distinguishes request-pool survival
  from worker death, but it has not exposed pointer bytes or a progressive
  mapped-address test.

Artifacts:

- `artifacts/njs_fetch_proxy_keepalive_oracle_20260520.cast`
- `artifacts/njs_fetch_proxy_keepalive_oracle_20260520.gif`
- `artifacts/njs_fetch_proxy_keepalive_oracle_percent_20260520.cast`
- `artifacts/njs_fetch_proxy_keepalive_oracle_percent_20260520.gif`

Sidecar source-audit result:

- The vulnerable path fails before proxy connection setup when a decoded
  credential exceeds `127` bytes, so resolver, upstream response parsing, and
  proxy-auth reflection are not reached on the overflowing request.
- Valid-length proxy-auth reflection only reflects attacker-controlled
  credentials.
- The request-pool allocator stores pool metadata before allocations, so this
  forward overflow does not trivially overwrite the owning pool header.
- The best remaining CVE-local lead is a pattern-dependent liveness oracle:
  vary decoded bytes after offset `128` and classify fixed-error survival,
  keepalive EOF, no first response, and recovery timing.

## 2026-05-20 Decoded-Byte Matrix

Tool:

- `tools/njs_fetch_proxy_pattern_matrix.py`

Purpose:

- Test whether the keepalive/crash oracle depends on attacker-controlled bytes
  written past decoded offset `128`, which would be a prerequisite for a useful
  remote address/progressive pointer oracle.
- The tool percent-encodes every credential byte so the tested byte value is
  exactly the decoded value passed to `ngx_unescape_uri()`.

Live result:

- Username overflow classes were length-driven, not byte-driven. In the tested
  matrix, decoded lengths through `160` kept the same TCP connection usable,
  while `192` and above returned the fixed error and then lost keepalive. Every
  tested overflow byte produced the same class at a given length.
- Password overflow classes were also length-driven. Most tested lengths kept
  the connection usable; a tested `512`-byte password region lost keepalive.
  Every tested overflow byte produced the same class at a given length.

Implication:

- The current CVE-2026-8711 lab exposes a useful remote stability oracle, but
  this matrix did not show byte-sensitive behavior that could be driven into a
  progressive ASLR leak.
- This reduces the plausibility of a standalone ASLR bypass for the standard
  `js_fetch_proxy` overflow path unless another NGINX/njs memory disclosure or
  dereference sink is found.

Artifacts:

- `artifacts/njs_fetch_proxy_pattern_matrix_user_20260520.cast`
- `artifacts/njs_fetch_proxy_pattern_matrix_user_20260520.gif`
- `artifacts/njs_fetch_proxy_pattern_matrix_pass_20260520.cast`
- `artifacts/njs_fetch_proxy_pattern_matrix_pass_20260520.gif`

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

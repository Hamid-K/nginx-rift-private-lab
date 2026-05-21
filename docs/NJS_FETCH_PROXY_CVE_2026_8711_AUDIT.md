# njs js_fetch_proxy Credential Overflow Audit

Started: 2026-05-21
Branch: `research/njs-fetch-proxy-cve-2026-8711-audit`

## Status

- [x] Identified a concrete fixed bug in NGINX JavaScript (`njs`) rather than
  NGINX core: `js_fetch_proxy` dynamic proxy URL credentials.
- [x] Confirmed vulnerable lab image: NGINX `1.31.1` plus njs `0.9.8`.
- [x] Confirmed fixed comparison image: NGINX `1.31.1` plus njs `0.9.9`.
- [x] Added a repo-local Dockerfile and config for rebuilding both variants.
- [x] Added a defensive ASAN reproducer.
- [x] Recorded a clean asciinema/GIF milestone after the probe run.

## Root Cause

Upstream njs commit `2bf4601a94c2a22b715d74e6d92dedb1850d56d3` is titled
`Fetch: fixed heap buffer overflow in proxy URL credentials`.

The vulnerable function is `ngx_js_parse_proxy_url()` in `nginx/ngx_js.c`.
Before the fix, decoded proxy username and password buffers were allocated as
fixed 128-byte pool chunks:

- `decoded_user = ngx_pnalloc(pool, 128)`
- `decoded_pass = ngx_pnalloc(pool, 128)`

The input length came from the configured proxy URL value. When
`js_fetch_proxy` used variables, request-controlled query/header-derived values
could flow into that URL. `ngx_unescape_uri()` can write one output byte per
input byte, so raw or percent-decoded credentials longer than 128 bytes wrote
past the destination buffer. The length check ran after decoding, which was too
late.

The fix sizes the destination buffers from the encoded credential lengths before
calling `ngx_unescape_uri()` and removes the unsafe post-decode 127-byte cap.

## Affected Condition

This requires an njs-enabled NGINX configuration using `js_fetch_proxy` with a
proxy URL containing variables in the credential component, for example:

```nginx
location /dynamic_proxy {
    js_fetch_proxy http://$arg_u:$arg_p@127.0.0.1:19412;
    js_content njs_fetch_proxy.http_fetch;
}
```

The bug is not in stock NGINX core alone. It is in the njs dynamic module when
this proxy feature is enabled and request-influenced variables are used in the
proxy URL credentials.

## Reproduction

Build vulnerable and fixed ASAN labs:

```bash
docker build -f env/Dockerfile.njs-fetch-proxy \
  --build-arg NJS_REF=0.9.8 \
  -t njs-fetch-proxy-098-asan env

docker build -f env/Dockerfile.njs-fetch-proxy \
  --build-arg NJS_REF=0.9.9 \
  -t njs-fetch-proxy-099-asan env

docker run --rm -d --name njs-fetch-proxy-098-asan -p 19411:19411 njs-fetch-proxy-098-asan
docker run --rm -d --name njs-fetch-proxy-099-asan -p 19421:19411 njs-fetch-proxy-099-asan
```

Run the defensive reproducer:

```bash
./tools/njs_fetch_proxy_asan_repro.py \
  --vuln-target 127.0.0.1:19411 \
  --vuln-container njs-fetch-proxy-098-asan \
  --fixed-target 127.0.0.1:19421 \
  --fixed-container njs-fetch-proxy-099-asan
```

Expected result:

- Vulnerable njs `0.9.8`: ASAN reports `heap-buffer-overflow` in
  `ngx_unescape_uri()`.
- Fixed njs `0.9.9`: the same request lengths complete without ASAN findings.

## Current Evidence

Existing ASAN container logs already show the vulnerable path aborting in:

- `ngx_unescape_uri()`
- called from `ngx_js_parse_proxy_url()`
- called through dynamic `js_fetch_proxy` evaluation
- request entered through `ngx_http_js_content_handler()`

The crash address was immediately after a 4096-byte NGINX request-pool region,
which is consistent with a small pool allocation overrun hidden inside the
larger request pool unless ASAN/pool instrumentation is active.

Live run on 2026-05-21:

```text
[vuln] user_len=127  status=200 bytes=70    note=ok
[vuln] user_len=128  status=500 bytes=28    note=ok
[vuln] user_len=129  status=500 bytes=28    note=ok
[vuln] user_len=160  status=500 bytes=28    note=ok
[vuln] user_len=200  status=-   bytes=0     note=RemoteDisconnected
[vuln] sanitizer_delta_bytes=7689 asan_hit=True
[fixed] user_len=127  status=200 bytes=70    note=ok
[fixed] user_len=128  status=200 bytes=70    note=ok
[fixed] user_len=129  status=200 bytes=70    note=ok
[fixed] user_len=160  status=200 bytes=70    note=ok
[fixed] user_len=200  status=200 bytes=70    note=ok
[fixed] sanitizer_delta_bytes=0 asan_hit=False
summary vuln_asan=True fixed_asan=False
```

Artifacts:

- `artifacts/njs_fetch_proxy_asan_repro_20260521.cast`
- `artifacts/njs_fetch_proxy_asan_repro_20260521.gif`

Interpretation: njs `0.9.8` rejects decoded usernames above 127 bytes only
after decoding into the fixed destination buffer. In this build, lengths 128 to
160 return a logged `500` without immediately crossing an ASAN redzone because
the overflow remains inside the larger NGINX request-pool allocation. Length
200 crosses the request-pool boundary and ASAN reports the write in
`ngx_unescape_uri()`. njs `0.9.9` sizes the decode buffers correctly and stays
clean for the same inputs.

## Next Work

- Minimize the exact credential length threshold and percent-encoding variants.
- Check whether the overflow is limited to dynamic HTTP `js_fetch_proxy` or
  also reachable in the stream module's dynamic proxy path.
- Keep this as crash/root-cause research only until the bug is fully
  characterized and fixed-version guidance is documented.

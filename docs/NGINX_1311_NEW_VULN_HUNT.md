# NGINX 1.31.1 New Vulnerability Hunt

Started: 2026-05-20
Branch base: `research/nginx-poolslip-rediscovery`

## Scope

The Nebusec demo is now treated as a separate `nginx/1.31.1` vulnerability hunt, not as CVE-2026-42945/Rift plus a new ASLR leak.

Visible demo facts:

- Target build reports `nginx/1.31.1`.
- Compiler reports clang `18.1.3 (1ubuntu1)`.
- Visible configure arguments: `--with-cc-opt='-O1 -g -fno-omit-frame-pointer' --without-http_gzip_module`.
- No visible `--with-http_v2_module`, `--with-http_ssl_module`, or `--with-http_mp4_module`.
- Exploit first recovers a heap base in about 300 requests, then prints an NGINX code base and obtains a shell.

Working assumption: the exploit uses a new HTTP/1/default-module bug or oracle in official-looking `1.31.1`, likely involving allocator/pool state and response/crash classification.

## Current Baseline

- Local NGINX source: `/tmp/nginx-rift-nginx-src`.
- Official `origin/master` currently resolves to commit `eff110885412737aec9b953067b6a670bffdbfa0`, matching `nginx/1.31.1`.
- The Rift fix is present: `ngx_http_script_regex_end_code()` resets `e->is_args`.
- Docker lab `nginx-poolslip-1311-amd64` reproduces the video-like build profile on amd64 Ubuntu 24.04.
- HTTP-only probes against range/static, malformed upstream charset headers, early hints, chunked trailers, rewrite/set, and large-header keepalive found no response-visible leak/crash anomaly.

## Audit Priorities

1. Default modules new or changed near `1.31.1`: `ngx_http_tunnel_module`, `ngx_http_upstream_sticky_module`, upstream keepalive/default keepalive, and proxy HTTP/1.1 changes.
2. Pool/allocator oracles: corruption of `ngx_pool_t.d.last`, `d.end`, `current`, `large`, or request buffer pointers where crash/no-crash behavior can reveal heap chunks.
3. Range/static response-shape oracles with gzip disabled.
4. Upstream parser state machines: status line, `103 Early Hints`, malformed headers, trailers, chunking, retry/reinit paths.
5. Request lifecycle and keepalive reuse: large header buffers, pipelining, discard body, lingering close, and request-body temp-file cleanup.

## Non-Assumptions

- Do not assume `CVE-2026-42945` is the exploited corruption primitive.
- Do not rely on core dumps, `/proc/<pid>/mem`, ptrace relaxation, or disabled ASLR.
- Do not use LFI, arbitrary file read, phpinfo, `/proc/<pid>/maps`, local files, or target-side introspection for the video-equivalent ASLR bypass.
- LFI-derived NGINX worker maps are now rejected for this new-vulnerability hunt; they belong only to the older Rift lab track.

## 2026-05-20 Progress

### Source-Audit Leads

- `1.31.1` is not a narrow HTTP/1 security diff from `1.31.0`: the local upstream tree only changes HTTP/2 header limits, MP4 null-pointer arithmetic, mail cleanup/style, and version metadata after `release-1.31.0`.
- The video build does not visibly enable HTTP/2, SSL, or MP4, so the hunt remains broader than the `1.31.0..1.31.1` diff.
- Range/static remains the highest-priority response-shape lead because gzip is disabled in the video and byte-range responses can expose precise body/filter length mistakes. Current source guards range numeric overflow and clamps ranges to `content_length`, but multipart range output still deserves live testing across static and upstream-backed bodies.
- `ngx_http_tunnel_module` is default-built in this tree, but it is only reachable when `tunnel_pass` is configured and only accepts `CONNECT`. It remains a config-dependent candidate, not a default-route lead.
- `ngx_http_upstream_sticky_module` has shared-memory state and route/session IDs, but configured server route IDs are bounded to `NGX_HTTP_UPSTREAM_SID_LEN` before runtime use. No remote pointer leak has been identified in the first pass.

### Live-Test Plan Updates

- Extended `env/nginx-poolslip.conf` with `/stream` and `/forced-range` locations to exercise upstream bodies with `proxy_buffering off` and `proxy_force_ranges on`.
- Extended `env/server.py` with deterministic 64 KiB upstream bodies using both `Content-Length` and chunked transfer.
- Extended `tools/no_lfi_http_module_probe.py` with `range/upstream` probes. These are still HTTP-only: no LFI, procfs, cores, debugger, or ASLR weakening.

### Live-Test Results

- `artifacts/no_lfi_http_module_probe_range_upstream_clean_20260520.cast`
- `artifacts/no_lfi_http_module_probe_range_upstream_clean_20260520.gif`

Clean result:

- Static range requests returned expected 206/416 responses only.
- Upstream `proxy_force_ranges` returned exact expected single-range bytes.
- Multi-range on forced upstream declined to full 200 body instead of exposing unexpected multipart data.
- `proxy_buffering off` stream paths returned full upstream bodies and did not apply unsafe range slicing.
- Malformed upstream charset, early hints with malformed charset, and chunked trailers did not crash or leak.
- Rewrite regression probes against fixed `1.31.1` did not crash.
- Large-header keepalive returned two normal response markers.

Current conclusion for this hypothesis: range/static/upstream output filtering remains a useful source-audit shape, but the tested HTTP-only configurations did not reproduce a leak/crash oracle.

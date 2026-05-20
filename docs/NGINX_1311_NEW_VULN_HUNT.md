# NGINX 1.31.1 New Vulnerability Hunt

Started: 2026-05-20
Branch: `research/poolslip-remote-only-oracles`

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
- A dedicated header/trailer sink probe now exercises large final headers,
  real `103 Early Hints`, and chunked trailers. These are good disclosure
  sinks if a separate corruption controls header metadata, but the sink paths
  are clean without that corruption.
- A large-header/pipelining matrix around the configured header-buffer limits
  produced expected `200,200` or clean `400` responses, with no remote
  allocator oracle observed.

## Audit Priorities

1. Default modules new or changed near `1.31.1`: `ngx_http_tunnel_module`, `ngx_http_upstream_sticky_module`, upstream keepalive/default keepalive, and proxy HTTP/1.1 changes.
2. Pool/allocator oracles: corruption of `ngx_pool_t.d.last`, `d.end`, `current`, `large`, or request buffer pointers where crash/no-crash behavior can reveal heap chunks.
3. Range/static response-shape oracles with gzip disabled.
4. Upstream parser state machines: status line, `103 Early Hints`, malformed headers, trailers, chunking, retry/reinit paths.
5. Request lifecycle and keepalive reuse: large header buffers, pipelining, discard body, lingering close, and request-body temp-file cleanup.

## Non-Assumptions

- Do not assume `CVE-2026-42945` is the exploited corruption primitive.
- Do not rely on core dumps, `/proc/<pid>/mem`, ptrace relaxation, or disabled ASLR.
- Do not use LFI, arbitrary file read, phpinfo, `/proc/<pid>/maps`,
  coredumps, ptrace, debugger output, or target-side filesystem reads as the
  ASLR leak for this new-vulnerability track.
- Do not count LFI-derived NGINX worker maps as the video-equivalent path.

## 2026-05-20 Header Sink Milestone

Tool:

- `tools/poolslip_header_sink_probe.py`

Lab updates:

- Backend can emit many proxied headers, many `103 Early Hints`, and chunked
  trailers.
- NGINX `/delay` enables `proxy_pass_trailers on` and `early_hints
  $http_early_hints` so the raw client sees the sink paths.

Result:

- Moderate early-hints cases returned `103,200` pairs and trailer cases returned
  chunked trailer output.
- Larger upstream header/hints cases returned clean `502` boundary responses.
- No binary spill, textual pointer, canonical little-endian pointer word, or
  worker instability was observed.

Artifacts:

- `artifacts/poolslip_header_sink_probe_20260520.cast`
- `artifacts/poolslip_header_sink_probe_20260520.gif`

## 2026-05-20 Large-Header Matrix

Tool:

- `tools/poolslip_large_header_matrix.py`

Result:

- Header sizes below the large-header limit support pipelined follow-up requests
  and return `200,200`.
- Header sizes beyond the configured limit return clean `400`.
- POST `/spray` with large headers plus a pipelined follow-up returns clean
  `200,200`.
- No crash, no remote timing/response anomaly, and no ASLR-relevant signal was
  observed.

Artifacts:

- `artifacts/poolslip_large_header_matrix_20260520.cast`
- `artifacts/poolslip_large_header_matrix_20260520.gif`

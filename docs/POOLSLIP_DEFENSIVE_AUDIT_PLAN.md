# Poolslip Defensive Source Audit Plan

Started: 2026-05-21
Branch: `research/poolslip-defensive-source-audit`
Target source: NGINX `eff110885412737aec9b953067b6a670bffdbfa0` / `nginx/1.31.1`
Observed demo build flags: `--with-cc-opt='-O1 -g -fno-omit-frame-pointer' --without-http_gzip_module`

## Scope And Boundaries

This plan is for authorized defensive vulnerability research on the local lab
and source tree. The objective is to identify, reproduce, minimize, and explain
remote pre-auth memory-safety issues in the NGINX build profile suggested by
the public demo.

Current stage:

- Find and prove bugs first. Exploit weaponization, ASLR bypass chaining, and
  payload engineering are deferred until there is a concrete memory-safety
  finding to study.

Allowed outputs in this stage:

- Source-audit notes with exact file/function references.
- Fuzzing harnesses and crash reproducers that demonstrate memory-safety faults
  without turning them into command execution.
- ASAN/UBSAN traces, minimized HTTP requests, and root-cause explanations.
- Patch, mitigation, detection, and responsible-disclosure notes.
- Non-sensitive artifacts such as asciinema/GIF recordings of crash or clean
  probe runs.

Deferred until a bug is found:

- Weaponized pre-auth exploitation.
- Functional ASLR-bypass exploit chaining.
- Payloads that turn a suspected undisclosed issue into arbitrary code
  execution against real NGINX deployments.
- Use of LFI, arbitrary file read, phpinfo, `/proc/<pid>/maps`,
  `/proc/<pid>/mem`, coredumps, ptrace, debugger output, disabled ASLR, or
  target-side filesystem reads as a claimed remote ASLR leak.

## Live Status

- [x] Created dedicated branch.
- [x] Created living plan document.
- [x] Confirm exact local source checkout and build flags.
- [x] Rebuild a clean ASAN audit image for `nginx/1.31.1` with the demo
  module profile.
- [x] Re-run existing remote-only probes against the clean audit image.
- [x] Start focused source-audit pass over highest-priority pre-auth surfaces.
- [x] Add first targeted module probes for newly enabled default modules.
- [x] Add first upstream parser fuzz/minimization harness.
- [x] Add focused request-body/discard/chunked pipeline probe.
- [x] Add source-guided request-sequence fuzzer for allocator/pool state.
- [x] Add lab-backed upstream-response fuzzer for proxy parser state.
- [ ] Update this plan with new hypotheses and completed tasks after each
  audit/test milestone.

## Current Hypotheses

The public demo appears to recover heap layout progressively, then derive an
NGINX code base after heap shaping. That does not look like a simple passive
pointer leak. The strongest defensive hypothesis is a memory-corruption bug
paired with a remote crash/survival or response-shape oracle.

Candidate surfaces:

- Request pool and connection pool allocation/reuse.
- Large request headers and keepalive/pipelining.
- Upstream HTTP parser state transitions, including `103 Early Hints`,
  trailers, chunked bodies, retries, and buffer compaction.
- Response header/trailer metadata copying.
- Range/static and proxied body filter metadata.
- Default modules present in the demo-like build: rewrite, proxy, fastcgi,
  uwsgi, scgi, charset, ssi, range, chunked, autoindex, userid, tunnel, and
  upstream sticky.

## Work Queue

### 1. Baseline And Reproducibility

- [x] Record exact source commit, configure output, compiler version, and module
  list in this document.
- [x] Build ASAN and non-ASAN containers with the same demo flags.
- [ ] Verify the image still reports `Server: nginx/1.31.1`.
- [ ] Record baseline clean runs for existing probes:
  - [x] `tools/no_lfi_http_module_probe.py`
  - [x] `tools/poolslip_header_sink_probe.py`
  - [x] `tools/poolslip_large_header_matrix.py`

### 2. Source Audit Passes

- [ ] Pool allocator and lifecycle:
  - `src/core/ngx_palloc.c`
  - `src/http/ngx_http_request.c`
  - cleanup handlers, request finalization, keepalive reuse.
- [ ] Large header and pipelined request parser:
  - `ngx_http_alloc_large_header_buffer()`
  - `ngx_http_process_request_header()`
  - `ngx_http_set_keepalive()`
  - `ngx_http_copy_pipelined_header()`
- [ ] Upstream parser and buffer compaction:
  - proxy status/header/trailer parsing
  - `ngx_http_upstream_process_early_hints()`
  - `ngx_http_upstream_process_trailers()`
  - retry/reinit behavior after invalid upstream responses.
- [ ] Header/body disclosure sinks:
  - final header filter
  - early hints filter
  - chunked trailer filter
  - range/body write filters.
- [ ] Default-module diff review around `1.31.0 -> 1.31.1` and nearby commits
  for newly introduced pool, parser, or filter behavior.
- [x] New default-module pass:
  - `ngx_http_tunnel_module`
  - `ngx_http_upstream_sticky_module`
- [ ] Request-body and discard-body pass:
  - `ngx_http_request_body_chunked_filter()`
  - `ngx_http_discard_request_body_filter()`
  - `ngx_http_copy_pipelined_header()`
  - lingering close and keepalive reuse after discarded bodies.

### 3. Fuzzing And Minimization

- [x] Add a raw HTTP/1 request-sequence fuzzer for large-header/keepalive/
  pipelining transitions.
- [x] Add an upstream-response fuzzer for proxy status/header/trailer/early
  hints state machines.
- [x] Add a targeted chunked request-body/discard probe for body parser to
  keepalive-pipeline transitions.
- [ ] Ensure harnesses support ASAN capture and request minimization.
- [ ] Record any crash with:
  - exact request bytes or upstream transcript,
  - ASAN stack,
  - affected source line,
  - minimized repro,
  - fixed/mitigated behavior if a patch is available or produced.

### 4. Evidence Rules

- [ ] A finding only counts as a candidate vulnerability if it reproduces from
  remote HTTP traffic in the lab without file-read/procfs/core/debugger inputs.
- [ ] A finding only counts as memory-safety evidence if ASAN/UBSAN or a
  deterministic crash confirms out-of-bounds, UAF, double free, use of
  uninitialized memory, or invalid pointer dereference.
- [ ] A finding only counts as an information leak if bytes returned to the
  HTTP client include memory not controlled by the client/upstream and not
  expected by protocol behavior.

## Milestone Log

- 2026-05-21: Created this defensive audit plan. Functional RCE and ASLR-bypass
  exploit chains are outside the deliverables I can provide; work continues on
  source audit, crash reproduction, leak identification, and mitigation-grade
  evidence.
- 2026-05-21: Baseline inventory confirmed:
  - Local source: `/tmp/nginx-rift-nginx-src`
  - Commit: `eff110885412737aec9b953067b6a670bffdbfa0`
  - Description: `release-1.31.0-6-geff110885`
  - Running lab reports: `nginx/1.31.1`
  - Compiler: `clang 18.1.3 (1ubuntu1)`, x86_64
  - Configure arguments: `--builddir=build --with-cc=clang
    --with-cc-opt='-O1 -g -fno-omit-frame-pointer'
    --without-http_gzip_module`
  - Health check: `GET /` returns `poolslip lab ok`.
- 2026-05-21: Initial ASAN+UBSAN build completed, but an ordinary `GET /`
  triggers UBSAN's function-pointer-type check in the NGINX HTTP filter chain:
  `ngx_output_chain()` calls a filter through a generic output-chain callback
  type. This is a sanitizer compatibility issue for this codebase and not a
  useful candidate vulnerability. Runtime fuzzing will use an ASAN-only image;
  UBSAN can still be used selectively with non-fatal options for specific
  arithmetic/state-machine hypotheses.
- 2026-05-21: ASAN-only image `nginx-poolslip-1311-amd64-asan` started on
  `127.0.0.1:19341` and returned healthy `GET /` responses. Existing remote-only
  probes completed without ASAN findings:
  - `tools/no_lfi_http_module_probe.py --target 127.0.0.1:19341`
  - `tools/poolslip_header_sink_probe.py --target 127.0.0.1:19341`
  - `tools/poolslip_large_header_matrix.py --target 127.0.0.1:19341`
  Observed errors were expected clean boundaries: oversized upstream headers,
  oversized trailers, and too-long client header lines.
- 2026-05-21: Large-header/keepalive source pass started. Current read:
  - `ngx_http_alloc_large_header_buffer()` bounds a single in-progress request
    line/header line against `large_client_header_buffers.size` before copying
    to a large buffer.
  - Large header buffers are allocated from the connection pool and linked in
    `ngx_http_connection_t.busy/free`.
  - `ngx_http_set_keepalive()` preserves the current large buffer for a
    pipelined request and resets/moves other large buffers to the free list.
  - ASAN large-header/pipeline matrix matched this ownership model and produced
    only clean `200,200` or `400` boundaries.
  - No candidate memory-safety bug found in this pass yet.
- 2026-05-21: Fetched `origin/master` and tags for the local NGINX source.
  The official remote still resolves to `eff110885412737aec9b953067b6a670bffdbfa0`;
  there is no newer upstream fix diff available in this checkout to work
  backward from.
- 2026-05-21: Added ASAN lab coverage for the default modules that were not
  exercised by the first broad probes:
  - `tunnel_pass` is now enabled on the same exposed port through a
    `tunnel.local` virtual server.
  - `sticky cookie` and `sticky learn` upstreams are reachable under
    `/sticky-cookie` and `/sticky-learn`.
  - The Python backend harness was changed to use `ThreadingTCPServer` and
    explicit `Connection: close`, avoiding false timeouts caused by the toy
    backend rather than NGINX.
- 2026-05-21: Added and ran targeted remote-only probes against the ASAN image:
  - `tools/poolslip_tunnel_probe.py --target 127.0.0.1:19341`
  - `tools/poolslip_sticky_probe.py --target 127.0.0.1:19341 --timeout 5`
  Sticky coverage returned clean `200` responses across large dynamic cookie
  domains, dynamic `samesite`, oversized route cookies, and learn-mode inputs;
  no pointer-looking output, non-ASCII spill, crash, or worker health loss was
  observed. Tunnel parser coverage returned expected `400`/`405` boundaries for
  malformed CONNECT authorities and no ASAN finding. This crosses off the
  simple client-controlled-length theories in `ngx_http_upstream_sticky_*()`
  and CONNECT authority parsing; the remaining value in these modules would
  require a more specific state-machine flaw.
- 2026-05-21: Added and ran the first upstream parser probe,
  `tools/poolslip_upstream_parser_probe.py --target 127.0.0.1:19341`.
  The probe exercised split/invalid status lines, duplicate content length,
  `Content-Length` plus `Transfer-Encoding`, chunk-size overflow, long chunk
  extensions, invalid/oversized trailers, and repeated `103 Early Hints`.
  ASAN stayed quiet, worker health stayed up, and the NGINX error log showed
  expected protocol-boundary errors only. No memory-safety candidate in this
  upstream parser pass.
- 2026-05-21: Request-body source pass started. Interesting but not yet
  confirmed bug lead: both `ngx_http_request_body_chunked_filter()` and
  `ngx_http_discard_request_body_filter()` transition from chunked-body parsing
  into `ngx_http_copy_pipelined_header()`, which can move bytes from a body
  buffer or stack discard buffer into a large client-header buffer for the next
  keepalive request. The next probe will focus on chunked body boundaries,
  trailers, pipelined follow-up requests, and static/discard endpoints.
- 2026-05-21: Added `tools/poolslip_body_state_probe.py` and ran it against
  the ASAN image on `127.0.0.1:19341`. It covered static/discard endpoints and
  proxied request-body endpoints with chunked bodies, many tiny chunks, medium
  chunks, long chunk extensions, trailers, split final chunks, invalid chunk
  sizes, content-length bodies followed by pipelined requests, and a large
  header in the pipelined follow-up. Results were clean: expected `200,200` for
  valid pipelined cases, `400` for invalid chunked bodies, worker health stayed
  up, no pointer-shaped response bytes were detected, and ASAN logs stayed
  silent. No candidate bug in this body/discard pass.
- 2026-05-21: Extended the upstream parser lab with a raw non-HTTP upstream on
  `127.0.0.1:19324` and added `/scgi-raw` plus `/uwsgi-raw` locations. This
  exercises the SCGI/UWSGI status-line fallback path touched by the
  split-status fix, not only the proxy module. Ran the expanded
  `tools/poolslip_upstream_parser_probe.py` against both ASAN images:
  - fixed/demo-like `nginx/1.31.1` at `127.0.0.1:19341`
  - comparison `nginx/1.31.0` at `127.0.0.1:19350`
  Results were clean in both: expected `200`/`502` boundaries, stable worker
  health, no pointer-looking output, and no ASAN report. This does not yet
  reproduce the older split-status issue as a memory-safety crash in this lab.
- 2026-05-21: Added an exact `/rewrite-old` trigger matching the public
  rewrite/set bug shape (`rewrite ^(.*) /new?c=1; set $rewrite_capture $1;`).
  A first payload sweep against the `nginx/1.31.0` ASAN image did not crash;
  source review clarified why: the local `release-1.31.0` tag already contains
  the `e->is_args = 0` fix. A vulnerable comparison build must use
  `2046b45aa^`, not `release-1.31.0`, if we want to replay that fixed bug.
- 2026-05-21: Corrected the source-audit tree. The host checkout at
  `../nginx-src` is not the same commit graph as the running audit image. The
  ASAN container contains the intended `nginx/1.31.1` tree at
  `eff110885412737aec9b953067b6a670bffdbfa0`, and that exact tree is now copied
  to `/tmp/nginx-rift-nginx-src-1311` for local searches and diffs. The
  `release-1.31.0..eff110885` source diff for compiled HTTP/core code is small:
  version bump, a default-disabled HTTP/2 special-header length guard, a
  default-disabled MP4 null-pointer guard, and mail cleanup/style changes. That
  means the Poolslip/video bug, if present in the demo-like no-H2/no-MP4 build,
  is probably not discoverable by a simple `1.31.0 -> 1.31.1` HTTP/core diff and
  needs deeper state-machine probing of default modules.
- 2026-05-21: Integrated sidecar audit feedback into concrete harnesses:
  - `tools/poolslip_request_sequence_fuzzer.py` fuzzes large headers,
    keepalive/pipelining, content-length mismatch, chunked discard/body paths,
    malformed framing, upstream edge cases, rewrite edge cases, and CONNECT
    traffic. It classifies only remote response/health signals, with optional
    Docker log checks for local ASAN evidence.
  - `tools/poolslip_upstream_response_fuzzer.py` drives proxy upstream parser
    transcripts through a new lab backend mode, `case=raw-hex`, so we can test
    split status lines, many `103 Early Hints`, heavy headers, malformed
    headers, chunking, trailers, and truncation beyond the earlier fixed case
    list.
  Next milestone is live ASAN execution of both fuzzers against
  `127.0.0.1:19341` after rebuilding the image with the updated backend.
- 2026-05-21: Ran
  `tools/poolslip_request_sequence_fuzzer.py --target 127.0.0.1:19341
  --iterations 750 --seed 1347374924 --timeout 4 --container
  nginx-poolslip-1311-amd64-asan --stop-on-suspicious` against the
  `nginx/1.31.1` ASAN image. Result: `summary suspicious=0 iterations=750`,
  `asan_log_bytes 0`, `asan_status clean`. The run covered large-header
  keepalive/pipelining, many-large-header boundaries, content-length mismatch,
  chunked discard/body paths, malformed framing, proxy upstream edge cases,
  rewrite edge cases, and CONNECT/tunnel parser traffic. This is negative
  evidence for the current allocator/connection-pool hypotheses, not a proof of
  absence; next live pass is upstream transcript fuzzing with the rebuilt
  backend.
- 2026-05-21: First upstream-response fuzzer transport used raw response bytes
  in the client query string and mostly hit client-side `414 Request-URI Too
  Large`, so it was stopped and redesigned. The lab backend now supports a
  compact `case=raw-gen` mode that generates large upstream transcripts
  server-side from short query parameters; this keeps the client request within
  header limits while still stressing the proxy parser.
- 2026-05-21: Rebuilt the `nginx/1.31.1` ASAN image with `raw-gen` backend
  support and ran
  `tools/poolslip_upstream_response_fuzzer.py --target 127.0.0.1:19341
  --iterations 750 --seed 3235920 --timeout 5 --container
  nginx-poolslip-1311-amd64-asan --stop-on-suspicious`. Result:
  `summary suspicious=0 iterations=750`, `asan_log_bytes 0`, `asan_status
  clean`. Case mix covered chunk extensions, chunk-size overflow,
  early-final `103,200` sequences, heavy upstream headers, invalid/split
  status lines, malformed headers, many Early Hints, trailers, truncation, and
  valid controls. This weakens the straightforward upstream parser,
  Early-Hints metadata, trailer, and heavy-header disclosure hypotheses in the
  current no-H2/no-MP4 ASAN build.
- 2026-05-21: Started a separate fixed-bug validation track for the HTTP/2
  response-header length issue fixed by `58a7bc340`. This is not a Poolslip
  demo match because the demo-like build does not include
  `--with-http_v2_module`. The work is tracked in
  `docs/H2_RESPONSE_HEADER_LENGTH_AUDIT.md`. First `release-1.31.0` H2 ASAN
  run with huge `Content-Type`/`Location` values produced no ASAN finding; this
  matches the upstream fix note that normal module paths may leave enough
  encoded-buffer slack despite the source-level allocation undercount.

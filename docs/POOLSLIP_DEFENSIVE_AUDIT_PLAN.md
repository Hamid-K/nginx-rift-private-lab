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

Deferred for this phase until a bug is found and characterized:

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
- [x] Add raw HTTP mutation fuzzer for parser/lifecycle coverage.
- [x] Add a focused CONNECT/tunnel lifecycle probe for the new default tunnel
  module.
- [x] Add a focused CONNECT/proxy-auth probe for the changed `auth_basic`
  behavior on `CONNECT` requests.
- [x] Add a focused static file `Range`/body-filter probe for `ngx_buf_t`
  offset manipulation.
- [x] Add a focused dynamic `tunnel_pass;` probe for `$host:$request_port`
  authority parsing and upstream evaluation.
- [x] Add a pool-canary build option that preserves NGINX pool allocation while
  detecting small pool allocation tail corruption.
- [x] Run first `nginx/1.31.0` comparison pass because public poolslip
  references disagree on whether the demo target is `1.31.0` or `1.31.1`.
- [x] Run a static-dangerous-API scan and triage remote-relevant hits.
- [x] Run `scan-build` and CodeQL over the current source tree and triage
  memory-safety-looking reports against source control flow.
- [x] Confirm one additional source-fixed HTTP/2 bug:
  `proxy_set_body $request_body` with `proxy_http_version 2` can corrupt the
  upstream HTTP/2 frame stream for request bodies larger than 16 MiB in the
  pre-fix parent of `c24fb259d`.
- [x] Add an ASAN + `NGX_DEBUG_PALLOC` build mode so small NGINX pool
  allocations are individually redzoned instead of hidden inside large pool
  blocks.
- [x] Add and test a default-module subrequest/filter route set covering SSI,
  mirror, and shared-memory limit modules on both `1.31.1` and `1.31.0`
  debug-palloc ASAN images.
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
- [x] Build ASAN + `NGX_DEBUG_PALLOC` container for pool-overwrite detection.
- [x] Verify the latest pool-canary/auth image still reports
  `Server: nginx/1.31.1`.
- [x] Record baseline clean runs for existing probes:
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
- [x] Default subrequest/filter modules:
  - SSI include/conditional parser with proxied length and chunked bodies.
  - mirror subrequests with preserved request body.
  - `limit_req` / `limit_conn` key handling and shared-memory boundaries.
- [ ] Default-module diff review around `1.31.0 -> 1.31.1` and nearby commits
  for newly introduced pool, parser, or filter behavior.
- [x] New default-module pass:
  - `ngx_http_tunnel_module`
  - `ngx_http_upstream_sticky_module`
  - `ngx_http_upstream_least_time_module`
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
- [x] Re-run highest-value parser/lifecycle fuzzers under the pool-canary ASAN
  build.
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

### 5. Current Source-Audit Focus

- [x] `ngx_http_tunnel_module`: reviewed request-controlled CONNECT authority
  handling, dynamic `tunnel_pass` evaluation, and upstream upgrade setup. The
  code path is small and no unchecked copy or response-visible pointer sink was
  identified in this pass. Existing ASAN probes also produced only clean
  `400`/`405`/tunnel boundaries.
  - [x] Added live coverage for the no-argument `tunnel_pass;` mode where
    NGINX derives the upstream from `$host:$request_port`.
- [x] `ngx_http_upstream_sticky_module`: reviewed session ID storage and
  shared-memory learn-mode updates. The fixed `sid[32]` node copy is protected
  by upstream peer IDs bounded to `NGX_HTTP_UPSTREAM_SID_LEN`; tested dynamic
  cookie/samesite/session inputs did not produce a sanitizer finding.
- [x] `ngx_http_upstream_least_time_module`: reviewed peer selection, inflight
  accounting, backup recursion, and sticky SID interaction. The recursive call
  passes the address of the first embedded field, so the cast back to the
  containing peer-data struct is intentional; no memory-safety candidate found
  in this pass.
- [ ] Continue source-guided pass on request-body discard/lingering close and
  range/static body filters with debug-palloc ASAN coverage.
  - [x] Static `Range` body-filter probe rejected the first
    request-controlled offset/copy hypotheses under pool-canary ASAN.
- [ ] Continue source-guided pass on cache-enabled upstream finalization and
  internal resolver SRV-name resolution because these are the only remaining
  clang-analyzer reports with non-trivial control-flow questions.
  - [x] Cache-enabled upstream finalization live repro rejected under ASAN.
  - [x] Resolver SRV `NGX_NO_RESOLVER` path source-rejected for valid
    upstream-zone resolution.
- [ ] Implement a remote-only allocator/pool metadata oracle harness that does
  not assume LFI, procfs, coredumps, or debugger access. The first version
  should classify only HTTP status, connection close/reset, worker recovery
  timing, and response-shape differences.

## Instrumentation Notes

Plain ASAN is weaker than it looks for NGINX request-pool bugs because small
`ngx_palloc()` allocations normally live inside a larger pool allocation. An
overwrite from one pool object into the next can stay inside the same ASAN
allocation and avoid a redzone. The `NGX_DEBUG_PALLOC` build mode disables
small-pool allocation for `ngx_palloc()`/`ngx_pnalloc()` and routes those
allocations through `ngx_palloc_large()`, giving ASAN separate allocations and
redzones for the objects most relevant to pool-corruption hypotheses.

## Milestone Log

- 2026-05-21: Created this defensive audit plan. Current phase is bug
  discovery and characterization: source audit, crash reproduction, leak
  identification, and mitigation-grade evidence. Exploit-chain work is
  intentionally deferred until there is a concrete bug to study.
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
- 2026-05-21: Confirmed the active no-gzip ASAN/debug-palloc audit container
  reports `nginx/1.31.1`, clang `18.1.3`, and configure arguments:
  `--builddir=build --with-cc=clang --with-cc-opt='-O1 -g
  -fno-omit-frame-pointer -fsanitize=address -DNGX_DEBUG_PALLOC'
  --with-ld-opt=-fsanitize=address --without-http_gzip_module`.
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
- 2026-05-21: Raw HTTP mutation fuzzer completed 3,000 iterations against
  `nginx-poolslip-1311-amd64-asan-debugpalloc-subreq` with ASAN clean and
  worker health stable. Expected parser boundaries included clean `400`
  responses and short-body timeouts; no crash, sanitizer report, or
  response-visible memory disclosure was observed.
- 2026-05-21: Added `tools/poolslip_tunnel_lifecycle_probe.py` and ran it
  against `127.0.0.1:19343`. The probe targets CONNECT upgrade boundaries,
  `Content-Length`, chunked bodies, `Expect: 100-continue`, split headers, and
  tunneled bytes sent after `200`. Result: 12/12 cases clean, ASAN delta `0`,
  worker health stable. This does not prove the tunnel module safe, but it
  closes the first direct lifecycle-corruption hypothesis.
- 2026-05-21: Source-audited the clang analyzer's FastCGI/SCGI/UWSGI duplicate
  header reports. They are source-triaged as false positives: duplicate request
  headers imply `r->headers_in.multi = 1` in `ngx_http_link_multi_headers()`,
  and the upstream parameter builders allocate the `ignored` array when
  `params->number || r->headers_in.multi` is true.
- 2026-05-21: Source-audited the request-body analyzer report at
  `ngx_http_request_body.c:1367`. The reported `rb->temp_file == NULL` deref
  path is blocked by `ngx_http_write_request_body()`, which assigns
  `rb->temp_file` before the reported `last_saved`/file-offset path is reached
  when `request_body_in_file_only` is active.
- 2026-05-21: Source-audited the resolver AAAA second-pass analyzer report.
  The mixed A/AAAA path reaches the second address-copy pass only after the
  first pass validates the response type against the query type; unexpected
  AAAA answers for an A query go to the invalid-response path before allocation
  and copy.
- 2026-05-21: CodeQL completed successfully on an arm64 host build of the same
  source tree. It produced 283 results, dominated by maintainability/style
  rules. The only security-severity result is command-line path injection in
  log-file opening, not a remote HTTP memory-safety candidate. No CodeQL result
  currently outranks the clang analyzer control-flow leads above.
- 2026-05-21: HTTP/2 upstream parser probe completed 96 iterations against the
  `proxy_http_version 2` ASAN lab with ASAN clean. This is useful coverage for
  source-fixed H2 issues, but the visible poolslip video build does not show
  `--with-http_v2_module`, so H2 remains a secondary surface for this track.
- 2026-05-21: Added `tools/poolslip_cache_finalize_probe.py` and a
  cache-enabled `/cache-lab` route. Built and ran an x86_64 ASAN/debug-palloc
  image on `127.0.0.1:19344`; verified `uname -m` reports `x86_64` and NGINX
  reports `nginx/1.31.1`. Cache fill, `HEAD`, intercepted cached `404`/`500`,
  truncated upstream body, and `204` all kept the worker healthy with ASAN
  delta `0`. This rejects the scan-build upstream-cache finalization report for
  the standard proxy path.
- 2026-05-21: Source-rejected the remaining resolver SRV clang-analyzer report.
  The public HTTP upstream-zone resolver timer checks `NGX_NO_RESOLVER` before
  setting `ctx->service` and before any SRV query is created. The internal SRV
  child-name loop only runs after an SRV response has been received through a
  resolver with configured connections, so the reported `cctx == NGX_NO_RESOLVER`
  dereference is not reachable through a valid remote DNS answer in this path.
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
- 2026-05-21: Ran `flawfinder --minlevel=3` over
  `/tmp/nginx-rift-nginx-src-1311/src/http` and `src/core`. The high-severity
  output is dominated by local filesystem TOCTOU patterns in file/cache/DAV
  code and one optional XSLT formatting warning. No result from this pass is a
  credible unauthenticated HTTP memory-safety candidate in the demo-like
  no-H2/no-MP4/no-DAV build profile.
- 2026-05-21: Public web triage of the poolslip teaser found only a repost of
  the Nebusec claim: "nginx-poolslip" is described as an unreleased NGINX
  1.31.x RCE with technical details held for 30 days. It does not disclose a
  trigger, affected module, request shape, or patch commit. Because public
  references disagree between `1.31.0` and `1.31.1`, the lab now tests both.
- 2026-05-21: Ran the existing HTTP-only probe set against the
  `nginx/1.31.0` ASAN comparison image at `127.0.0.1:19350`:
  - `tools/no_lfi_http_module_probe.py --target 127.0.0.1:19350`
  - `tools/poolslip_header_sink_probe.py --target 127.0.0.1:19350`
  - `tools/poolslip_large_header_matrix.py --target 127.0.0.1:19350`
  - `tools/poolslip_body_state_probe.py --target 127.0.0.1:19350 --timeout 8`
  These stayed clean: expected `200`, `206`, `400`, `416`, and `502`
  boundaries; no pointer-looking response bytes; health stayed up.
- 2026-05-21: Ran
  `tools/poolslip_request_sequence_fuzzer.py --target 127.0.0.1:19350
  --iterations 750 --seed 1310 --timeout 4 --container
  nginx-poolslip-1310-amd64-asan --stop-on-suspicious`. Result:
  `summary suspicious=0 iterations=750`, `asan_log_bytes 0`, `asan_status
  clean`. Case mix covered client framing, large headers, pipelining, chunked
  discard/body paths, rewrite edge cases, CONNECT/tunnel traffic, and upstream
  edge routes. This rules out the same broad allocator/request-lifecycle
  hypotheses on the `1.31.0` comparison build as well.
- 2026-05-21: Started but intentionally interrupted a generated upstream
  response fuzz run against `1.31.0` because several expected timeout cases
  made it low-yield. Earlier fixed-case upstream parser coverage against both
  `1.31.0` and `1.31.1` remains clean; next upstream work should use shorter
  transcript-specific probes or minimizers rather than another broad timeout-
  heavy random campaign.
- 2026-05-21: Added `tools/poolslip_raw_http_mutation_fuzzer.py`, a
  transport-level fuzzer for malformed HTTP/1.x request lines, CONNECT targets,
  large and folded headers, chunked/body mismatches, binary-ish header values,
  and pipelined follow-up requests. Live ASAN runs:
  - `tools/poolslip_raw_http_mutation_fuzzer.py --target 127.0.0.1:19341
    --iterations 3000 --seed 20260521 --timeout 0.35 --container
    nginx-poolslip-1311-amd64-asan --log-every 250 --stop-on-suspicious`
    produced `summary suspicious=0 iterations=3000`, `asan_log_bytes 0`,
    `asan_status clean`.
  - `tools/poolslip_raw_http_mutation_fuzzer.py --target 127.0.0.1:19350
    --iterations 3000 --seed 20261310 --timeout 0.35 --container
    nginx-poolslip-1310-amd64-asan --log-every 250 --stop-on-suspicious`
    produced `summary suspicious=0 iterations=3000`, `asan_log_bytes 0`,
    `asan_status clean`.
  This is negative evidence for generic request-line/header/body parser memory
  safety on both checked versions, but it is still broad fuzzing and not a
  replacement for source-guided module-specific probes.
- 2026-05-21: Ran longer ordinary-ASAN raw HTTP mutation campaigns:
  - `tools/poolslip_raw_http_mutation_fuzzer.py --target 127.0.0.1:19341
    --iterations 20000 --seed 2026052101 --timeout 0.35 --container
    nginx-poolslip-1311-amd64-asan --log-every 1000 --stop-on-suspicious`
    produced `summary suspicious=0 iterations=20000`, `asan_log_bytes 0`,
    `asan_status clean`.
  - `tools/poolslip_raw_http_mutation_fuzzer.py --target 127.0.0.1:19350
    --iterations 20000 --seed 2026052102 --timeout 0.35 --container
    nginx-poolslip-1310-amd64-asan --log-every 1000 --stop-on-suspicious`
    produced `summary suspicious=0 iterations=20000`, `asan_log_bytes 0`,
    `asan_status clean`.
- 2026-05-21: Re-ran the existing charset OOB proof in the current lab as a
  concrete confirmed-bug baseline. Commands:
  - `tools/charset_oob_probe.py 127.0.0.1:19321 --runs 8 --framing chunked`
    returned `88 0a 58` on every run.
  - `tools/charset_oob_probe.py 127.0.0.1:19321 --runs 4 --framing close`
    returned `88 00 58` on every run.
  - `tools/charset_oob_probe.py 127.0.0.1:19321 --runs 4 --framing length`
    returned `88 00 58` on every run.
  This confirms the fixed CVE-2026-42934 class is real and client-visible, but
  the leaked byte remains framing/slack (`0a` or `00`) rather than an ASLR-useful
  heap/libc/code pointer in this harness.
- 2026-05-21: Confirmed another fixed bug from the nearby HTTP/2 source-fix
  set: commit `c24fb259d` changes `proxy_set_body $request_body` handling for
  `proxy_http_version 2` so large request bodies are passed through the normal
  body-output path instead of being emitted as one oversized DATA frame.
  The vulnerable parent (`2046b45aa`) was built as
  `nginx-h2-setbody-prepatch-amd64-asan` and exposed on `127.0.0.1:19363`.
  `tools/proxy_v2_set_body_probe.py --target 127.0.0.1:19363 --size 16777216`
  produced `parse=truncated` with a single DATA frame length of `0`, showing
  the 24-bit length wrap and raw unframed stream bytes after the frame.
  `--size 16777217` produced a single DATA frame length of `1`, and
  `--size 17825792` produced a single DATA frame length of `1048576` plus
  downstream parse desynchronization. The fixed comparison image on
  `127.0.0.1:19361` fragmented all tested bodies into DATA frames no larger
  than `16384` and parsed cleanly. This is an HTTP/2-enabled-build bug, not the
  Poolslip default-module demo bug, but it is a concrete remote-triggered
  protocol corruption/injection issue from the current source-fix set.
- 2026-05-21: Added `DEBUG_PALLOC=1` support to `env/Dockerfile.poolslip` and
  built `nginx-poolslip-1311-amd64-asan-debugpalloc` from
  `eff110885412737aec9b953067b6a670bffdbfa0` with
  `-fsanitize=address -DNGX_DEBUG_PALLOC`. The image reports
  `Server: nginx/1.31.1` on `127.0.0.1:19342`.
- 2026-05-21: Replayed the focused probe suite against the ASAN +
  `NGX_DEBUG_PALLOC` image on `127.0.0.1:19342`:
  - `tools/no_lfi_http_module_probe.py`
  - `tools/poolslip_header_sink_probe.py`
  - `tools/poolslip_large_header_matrix.py`
  - `tools/poolslip_tunnel_probe.py`
  - `tools/poolslip_sticky_probe.py --timeout 5`
  - `tools/poolslip_upstream_parser_probe.py`
  - `tools/poolslip_body_state_probe.py --timeout 8`
  Results stayed clean: expected protocol/status boundaries, worker health up,
  and no ASAN report in Docker logs.
- 2026-05-21: Ran the broader fuzzers against the ASAN + `NGX_DEBUG_PALLOC`
  image:
  - `tools/poolslip_raw_http_mutation_fuzzer.py --target 127.0.0.1:19342
    --iterations 10000 --seed 61616161 --timeout 0.35 --container
    nginx-poolslip-1311-amd64-asan-debugpalloc --log-every 1000
    --stop-on-suspicious` produced `summary suspicious=0 iterations=10000`,
    `asan_log_bytes 0`, `asan_status clean`.
  - `tools/poolslip_request_sequence_fuzzer.py --target 127.0.0.1:19342
    --iterations 1000 --seed 42424242 --timeout 4 --container
    nginx-poolslip-1311-amd64-asan-debugpalloc --stop-on-suspicious` produced
    `summary suspicious=0 iterations=1000`, `asan_log_bytes 0`, `asan_status
    clean`.
  - `tools/poolslip_upstream_response_fuzzer.py --target 127.0.0.1:19342
    --iterations 1000 --seed 51515151 --timeout 5 --container
    nginx-poolslip-1311-amd64-asan-debugpalloc --stop-on-suspicious` produced
    `summary suspicious=0 iterations=1000`, `asan_log_bytes 0`, `asan_status
    clean`.
  This is stronger negative evidence than previous ordinary-ASAN runs for
  simple pool-adjacent overwrites in the covered surfaces, because small
  request-pool allocations now have ASAN redzones. It still does not rule out
  logic-only corruption, uninstrumented shared-memory/slab issues, or module
  paths not represented in the current lab configuration.
- 2026-05-21: Built the same ASAN + `NGX_DEBUG_PALLOC` comparison image for
  `release-1.31.0` as `nginx-poolslip-1310-amd64-asan-debugpalloc`, exposed on
  `127.0.0.1:19352`. It reports `Server: nginx/1.31.0`.
- 2026-05-21: Ran the 1.31.0 debug-palloc comparison through:
  - `tools/no_lfi_http_module_probe.py --target 127.0.0.1:19352`
  - `tools/poolslip_large_header_matrix.py --target 127.0.0.1:19352`
  - `tools/poolslip_raw_http_mutation_fuzzer.py --target 127.0.0.1:19352
    --iterations 10000 --seed 71717171 --timeout 0.35 --container
    nginx-poolslip-1310-amd64-asan-debugpalloc --log-every 1000
    --stop-on-suspicious`
  - `tools/poolslip_request_sequence_fuzzer.py --target 127.0.0.1:19352
    --iterations 1000 --seed 81818181 --timeout 4 --container
    nginx-poolslip-1310-amd64-asan-debugpalloc --stop-on-suspicious`
  Results: raw fuzzer `summary suspicious=0 iterations=10000`, sequence fuzzer
  `summary suspicious=0 iterations=1000`, both with `asan_log_bytes 0` and
  `asan_status clean`. This gives the same pool-redzone coverage to the older
  public-hint comparison target.
- 2026-05-21: Added a sharper HTTP/2 response-special-header lab route,
  `/h2-header-pass-special`, plus `tools/h2_header_overflow_probe.py`. The
  route passes upstream `Date` and `Server` headers through so the fixed
  `Content-Type`/`Location` response-header length bug from `58a7bc340` is less
  masked by generated header Huffman slack. A long single case against
  `release-1.31.0` (`huge-content-type`, size `2097279`, fill `~`,
  pass-through special headers) timed out client-side after 60 seconds, but the
  worker stayed healthy and Docker logs contained no ASAN report. This did not
  produce a crash proof.
- 2026-05-21: Added default-module subrequest/filter lab routes to
  `env/nginx-poolslip.conf`:
  `/ssi-proxy`, `/mirror-spray`, `/mirror-target`, `/limit-req-lab`, and
  `/limit-conn-lab`. Added backend `case=ssi-gen` to generate SSI include,
  conditional, long-param, unterminated, and split-token bodies with length or
  chunked upstream framing. Added
  `tools/poolslip_subrequest_filter_probe.py` to drive these paths.
- 2026-05-21: Built and ran `nginx-poolslip-1311-amd64-asan-debugpalloc-subreq`
  on `127.0.0.1:19343`. The subrequest/filter probe completed 22 cases:
  SSI length/chunked cases, mirror POST bodies up to 65535 bytes, and
  `limit_req` keys up to the request-line limit. Result:
  `summary suspicious=0 cases=22`, `asan_log_bytes 0`, `asan_status clean`.
- 2026-05-21: Repeated the same subrequest/filter route set and probe against
  `release-1.31.0` as
  `nginx-poolslip-1310-amd64-asan-debugpalloc-subreq` on `127.0.0.1:19353`.
  Result: `summary suspicious=0 cases=22`, `asan_log_bytes 0`,
  `asan_status clean`. This narrows the easy SSI/mirror/limit-module theories
  but does not close deeper request-body lifecycle or static/range filter
  hypotheses.
- 2026-05-21: Extended `tools/poolslip_body_state_probe.py` with optional
  Docker ASAN log detection and additional `Content-Length` short/zero-body
  pipeline, `Expect: 100-continue`, and post-chunked large-followup cases.
  Ran it against `nginx-poolslip-1311-amd64-asan-debugpalloc-subreq`
  (`127.0.0.1:19343`) and
  `nginx-poolslip-1310-amd64-asan-debugpalloc-subreq`
  (`127.0.0.1:19353`). Both runs produced
  `summary suspicious=0 cases=19`, `asan_log_bytes 0`, and
  `asan_status clean`.
- 2026-05-21: Integrated read-only parallel audit feedback. The strongest
  remaining Poolslip hypothesis is not a passive header/body pointer leak, but
  a remote allocator or request-pool metadata oracle: corrupt or stress
  `ngx_pool_t`, cleanup-list, large-header, or response-buffer metadata and
  recover heap layout through response/crash/survival differences. Source
  regions to prioritize next: `ngx_palloc_small()` / `ngx_palloc_block()`,
  request cleanup walk, large-header keepalive reuse, final header filter
  copying of `ngx_table_elt_t.value`, and range/body write filters copying
  `ngx_buf_t.pos..last`.
- 2026-05-21: Completed the outstanding debug-palloc upstream-response fuzzer
  run:
  `tools/poolslip_upstream_response_fuzzer.py --target 127.0.0.1:19343
  --container nginx-poolslip-1311-amd64-asan-debugpalloc-subreq --iterations
  1500 --seed 3233104 --timeout 5 --stop-on-suspicious`. Result:
  `summary suspicious=0 iterations=1500`, `asan_log_bytes 0`,
  `asan_status clean`. Case mix covered valid responses, split and invalid
  status lines, early hints, heavy headers, malformed headers, chunked edge
  cases, trailers, and truncated bodies.
- 2026-05-21: Added `POOL_CANARY=1` support to `env/Dockerfile.poolslip`.
  The patch (`env/patches/nginx_pool_canary.patch`) instruments small
  `ngx_palloc()`/`ngx_pnalloc()` allocations with tail canaries while keeping
  them inside NGINX request/connection pools. This is intended to catch pool
  overwrites that ASAN may miss and that `NGX_DEBUG_PALLOC` can mask by moving
  allocations out to malloc.
- 2026-05-21: Built and started
  `nginx-poolslip-1311-amd64-asan-poolcanary` on `127.0.0.1:19345`.
  Smoke test returned `Server: nginx/1.31.1`; Docker logs were clean.
  Targeted pool-canary checks completed clean:
  - `tools/poolslip_body_state_probe.py --target 127.0.0.1:19345
    --container nginx-poolslip-1311-amd64-asan-poolcanary --timeout 8`
    produced `summary suspicious=0 cases=19`, `asan_log_bytes 0`,
    `asan_status clean`.
  - `tools/poolslip_tunnel_lifecycle_probe.py --target 127.0.0.1:19345
    --container nginx-poolslip-1311-amd64-asan-poolcanary --timeout 6`
    produced `summary suspicious=0 cases=12`, `asan_log_bytes 0`,
    `asan_status clean`.
  - `tools/poolslip_upstream_parser_probe.py --target 127.0.0.1:19345
    --timeout 6` completed `summary suspicious=0 cases=32`; follow-up Docker
    log grep found no `pool canary`, ASAN, UBSAN, runtime, or abort markers.
- 2026-05-21: Ran the pool-canary request-sequence fuzzer:
  `tools/poolslip_request_sequence_fuzzer.py --target 127.0.0.1:19345
  --iterations 1000 --seed 91919191 --timeout 4 --container
  nginx-poolslip-1311-amd64-asan-poolcanary --stop-on-suspicious`.
  Result: `summary suspicious=0 iterations=1000`, `asan_log_bytes 0`,
  `asan_status clean`. Case mix covered large headers, invalid framing,
  chunked discard, proxy body handling, rewrite edges, tunnel CONNECT, and
  upstream response edges. This is negative evidence for simple pool-local tail
  overwrites in the exercised request parser/lifecycle paths.
- 2026-05-21: Harvested background read-only audit feedback and tightened the
  next hunt direction. The most plausible remaining Poolslip shape still needs
  a real corruption primitive first; once present, the likely remote sinks are
  `ngx_table_elt_t.value` in the final/early-hints/trailer header filters and
  `ngx_buf_t.pos..last` in body/range output. The njs proxy-overflow side
  review produced a liveness oracle only, not a direct pointer disclosure, so
  it is not counted as a Poolslip finding.
- 2026-05-21: Ran the pool-canary raw HTTP mutation fuzzer:
  `tools/poolslip_raw_http_mutation_fuzzer.py --target 127.0.0.1:19345
  --iterations 3000 --seed 93939393 --timeout 0.35 --container
  nginx-poolslip-1311-amd64-asan-poolcanary --log-every 500
  --stop-on-suspicious`. Result: `summary suspicious=0 iterations=3000`,
  `asan_log_bytes 0`, `asan_status clean`. This run adds parser-level
  mutation coverage under the pool-canary build and did not expose a crash,
  canary overwrite, or response disclosure.
- 2026-05-21: Completed the pool-canary upstream-response fuzzer run:
  `tools/poolslip_upstream_response_fuzzer.py --target 127.0.0.1:19345
  --iterations 500 --seed 92929292 --timeout 5 --container
  nginx-poolslip-1311-amd64-asan-poolcanary --stop-on-suspicious`. Result:
  `summary suspicious=0 iterations=500`, `asan_log_bytes 0`,
  `asan_status clean`. Case mix covered chunk extensions, chunk-size overflow,
  early hints, heavy and malformed headers, invalid and split status lines,
  trailers, truncated upstream bodies, and valid controls.
- 2026-05-21: Built
  `nginx-poolslip-1311-amd64-asan-ubsan-poolcanary-auth` with
  `-fsanitize=address,undefined -DNGX_POOL_CANARY`, exposed it on
  `127.0.0.1:19346`, and verified `GET /` returns `Server: nginx/1.31.1`.
  Added `tools/poolslip_connect_auth_probe.py` plus an
  `auth.tunnel.local` virtual server using `auth_basic`,
  `auth_basic_user_file`, and `tunnel_pass` on the same listener.
  The probe covered missing auth, `Authorization` vs `Proxy-Authorization`,
  invalid scheme/base64, valid auth, body-after-CONNECT, long user/password,
  binary user, duplicate proxy auth, `Proxy-Connection`, split request bytes,
  and an unauthenticated tunnel control. Result:
  `summary suspicious=0 cases=13`, worker health stable, and no ASAN or
  pool-canary finding.
- 2026-05-21: Triage note from the auth image: NGINX's file error log captured
  UBSAN diagnostics that the initial probe did not read from Docker stdout.
  The recurring `ngx_output_chain()` function-pointer-type report is the known
  sanitizer compatibility issue in the HTTP filter callback chain. A
  `ngx_string.c:586` null-argument warning appears on a zero-length string
  formatting path after declined auth; source review shows this is consistent
  with a zero-length `ngx_str_t` reaching `%V` formatting and causing UBSAN to
  complain about `memcpy(dst, NULL, 0)`. It is a sanitizer-cleanliness issue,
  not memory disclosure or corruption evidence, but future probes should read
  both Docker stdout and `/app/logs/error.log` so sanitizer findings are not
  missed.
- 2026-05-21: Added `tools/poolslip_range_filter_probe.py` for the static file
  range/body-filter sink (`ngx_buf_t.pos..last` and file offsets). Ran it
  against `nginx-poolslip-1311-amd64-asan-poolcanary` at
  `127.0.0.1:19345`. The probe covered baseline static output, single ranges,
  suffix/open-ended ranges, unsatisfiable and overflow ranges, space-tolerant
  parsing, overlapping and many-part multipart ranges, invalid units/tokens,
  `If-Range`, `HEAD`, and keepalive pipelining. Result:
  `summary suspicious=0 cases=21`, `sanitizer_log_bytes 0`,
  `memsafety_status clean`, `ubsan_status clean`. No response-visible pointer
  material, ASAN hit, pool-canary hit, or worker-health loss was observed.
- 2026-05-21: Source-reviewed the CONNECT request-line path used by
  `tunnel_pass;`. The current target includes `a43c76b4e`, which adds
  `sw_port_start` and rejects `CONNECT host:` before normal request
  processing. Without that fix, request-line host validation could accept an
  empty port as `r->port = 0`; in the current tree it is rejected at parse time.
  The default dynamic tunnel route uses `$host:$request_port`, where
  `$request_port` allocates a 5-byte string and emits only ports in
  `1..65535`.
- 2026-05-21: Added a same-NGINX-listener dynamic tunnel vhost for
  `server_name 127.0.0.2` with no-argument `tunnel_pass;`, and changed the toy
  backend listener to `0.0.0.0:19323` so loopback `127.0.0.2:19323` is a real
  backend target inside the lab container. Built
  `nginx-poolslip-1311-amd64-asan-poolcanary-dyn`, exposed it on
  `127.0.0.1:19347`, and verified `GET /` with `Host: health.local` returns
  `Server: nginx/1.31.1`.
- 2026-05-21: Added and ran `tools/poolslip_dynamic_tunnel_probe.py --target
  127.0.0.1:19347 --container
  nginx-poolslip-1311-amd64-asan-poolcanary-dyn --timeout 6`. The probe
  covered valid dynamic tunnel selection, split request line, mismatched Host
  vs CONNECT authority, no-port and colon-without-port authorities,
  non-numeric/zero/oversized ports, trailing-dot IP host, userinfo-shaped
  authority, IPv6 authority forms, and body-before-tunnel. Result:
  `summary suspicious=0 cases=13`, `memsafety_status clean`,
  `ubsan_status clean`. Expected boundaries included `400` for invalid
  authority shapes, `405` for an IPv6 authority that did not select the
  dynamic tunnel vhost, and `500` for port zero; no crash, canary overwrite, or
  response-visible pointer material was observed.
- 2026-05-21: Extended `tools/poolslip_raw_http_mutation_fuzzer.py` so random
  CONNECT targets include the dynamic tunnel vhost (`127.0.0.2:19323`,
  no-port, and colon-without-port forms), and so sanitizer detection reads both
  Docker stdout and `/app/logs/error.log`. Ran it against the dynamic
  pool-canary image:
  `tools/poolslip_raw_http_mutation_fuzzer.py --target 127.0.0.1:19347
  --iterations 3000 --seed 104104104 --timeout 0.35 --container
  nginx-poolslip-1311-amd64-asan-poolcanary-dyn --log-every 500
  --stop-on-suspicious`. Result: `summary suspicious=0 iterations=3000`,
  `asan_status clean`. The large `asan_log_bytes` value in this run is normal
  NGINX error-log volume from rejected malformed requests; no ASAN, UBSAN,
  runtime, `ERROR:`, or pool-canary marker was present.
- 2026-05-21: Parallel CONNECT/tunnel/request-lifecycle source audit returned
  no concrete memory-safety candidate in `eff110885`. Rejected leads include
  colon-without-port CONNECT authorities, `$request_port` sizing, large-header
  relocation of `host_start`/`host_end`, body-before-upgrade handling in
  `ngx_http_tunnel_module`, surplus-body to pipelined-header copying, empty
  request-body temp-file finalization, and keepalive reuse of large buffers.
  These remain useful negative coverage for core Poolslip, but not findings.
- 2026-05-21: Separate njs track found a concrete fixed bug:
  `js_fetch_proxy` dynamic proxy URL credentials in njs `0.9.8` overflow fixed
  by upstream commit `2bf4601a`. This is not stock NGINX core Poolslip, but it
  is a real NGINX-family module memory-safety issue reachable through ordinary
  HTTP requests when a deployment uses request-controlled variables in
  `js_fetch_proxy` credentials. Details and repro are in
  `docs/NJS_FETCH_PROXY_CVE_2026_8711_AUDIT.md`.
- 2026-05-21: Response/filter/upstream/sticky source audit returned no
  concrete memory-safety candidate in `eff110885`. Rejected leads include
  upstream `Content-Type` charset underflow, split UTF-8 charset conversion,
  early-hints header reuse, trailer pass-through, range offset manipulation,
  SSI parser/subrequest state, sticky SID storage, and upstream-zone shared
  memory copies. The top historical leak-looking classes in this area are
  already fixed in the target commit.

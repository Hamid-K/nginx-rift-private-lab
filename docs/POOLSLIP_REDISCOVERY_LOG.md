# NGINX Poolslip Rediscovery Log

Started: 2026-05-20
Branch: `research/nginx-poolslip-rediscovery`

## Goal

Try to rediscover the vulnerability class hinted by the Nebusec demo, or find another NGINX 1.31.x vulnerability in the same broad area. The demo appears to use a remote heap-base oracle, then a heap-shaping step to leak the NGINX code base and spawn a reverse shell.

## Constraints

- Authorized local lab only.
- Keep work isolated on this branch.
- Track experiments and live results in markdown.
- For Vagrant, treat stock Ubuntu `kernel.yama.ptrace_scope=1` as the realistic baseline.
- Do not count `/proc/<worker>/mem` as a viable Vagrant coreless vector. Standard Ubuntu has `kernel.yama.ptrace_scope=1`, and weakening that setting is equivalent to changing the target security posture for the exploit.
- Prefer crash/leak classifiers and minimized harnesses over writing a weaponized public exploit for an undisclosed issue.

## Video Clues

Observed from the Nebusec X video:

- Target IP: `172.17.0.2`.
- Built NGINX: `nginx/1.31.1`.
- Build flags shown: `--with-cc-opt='-O1 -g -fno-omit-frame-pointer' --without-http_gzip_module`.
- Exploit command: `python3 exp.py 172.17.0.2`.
- First stage: `Probing remote heap ASLR base within 300 requests...`.
- Heap base appears to be recovered in chunks:
  - `0x000000000000...`
  - `0x0000006a0000**`
  - `0x0000466a0000^^^`
  - `0x003a466a0000++`
  - `0x5f3a46676000-----+++++++++++++++++++++`
- Second stage: `Leaking nginx code base with crazy heap feng shui...`.
- Printed code base: `0x5f3a0ad38000`.
- Reverse shell proof runs as `uid=1000(ubuntu)`.

Interpretation: the heap stage looks like a remote crash/success or response-difference oracle over page-aligned heap-base chunks, not a direct full pointer dump. The code-base stage likely uses heap shaping after the heap base is known.

## Vagrant Regression Notes

- `192.168.1.205:19321` assessed successfully with ASLR enabled.
- 2026-05-20 live check: Vagrant baseline has `kernel.yama.ptrace_scope=1` and `kernel.randomize_va_space=2`.
- Same-UID worker maps and libc reads work through LFI, but `/proc/<worker>/mem` is blocked at baseline.
- `nginx_rifter.py --exploit-method core --max-final-candidates 20` did not win in the capped Vagrant campaign.
- A one-time diagnostic lowering of `kernel.yama.ptrace_scope=0` immediately made `/proc/<worker>/mem` readable through the LFI endpoint. This confirmed why Docker proc-mem worked and Vagrant did not. The VM was restored to `ptrace_scope=1`, and this path is rejected for Vagrant/coreless work.
- Current rule: do not change Yama/ptrace policy for exploit viability tests. Any path requiring `ptrace_scope=0`, `CAP_SYS_PTRACE`, or a debugger on the target is disqualified for the standard-Ubuntu Vagrant claim.
- 2026-05-20 recorded Vagrant worker-respawn probe used only LFI-readable `/proc/<worker>/maps`: 3/3 controlled crashes produced replacement workers with stable master PID, NGINX writable image base, libc base, heap base, and stack base. Artifacts: `artifacts/vagrant_respawn_stability_20260520.cast` and `artifacts/vagrant_respawn_stability_20260520.gif`.
- 2026-05-20 added `tools/maps_only_bruteforce_exploit.py`, a prototype that uses only LFI maps/libc plus marker-file proof. It does not read `/proc/<worker>/mem`, parse core dumps, change ptrace policy, or use target-side debugger/shell data.
- 2026-05-20 recorded smoke run of the maps-only brute-force prototype against Vagrant. It profiled heap growth with delayed `/spray` bodies, selected only heap ranges, and exercised the first candidates without a proof hit. Artifacts: `artifacts/maps_only_bruteforce_smoke_20260520.cast` and `artifacts/maps_only_bruteforce_smoke_20260520.gif`.
- 2026-05-20 started a recorded 2,000-candidate maps-only Vagrant campaign over the highest observed heap extent, prioritizing address modulo 7 based on the original PoC/body-address pattern. Artifact in progress: `artifacts/maps_only_bruteforce_campaign1_20260520.cast`.
- 2026-05-20 stopped the first 2,000-candidate campaign early after identifying a sled-geometry issue: the prototype placed a complete fake cleanup plus command every 128 bytes, leaving many plausible body offsets uncovered. Partial artifacts: `artifacts/maps_only_bruteforce_campaign1_20260520.cast` and `artifacts/maps_only_bruteforce_campaign1_20260520.gif`.
- 2026-05-20 rebuilt the maps-only sled as dense fake cleanup records pointing to one shared command string. This keeps the input primitive identical but raises body coverage from roughly 31 fake cleanups to more than 120 per 4,000-byte body with the default 32-byte stride.
- 2026-05-20 recorded a dense-sled Vagrant smoke run under `ptrace_scope=1`. It selected heap ranges from LFI-readable maps, derived `system()` from LFI-read libc, exercised 20 candidates, and produced no marker proof as expected for a smoke cap. Artifacts: `artifacts/maps_only_dense_sled_smoke2_20260520.cast` and `artifacts/maps_only_dense_sled_smoke2_20260520.gif`.
- 2026-05-20 started a 6,000-candidate dense-sled Vagrant campaign under `ptrace_scope=1`, using only maps/libc LFI plus marker readback. Artifact in progress: `artifacts/maps_only_dense_sled_campaign1_20260520.cast`.
- 2026-05-20 built an amd64 Docker lab matching the Nebusec video profile closely: Ubuntu 24.04, NGINX `1.31.1`, clang `18.1.3`, `--with-cc-opt='-O1 -g -fno-omit-frame-pointer'`, and `--without-http_gzip_module`. It serves on `127.0.0.1:19331` and responds with `Server: nginx/1.31.1`. Verification artifacts: `artifacts/poolslip_1311_amd64_verify_20260520.cast` and `artifacts/poolslip_1311_amd64_verify_20260520.gif`.
- 2026-05-20 added `tools/no_lfi_heap_oracle_probe.py`, a crash/no-crash probe for the blog/video ASLR idea. It uses no file-read primitive at all: it sprays zeroed request bodies, partially overwrites the cleanup pointer, and treats a non-crashing worker as a possible mapped cleanup-list landing. Docker smoke over 20 low-byte candidates found no no-crash hit, which is expected for a small cap. Artifacts: `artifacts/no_lfi_heap_oracle_docker_smoke_20260520.cast` and `artifacts/no_lfi_heap_oracle_docker_smoke_20260520.gif`.
- 2026-05-20 added `tools/no_lfi_http_module_probe.py`, an HTTP-only probe suite for default-module source-audit leads. The Docker lab now exposes deterministic static content, a fixed-version rewrite/set route, and backend cases for malformed upstream charset headers, early hints, and chunked trailers. Recorded run against `nginx/1.31.1` produced no HTTP-visible leak/crash anomaly across range/static, upstream header/chunking, rewrite/set, and large-header keepalive probes. Artifacts: `artifacts/no_lfi_http_module_probe_20260520.cast` and `artifacts/no_lfi_http_module_probe_20260520.gif`.

## Current Brute-Force Design

The maps-only campaign is a practical substitute for target memory reads if the candidate space is small enough:

1. Use LFI to find a same-UID NGINX worker and read `/proc/<worker>/maps`.
2. Use LFI to read libc from disk and derive `system()`.
3. Profile request-body heap growth with delayed `/spray` bodies, then scan candidate addresses from heap mappings only.
4. Build a dense fake `ngx_pool_cleanup_t` sled in each request body. The current version stores the command once near the end of the body and points each candidate cleanup record at that shared command, avoiding the earlier low-density per-slot command layout.
5. Overwrite only the low two bytes of the victim pool cleanup pointer and use crash/respawn plus marker-file readback as the oracle.

This is not a memory leak. It is a bounded remote brute-force strategy using stable worker respawns and ordinary file-read-derived process maps.

Open risk: if the original cleanup pointer's high bytes do not point into a heap window containing one of the sled slots, this pass will only cause crashes and no marker proof. In that case, the next refinements are to scan additional address modulo classes, vary the sled phase/stride, and add a body-placement classifier that still uses only maps and response/crash behavior.

## No-LFI Crash Oracle Track

The DepthFirst write-up notes that stable master/worker respawn behavior could theoretically probe ASLR progressively by overwriting pointers byte by byte. The Nebusec video appears to operationalize this: it recovers heap-base chunks with a request budget of about 300, then uses heap shaping to derive the code base.

The first local probe for this track is deliberately minimal:

1. Spray zeroed POST bodies so any cleanup pointer that lands inside the body sees `handler = NULL` and `next = NULL`.
2. Partially overwrite the victim pool `cleanup` pointer with URI-safe low bytes.
3. Classify wrong guesses by crash/worker respawn and possible hits by no crash.

This is weaker than the LFI-maps strategy but more interesting for a no-file-read real-world exploit. Current limitation: on normal x86_64 layouts, heap address bytes often include URI-unsafe values. A pure progressive overwrite can only set bytes that survive URI escaping, so it may need a placement trick, alternate target pointer, or response-side oracle that does not require writing every heap byte literally.

## Working Hypotheses

1. Pool pointer oracle: an allocation/free/reuse path lets a request test whether a guessed heap address is mapped or has a pool-looking object.
2. Pool cleanup or large allocation misuse: corrupt or race a pool metadata field so a guessed pointer changes response/crash behavior.
3. Request-body/temp-file cleanup path: a pool cleanup object may be reachable with less setup than the Rift chain if another pool bug exists.
4. Header/body filter pool reuse: a stale pool buffer or chain link may disclose allocator-adjacent bytes under specific filter/module settings.
5. Their `--without-http_gzip_module` flag may remove noise or avoid a filter that masks a leak; it may also be incidental.

## Source Audit Notes

- Depthfirst's technical write-up explicitly points to stable master/worker layout and says ASLR could theoretically be probed by progressive pointer overwrites. The Vagrant maps-only respawn probe confirms this property in the current lab.
- Nebusec video frame review confirms the target identifies as `nginx/1.31.1`, built by clang `18.1.3 (1ubuntu1)`, with visible configure arguments limited to `--with-cc-opt='-O1 -g -fno-omit-frame-pointer' --without-http_gzip_module`. No `--with-http_v2_module`, `--with-http_ssl_module`, or `--with-http_mp4_module` flag is visible, so the first-pass audit prioritizes default HTTP modules rather than optional H2/SSL/MP4 paths.
- The official NGINX `origin/master` source currently resolves to commit `eff110885412737aec9b953067b6a670bffdbfa0`, matching `nginx/1.31.1`. There are no later upstream source commits in this local clone after that commit, so there is no public post-1.31.1 fix diff to work backward from.
- Official `1.31.1` contains the Rift fix in `src/http/ngx_http_script.c`: `ngx_http_script_regex_end_code()` resets `e->is_args = 0` before subsequent `set` complex-value evaluation. A straight reuse of the disclosed `rewrite` + `set` trigger should therefore not reproduce CVE-2026-42945 on unmodified official `1.31.1`.
- The video-like Docker build confirms the default/no-gzip module set includes `rewrite`, `proxy`, `fastcgi`, `uwsgi`, `scgi`, `charset`, `ssi`, `range`, `chunked`, `autoindex`, `userid`, `tunnel`, and `upstream_sticky`, but not HTTP/2, SSL, gzip, gunzip, MP4, or random_index. Newer/default modules `ngx_http_tunnel_module` and `ngx_http_upstream_sticky_module` are now on the audit list; first read found no immediate client-controlled pointer disclosure, but `tunnel_pass` is relevant to SSRF/open-proxy research when configured.
- Independent high-effort source audit reached the same negative result for official `1.31.1`: no convincing unpatched HTTP/1 default-module memory disclosure or pointer oracle matching the Nebusec heap/code-base demo. Best remaining candidates are response-shape/oracle paths in range/static and upstream parsing, but current code bounds range parsing, fixes charset split handling, guards malformed upstream charset parsing, rejects chunk-size overflow, and exposes pool pointer formatting only in logs rather than HTTP responses.
- CVE-2026-42934 charset OOB read remains the strongest disclosed "leak-looking" fix. Local Docker work reproduced a visible byte before the upstream buffer, but tested `chunked`, close-delimited, and content-length framings leaked stable framing/slack bytes (`0a` or `00`), not heap/libc/code pointers. The source bug is narrow: the vulnerable path adjusts `src` backward after completing a split UTF-8 sequence, giving a tiny pre-buffer read rather than a broad arbitrary read.
- CVE-2026-42946 upstream status-line parsing is a remote crash/excessive-allocation class. The fix restores parser state/backtracking for split invalid status lines in SCGI/UWSGI/proxy. It is useful as a denial/crash primitive but does not obviously send uninitialized process memory to the client.
- CVE-2026-40701 OCSP resolver cleanup is a connection-close UAF. It is potentially security-relevant in TLS deployments with stapling/resolver, but current review found no default client-visible pointer disclosure. Turning it into an ASLR leak would require a separate reuse/readout primitive.
- The post-1.31.0 HTTP/2 `Content-Type`/`Location` length fix documents an HPACK header-buffer underallocation for multi-megabyte special headers. The upstream commit itself notes no current NGINX module exposes reasonably large special `Content-Type`/`Location` values. It looks like a potential memory-corruption lead, not a practical ASLR leak, and the Nebusec video build flags do not show `--with-http_v2_module`.
- HTTP/2 unknown extension frames are skipped by `ngx_http_v2_state_skip()`; their payload is not intentionally retained as a request body object. The current Rift exploit's fake cleanup bytes are therefore still expected to come from held HTTP `/spray` request bodies, while the H2 connection mainly supplies a cleanup-bearing victim pool.

## Next Steps

1. Build/test an NGINX `1.31.1` lab matching the video flags.
2. Diff/audit NGINX `1.31.0` to `1.31.1` and nearby post-Rift commits for pool, request body, upstream, charset, range, slice, header, and cleanup changes.
3. Instrument source locally to find remote-visible address or mapped/unmapped oracles.
4. Build minimal crash/leak probes and record every meaningful milestone.

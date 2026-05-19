# Blog Hint ASLR Leak Research

Started: 2026-05-20
Branch: `research/blog-hint-aslr-leaks`

## Goal

Evaluate whether exploitation ideas hinted in the Depthfirst NGINX Rift write-up can produce an ASLR leak or an alternate RCE path beyond the current LFI plus `/proc/<worker>/mem` chain.

## Candidate Paths

1. Blind byte-wise probing from stable worker respawns.
2. CVE-2026-42934 charset out-of-bounds read as a possible memory disclosure.
3. Active response/header over-read by corrupting NGINX response metadata.
4. Other confirmed CVEs as auxiliary disclosure or control primitives.

## Initial Reading

The write-up explicitly notes that nginx worker processes are forked from a master, so failed attempts can crash a worker and the master can spawn a replacement with the same broad layout. It also mentions a theoretical ASLR approach using progressive byte-wise pointer overwrites. That is a crash/success oracle idea, not a direct memory leak.

The same write-up describes CVE-2026-42934 as an out-of-bounds read in `ngx_http_charset_module` that reads two bytes before an upstream buffer. This is the only other discussed issue that looks like a possible disclosure candidate rather than only a crash/control-flow issue.

## Rules

- Authorized local lab only.
- Do not count target-side shell, Docker exec, debugger output, or hardcoded live target bases as exploit oracle data.
- Docker exec and source inspection are allowed to understand and instrument hypotheses.
- Record live exploit milestones with asciinema and GIF if a candidate reaches command execution or a meaningful leak.

## Running Log

- 2026-05-20: Created branch and started source/test audit.
- 2026-05-20: Added a focused Docker harness for CVE-2026-42934. The harness keeps the vulnerable HTTP/2/LFI locations available, but adds `/charset/`, where NGINX proxies a chunked UTF-8 response and recodes it to `windows-1251`. The upstream deliberately splits a UTF-8 Euro sign over multiple chunks to exercise the out-of-bounds read described in the write-up.
- 2026-05-20: First charset run returned the original UTF-8 bytes (`e2 82 ac 58`) because the upstream response declared `charset=utf-8`, and NGINX declined to override that response charset. Source review confirmed `override_charset on;` is needed for this harness.
- 2026-05-20: With `override_charset on`, the harness reproduced a visible one-byte over-read: upstream `e2 | 82 | ac | 58` became client body `88 0a 58`. The first over-read byte was stable `0a`, which is likely adjacent chunked-transfer framing rather than a useful process pointer. Extended the backend to test `chunked`, close-delimited, and content-length upstream bodies.
- 2026-05-20: Framing comparison:
  - `chunked`: stable leaked byte `0a`, consistent with the byte before decoded chunk data.
  - `close`: stable leaked byte `00`.
  - `length`: stable leaked byte `00`.
  - 4-byte UTF-8 split tests returned replacement bytes (`3f 3f 58`) and did not produce a better disclosure primitive.
- 2026-05-20: Recorded live charset OOB proof: [cast](../artifacts/charset_oob_probe_20260520.cast), [gif](../artifacts/charset_oob_probe_20260520.gif).
- 2026-05-20: Adjusted the research backend to serve both the original delayed HTTP backend on `127.0.0.1:19323` and the charset OOB backend on `127.0.0.1:19325`. This keeps `/spray`, `/internal`, and the Rift crash/oracle path realistic while the charset harness is enabled.
- 2026-05-20: Added `tools/worker_respawn_stability_probe.py` to measure the blog's worker-respawn hint using only HTTP/LFI-readable `/proc/<pid>/maps` snapshots. It intentionally does not read `/proc/<pid>/mem` or crash cores.
- 2026-05-20: Live respawn measurement on Docker (`127.0.0.1:19321`) showed 3/3 controlled crashes, a stable master PID, stable NGINX writable image base, stable libc base, and stable stack base across replacement workers. Recorded proof: [cast](../artifacts/worker_respawn_stability_20260520.cast), [gif](../artifacts/worker_respawn_stability_20260520.gif).

## Interim Findings

### CVE-2026-42934 Charset OOB Read

The bug is reproducible in the Docker lab and produces client-visible bytes from before the current upstream buffer. Under the tested upstream framings, the disclosed bytes are stable but not ASLR-useful:

- chunked upstream bodies disclose `0a`, likely the line-feed byte immediately before chunk data after NGINX chunk parsing;
- close-delimited and content-length bodies disclose `00`, likely buffer slack/initialization near the streamed body buffer;
- tested split patterns did not expose heap, binary, libc, or stack-looking pointer bytes.

Current status: confirmed disclosure bug, but not yet a practical ASLR bypass for the NGINX Rift RCE chain.

### Worker Respawn Crash Oracle

The master/worker model does preserve broad address layout across worker crashes in the current lab. This makes the write-up's byte-wise probing idea plausible as an oracle primitive:

- a bad guess can crash one worker and the master respawns another;
- the replacement worker keeps the same mapped NGINX and libc bases in this lab;
- a stable base means guesses do not need to restart from zero after each crash.

Current status: useful for bounded brute-force campaigns, but not a complete ASLR bypass by itself. It still needs either a small candidate set, a stronger success oracle than "worker died", or a way to locate the live request body/cleanup slot without reading worker memory.

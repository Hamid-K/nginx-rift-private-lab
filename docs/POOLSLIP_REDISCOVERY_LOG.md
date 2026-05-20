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
- Do not count `/proc/<worker>/mem` as a viable Vagrant coreless vector unless the lab deliberately lowers `ptrace_scope`; that is a demo amplifier, not the standard Ubuntu path.
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
- Vagrant baseline has `kernel.yama.ptrace_scope=1`.
- Same-UID worker maps and libc reads work through LFI, but `/proc/<worker>/mem` is blocked at baseline.
- `nginx_rifter.py --exploit-method core --max-final-candidates 20` did not win in the capped Vagrant campaign.
- Lowering `kernel.yama.ptrace_scope=0` immediately made `/proc/<worker>/mem` readable through the LFI endpoint. This confirms why Docker proc-mem worked and Vagrant did not, but it is not a standard-Ubuntu solution.

## Working Hypotheses

1. Pool pointer oracle: an allocation/free/reuse path lets a request test whether a guessed heap address is mapped or has a pool-looking object.
2. Pool cleanup or large allocation misuse: corrupt or race a pool metadata field so a guessed pointer changes response/crash behavior.
3. Request-body/temp-file cleanup path: a pool cleanup object may be reachable with less setup than the Rift chain if another pool bug exists.
4. Header/body filter pool reuse: a stale pool buffer or chain link may disclose allocator-adjacent bytes under specific filter/module settings.
5. Their `--without-http_gzip_module` flag may remove noise or avoid a filter that masks a leak; it may also be incidental.

## Next Steps

1. Build/test an NGINX `1.31.1` lab matching the video flags.
2. Diff/audit NGINX `1.31.0` to `1.31.1` and nearby post-Rift commits for pool, request body, upstream, charset, range, slice, header, and cleanup changes.
3. Instrument source locally to find remote-visible address or mapped/unmapped oracles.
4. Build minimal crash/leak probes and record every meaningful milestone.

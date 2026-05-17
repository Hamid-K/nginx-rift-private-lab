# Coreless ASLR Bypass Research Log

## 2026-05-18

### Branch Setup

- Created branch `research/coreless-aslr-bypass` from commit `33d22d1`.
- Scope: find a coreless path for the NGINX Rift exploit chain.
- Started three workstreams:
  - NGINX source leak audit,
  - practical coreless brute-force measurement,
  - standard Ubuntu/nginx Docker local-file-read disclosure audit.

### Initial Constraints

- The prior working chain used an LFI-readable nginx worker core to recover live heap slots.
- This branch treats that core-read as out of scope for success.
- Standard `/proc/<pid>/maps` and binary reads are still in scope if standard permissions allow them from the web-app UID.
- Docker exec/debugger access may be used for research validation, but not as exploit input.

### Standard Procfs Memory Primitive

- Verified through the HTTP LFI endpoint, not Docker exec, that same-UID `/proc/<nginx-worker>/mem` can be read at mapped offsets in the current Docker lab:
  - `/proc/<worker>/maps` gives the mapped ranges,
  - `/proc/<worker>/mem` at the nginx image mapping returned the ELF header,
  - `/proc/<worker>/mem` at writable anonymous mappings returned live worker memory.
- Added `tools/lfi_proc_mem_scan.py` to scan worker writable mappings over LFI and identify nginx-pool-looking structures without reading crash cores.
- First scan result against `127.0.0.1:19321`:
  - worker PID `61`,
  - `/proc/61/mem` read succeeded,
  - found `32` pool-like structures in writable mappings.
- Added `tools/proc_mem_coreless_exploit.py`, an experimental coreless exploit path that sends the normal probe body, keeps the worker state live, scans `/proc/<worker>/mem` for nonce-marked fake-cleanup slots and pool cleanup windows, then tries recovered candidates after worker reset.
- First live-memory exploit attempt:
  - `/proc/<worker>/mem` sample succeeded,
  - live pool scan found `13` cleanup-like pools,
  - nonce slot scan found `0` slots,
  - no candidate was tried.
- Current interpretation: `/proc/<worker>/mem` is a credible replacement disclosure if the exact probe-body bytes are still resident and searchable at the right moment. The first timing did not capture those bytes, so the next step is to adjust probe timing and scan scope.

### Source Leak Audit Result

- A focused source audit of the local NGINX checkout at commit `98fc3bb78` found no credible direct memory-disclosure candidate that is remotely observable under default/non-debug behavior.
- Areas reviewed:
  - rewrite/script handling around the vulnerable copy path,
  - HTTP/2 frame generation and filter paths,
  - range and slice filters,
  - `$request_body` and `$request_body_file`,
  - upstream/proxy/FastCGI parsing,
  - `error_page` and internal redirects.
- Conclusion: the known rewrite issue is an overwrite primitive, not a direct leak. The reviewed response paths emit exact request/upstream/file/static bytes or fail closed. Debug logs contain pointer prints, but debug logging is not a default production leak.

### Coreless Proc-Mem Win

- Fixed the live-memory scanner to mirror the known-good core marker scanner.
- Changed the proc-mem exploit to use a full 6-byte overwrite after recovering full sprayed body addresses from live worker memory.
- This avoids needing the original cleanup pointer's high bytes:
  - the held probe writes the URI-safe bogus address `0x303030303030`,
  - the LFI reads `/proc/<nginx-worker>/mem` while the relevant body slots are still resident,
  - the scanner recovers full fake-cleanup slot addresses,
  - final candidates use a full 6-byte overwrite to point directly at a recovered slot.
- Successful Docker run:

```bash
timeout 300 python3 -u tools/proc_mem_coreless_exploit.py \
  --target 127.0.0.1:19321 \
  --cmd id \
  --target-len 6 \
  --max-region 268435456 \
  --max-final-candidates 5 \
  | tee artifacts/coreless_proc_mem_win_20260518.txt
```

- Observed:
  - `/proc/<worker>/mem` LFI sample succeeded,
  - recovered `115` URI-safe full-address slots out of `2485` live slots,
  - produced `115` cleanup-window matches,
  - final candidate 1 executed `id`,
  - output: `uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)`.
- This is coreless: it did not read or require `/app/tmp/core`.
- Practical brute-force note: after `/proc/<worker>/mem` narrows the candidate list to 115 full-address slots, the final stage is a bounded candidate campaign. In the successful run, candidate 1 won; the implemented cap was 5.

### Known-Offset Brute Force Check

- Tested the older no-core, no-proc-mem known-offset candidate path with full 6-byte overwrite:

```bash
./ctf_remote_exploit.py --host 127.0.0.1 --port 19321 \
  --target-len 6 --h2-victim --a-count 127 --plus-count 962 \
  --tries-per-candidate 1 --proof-delay 0.25 \
  --cmd 'id > /tmp/bruteforce_test' --verbose
```

- Result:
  - 5 URI-safe candidates from the static preread offset list,
  - all 5 disrupted the worker,
  - none produced proof.
- Conclusion: static known-offset brute force is not currently enough. The practical brute-force path needs a live disclosure to narrow candidates.

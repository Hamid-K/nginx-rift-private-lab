# Demo PoC Improvement Notes

Last updated: 2026-05-15 05:06:15 CEST

## Scope

The original working exploit path is preserved. The improved demo runners are separate files with minor-version suffixes:

- `demo_ctf_exploit_v1_1.py`
- `demo_ctf_exploit_v1_2.py`

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
  --host 192.168.1.205 --port 19321 \
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
  --host 192.168.1.205 --port 19321 \
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

## Recommended Demo Command

For video recording:

```bash
./demo_ctf_exploit_v1_2.py --host 192.168.1.205 --port 19321 --clear --require-reset-core
```

For a fast validation run:

```bash
./demo_ctf_exploit_v1_2.py --host 192.168.1.205 --port 19321 --fast --require-reset-core
```

## Remaining Technical Limits

- This still depends on readable crash cores as the strong memory-disclosure primitive.
- The same-port lab intentionally uses one nginx worker for reproducibility. Multiple production workers would require worker selection or more retry logic.
- The exploit is calibrated for the current lab nginx build, Ubuntu userspace, and HTTP/2 connection-pool layout.
- The chain is stronger than a hardcoded-offset demo because ASLR-sensitive bases and final heap candidates are derived remotely, but it remains a lab chain rather than a claim about default production exploitability.

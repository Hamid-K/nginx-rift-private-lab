# Known Layout Pattern Notes

Last updated: 2026-05-15 05:31:30 CEST

`known_layout_patterns.json` is a seed knowledge base for reliability work across nginx builds, Linux distributions, and lab configurations.

The rule for this project remains the same: the exploit runner must derive ASLR-sensitive values from live remote primitives. The pattern file is only for expected geometry, sanity ranges, and future triage. It should not become a replacement for reading target maps, hashing target binaries, and using reset-core candidates.

## Current Seed Entry

- `ubuntu-22.04.3-nginx-rift-http2-single-worker`
- Observed on the ESXi Vagrant lab at `<target-host>`.
- Uses HTTP/2 same-port victim behavior.
- v1.6 remote binary fingerprints:
  - nginx build ID `060e053ab1fa1a2876b7fe0ff4eff0cc777857b6`
  - nginx SHA-256 `14bebe8937678598b8ebb8449f8c155478a4c49894c9467ce51d54a79352f08f`
  - libc build ID `095c7ba148aeca81668091f718047078d57efddb`
  - libc SHA-256 `c53819710b163d3f1d2541778590d58d3ef31cb0ed75adcbe059faac68c1e72d`
- Uses `target_len=2`, `a_count=127`, `plus_count=962`.
- Observed reset-core slot total: `10437`.
- Observed URI-safe reset-core slot range in recent successful runs: `896..1204`.
- Observed corrupted/probe pool count: `1`.

## TODO

- Reconfirm v1.6 nginx/libc build IDs and SHA-256 fingerprints after repeated clean rebuilds.
- Add separate entries for Ubuntu 24.04 and Debian once validated on real x86_64 VMs.
- Track first-winning candidate index and candidate-count distributions by platform.
- Add explicit notes for multi-worker topologies once worker correlation has been tested outside the single-worker lab.

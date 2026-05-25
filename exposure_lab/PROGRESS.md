# Rift Exposure Lab Progress

## Plan

- [x] Create a dedicated folder for sanitized GitHub config simulation.
- [x] Add an anonymous block-level corpus format.
- [x] Add a Docker target that builds a vulnerable NGINX with ASAN and
  `NGX_DEBUG_PALLOC`.
- [x] Add a parallel Docker runner for local trigger verification.
- [x] Build a sanitized corpus from all available GitHub search candidates.
- [x] Run at least 10 Docker case tests in parallel.
- [x] Generate and review the markdown report.
- [ ] Commit the harness, corpus, generated configs, and report.

## Notes

- Stored corpus records omit repository names, owners, URLs, source paths, and
  raw public config snippets.
- Local testing verifies the vulnerable memory-corruption primitive, not full
  remote RCE against public targets.
- Full corpus run collected 3,820 deduplicated candidate file references from
  9,040 raw GitHub code-search hits and generated 129 publicish sanitized local
  cases with 80 unique sanitized semantic fingerprints.
- Full local Docker run tested all 129 cases with 10-way parallelism. Results:
  23 `asan_hit`, 106 `no_trigger`.

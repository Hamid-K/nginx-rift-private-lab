# Rift Exposure Lab

This folder turns the aggregate GitHub exposure survey into a local, sanitized
Docker test harness.

The corpus builder fetches public candidate NGINX configs, extracts only the
Rift-relevant directive semantics, and writes anonymous case records. It does
not store repository names, owners, URLs, paths, or raw public config snippets.

The local harness then generates synthetic NGINX configs that preserve the
dangerous shape:

- a `rewrite` directive whose replacement contains a query string marker
  (`?`)
- a same-location `set` directive that consumes numbered regex captures
  (`$1`..`$9`)

The test runner launches one Docker container per generated case and sends a
Rift trigger request. A positive result means the sanitized local case triggered
the vulnerable memory-corruption primitive under a vulnerable NGINX
ASAN/debug-palloc build. It is not, by itself, proof that a public repository is
deployed, internet reachable, running a vulnerable NGINX version, or remotely
RCE-exploitable.

## Workflow

Build the local target image:

```bash
docker build --platform linux/amd64 -t rift-exposure-nginx:asan exposure_lab
```

Build a sanitized corpus from GitHub code search:

```bash
python3 exposure_lab/tools/build_sanitized_corpus.py
```

Run local tests with ten containers in parallel:

```bash
python3 exposure_lab/tools/run_local_case_tests.py --parallel 10
```

For a quick smoke run:

```bash
python3 exposure_lab/tools/build_sanitized_corpus.py --sample 25
python3 exposure_lab/tools/run_local_case_tests.py --limit 10 --parallel 10
```

Generated outputs:

- `exposure_lab/corpus/cases.jsonl`
- `exposure_lab/corpus/summary.json`
- `exposure_lab/generated/case_*/nginx.conf`
- `exposure_lab/reports/local_test_report.md`
- `exposure_lab/reports/local_test_results.json`

## Current Corpus Snapshot

The committed run generated 129 sanitized publicish local cases from 3,820
deduplicated GitHub candidate references. The local Docker run tested all 129
cases with `--parallel 10` on an amd64 ASAN/debug-palloc NGINX image and
observed 23 ASAN heap-buffer-overflow hits.

Cases marked `no_trigger` are still useful for risk analysis: the static
ingredients were present in the same location block, but the generated
preserved-order simulation did not reach the vulnerable `rewrite` plus `set`
execution path. Common reasons include `set` appearing before the query-setting
`rewrite`, redirect-style rewrite flags, or generated routes returning a normal
HTTP response.

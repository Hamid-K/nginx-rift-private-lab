# Non-LFI Remote ASLR Bypass Log

This log tracks work on bypassing ASLR without LFI, phpinfo, procfs reads, readable cores, debugger access, or hardcoded live target bases.

## Research Question

Can the NGINX rewrite/set overflow be exploited on a realistic default-style deployment with the vulnerable rewrite configuration, using only remote HTTP behavior, by first leaking enough memory to derive process-specific ASLR state?

## Current Confidence

Not proven impossible.

The prior source audit did not find a credible default response path that passively prints NGINX or libc pointers. That is not a proof that no leak exists. The remaining realistic non-LFI path is likely an active leak gadget: use the overflow to corrupt a nearby response header/body structure so NGINX over-reads process memory into a normal HTTP response.

## Constraints

- No LFI or arbitrary file-read primitive.
- No `/proc/<pid>/maps`, `/proc/<pid>/mem`, core dumps, debugger, or target-side shell oracle.
- No hardcoded live ASLR base.
- Docker/debugger/local memory inspection is allowed only for clone-side research, not as final exploit oracle data.
- Live milestone tests must be recorded with asciinema and converted to GIF.

## Passive Leak Audit Notes

### `set $var ...$1` Reflection

The vulnerable script sequence is caused by `rewrite` leaving argument-escaping state active before a later `set` complex value copies a capture containing `+` bytes.

Relevant source behavior:

- `ngx_http_script_complex_value_code()` allocates `e->buf` using the length-code result, then immediately stores `e->sp->len = e->buf.len` and `e->sp->data = e->buf.data`.
- Later copy code can escape captures and write past the allocation.
- `ngx_http_script_set_var_code()` stores the already-pushed `e->sp->len` and `e->sp->data` into `r->variables[index]`.

Implication: common passive reflection sinks such as `return 200 "$original_endpoint"`, `add_header X "$original_endpoint"`, and upstream variables should use the under-calculated variable length, not the overflowed `e->pos`. That makes them poor direct memory disclosure candidates: they may expose attacker-controlled transformed data, but not adjacent heap bytes past the stored length.

### `rewrite ... redirect` / `Location`

`ngx_http_script_regex_end_code()` computes redirect `Location` length as `e->pos - e->buf.data` after copying. That can include bytes written beyond the allocation, but those bytes are still produced by the script copy operations from attacker-controlled request/capture data. This is not currently a pointer leak by itself.

### Error Responses

Default special responses use static buffers and fixed lengths. They do not include request URI, arguments, or internal pointers in the response body by default.

## Remaining Candidate Classes

| ID | Class | Idea | Status |
| --- | --- | --- | --- |
| P1 | Passive reflected variable | Reflect overflowed `$original_endpoint` via `return` or `add_header` | Tested: no leak observed |
| P2 | Passive redirect | Trigger overflow in redirect-like rewrite path and inspect `Location` | Tested: no leak observed |
| A1 | Active body over-read | Corrupt `ngx_buf_t.pos/last` or chain metadata of a live response to extend output | Open |
| A2 | Active header over-read | Corrupt `ngx_table_elt_t.value.len/data` for a header sent to client | Open |
| A3 | Upstream/proxy buffer over-read | Corrupt proxied response buffer metadata while backend response is pending | Open |
| B1 | Practical blind brute force | Use worker crash/restart behavior as oracle without a leak | Previously failed for static 5-candidate layout; wider bounded campaign still open |

## Next Tests

1. Instrument a clone worker to map heap adjacency around candidate victim objects and test active `ngx_buf_t` / header over-read corruption.
2. Build a non-LFI active leak probe if a response-buffer or header metadata target is plausible.
3. Revisit blind brute force with a measured crash/restart rate and a realistic candidate space.

## 2026-05-18 Passive Sink Harness

Added a no-LFI Docker harness:

- `env/nginx-nonlfi-leak-harness.conf`
- `env/docker-compose.nonlfi-leak.yml`

The harness keeps the vulnerable rewrite/set shape but exposes only normal HTTP response sinks:

- `/reflect_body/<payload>`: `return 200 "$original_endpoint\n"`
- `/reflect_header/<payload>`: `add_header X-Original "$original_endpoint" always`
- `/reflect_redirect/<payload>`: redirect `Location`

Added probe:

- `tools/non_lfi_leak_probe.py`

The probe sends remote HTTP requests only. It does not use LFI, phpinfo, procfs, cores, debugger, or local target files.

Recorded runs:

- initial raw probe:
  - cast: `artifacts/non_lfi_passive_leak_probe_20260518.cast`
  - gif: `artifacts/non_lfi_passive_leak_probe_20260518.gif`
- classified probe:
  - cast: `artifacts/non_lfi_passive_leak_probe_classified_20260518.cast`
  - gif: `artifacts/non_lfi_passive_leak_probe_classified_20260518.gif`

Classified result:

```text
summary: clean=9, reset=7, deviation=0, interesting=0
no passive memory disclosure observed
worker resets/crashes occurred, but did not return leaked bytes
```

Interpretation:

- `return` and `add_header` reflected deterministic attacker-controlled bytes when they returned a response.
- Higher overwrite pressure sometimes reset/crashed the worker before a response.
- Redirect `Location` remained printable attacker-derived data.
- No passive response contained pointer-like bytes or non-print memory.

This reduces confidence in passive reflected-variable leaks. It does not rule out active leak gadgets that corrupt response-buffer or header metadata.

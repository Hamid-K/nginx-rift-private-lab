# Static Analyzer Triage

Started: 2026-05-21  
Branch: `research/poolslip-defensive-source-audit`  
Source: `/tmp/nginx-rift-nginx-src` at `eff110885412737aec9b953067b6a670bffdbfa0`

## Summary

`scan-build` reported 23 findings. Most are local false positives, config-time
paths, or defensive-null-check patterns. The items below are the reports that
looked remotely relevant enough to source-triage or queue for live testing.

CodeQL completed on an arm64 host build and returned 283 findings. The result
set is not memory-safety useful for this target: mostly style/maintainability,
plus one command-line path-injection warning for log opening.

## Triage Table

| Report | Location | Analyzer Claim | Current Triage |
| --- | --- | --- | --- |
| `report-72b49a.html` | `src/http/ngx_http_request_body.c:1367` | `rb->temp_file` can be null when file-only body bookkeeping dereferences it. | Source-triaged false positive. `ngx_http_write_request_body()` creates and assigns `rb->temp_file` before the file-only path reaches offset bookkeeping. |
| `report-5f4414.html` | `src/http/modules/ngx_http_fastcgi_module.c:989` | Duplicate headers can write through a null `ignored` array. | Source-triaged false positive. `ngx_http_link_multi_headers()` sets `r->headers_in.multi = 1` when duplicate header links exist; FastCGI allocates `ignored` when `params->number || r->headers_in.multi`. |
| `report-61e809.html` | `src/http/modules/ngx_http_scgi_module.c:793` | Same duplicate-header/null-`ignored` pattern. | Same false-positive reason as FastCGI. |
| `report-c0d59d.html` | `src/http/modules/ngx_http_uwsgi_module.c:1004` | Same duplicate-header/null-`ignored` pattern. | Same false-positive reason as FastCGI. |
| `report-f1ac21.html` | `src/core/ngx_resolver.c:2377` | AAAA answer storage can be null in the second copy pass. | Source-triaged likely false positive. The first DNS answer pass rejects unexpected AAAA records for an A query before allocation and second-pass copy. |
| `report-2227c2.html` | `src/http/ngx_http_upstream.c:4877` | `r->cache != NULL` while `u->pipe == NULL` at upstream finalization. | Live-tested and rejected for the standard proxy path. `tools/poolslip_cache_finalize_probe.py` exercised cache fill, `HEAD`, intercepted cached `404`/`500`, truncated upstream body, and `204`; ASAN stayed clean. Source read also shows standard upstream modules allocate `u->pipe` before cached finalization, and `ngx_http_file_cache_free()` accepts a null temp-file pointer. |
| `report-0cf824.html` | `src/core/ngx_resolver.c:3012` | Internal SRV-name resolution may treat `NGX_NO_RESOLVER` as a real context. | Source-rejected for reachable HTTP upstream-zone SRV resolution. `ngx_http_upstream_zone_resolve_timer()` checks `ctx == NGX_NO_RESOLVER` before setting `ctx->service` or issuing the SRV lookup. The internal SRV child-name loop only runs after an SRV DNS response has been received by a resolver with configured connections; in that state `ngx_resolve_start(r, NULL)` cannot return `NGX_NO_RESOLVER` unless the resolver object is being torn down. |
| `report-aada45.html` | `src/http/modules/ngx_http_index_module.c:189` | `name` can be null when index path buffer is not reallocated. | Source-triaged likely false positive. Initial `allocated = 0`; valid static and variable index names require positive `reserve`, forcing `ngx_http_map_uri_to_path()` before `name` use. |
| `report-f99388.html` | `src/http/modules/ngx_http_index_module.c:176` | Unix API warning in the same index path. | Same index-path triage; no remote memory-safety candidate found. |

## Completed Live Tests

- Built a cache-enabled x86_64 ASAN/debug-palloc route and tested upstream
  finalization paths with cache fill, intercepted errors, header-only requests,
  truncated upstream body, and no-content responses. Result: ASAN clean, worker
  stable.

## Remaining Work

- Continue source-guided and sanitizer-backed hunting on default HTTP/1 module
  surfaces. The current static analyzer set no longer contains an actionable
  remote pre-auth memory-safety candidate.
- Re-run parser and lifecycle probes under the new pool-canary ASAN build to
  cover pool-local corruption that ordinary ASAN and debug-palloc can miss or
  perturb.

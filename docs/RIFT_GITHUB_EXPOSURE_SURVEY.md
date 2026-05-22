# NGINX Rift GitHub Exposure Survey

Generated: 2026-05-22T23:00:40.657834+00:00

## Scope

This is an aggregate public GitHub code-search survey. It does not list
repositories, URLs, owners, or paths. Candidate files were fetched only after
matching Rift-relevant prefilter terms.

Prefilter:

- `rewrite`
- `?` in the searched content
- `set`
- numbered capture references `$1` through `$9`
- scopes: `extension:conf, filename:nginx.conf, path:nginx, path:conf.d, path:sites-available, path:sites-enabled, language:Nginx`

High-confidence local classifier:

- same `location` block contains a `rewrite` directive whose replacement
  contains `?`
- the same block contains a `set` directive that consumes a numbered regex
  capture (`$1`..`$9`)

A high-confidence config shape is potentially vulnerable when deployed on an
affected NGINX version. Static GitHub config review cannot prove production
deployment, exposed routing, runtime NGINX version, WAF behavior, or ASLR
bypass feasibility.

## Statistics

| Metric | Count |
| --- | ---: |
| GitHub code-search API calls | 185 |
| Raw search result items before dedupe | 8913 |
| Unique candidate files after dedupe | 3737 |
| Unique files fetched and parsed | 3021 |
| NGINX-looking files | 3015 |
| File-level Rift predicate but not same-location confirmed | 210 |
| High-confidence vulnerable config-shape files | 120 |
| High-confidence files with no obvious static access blocker | 119 |
| High-confidence files only in blocks with static blockers | 1 |
| Total high-confidence vulnerable-shape blocks | 328 |
| Total high-confidence publicish blocks | 327 |
| Total high-confidence blocked blocks | 1 |

## Vulnerability And Exploitability

| Class | Files | Blocks | Interpretation |
| --- | ---: | ---: | --- |
| Confirmed deployed and exploitable from GitHub config alone | 0 | 0 | Static public repo config cannot prove deployment, exposed routing, runtime version, or a working exploit chain. |
| Potentially exploitable config shape, no static access blocker visible | 119 | 327 | Same-location Rift predicate and no obvious `internal`/auth/ACL blocker; exploitable only if deployed on an affected NGINX version and reachable by requests. |
| Vulnerable config shape but statically blocked | 1 | 1 | Same-location Rift predicate exists, but the block shows an obvious static access blocker. |
| Needs manual review | 210 | n/a | Rewrite-with-query and capture-consuming `set` appear in the same file but not in the same parsed location block. |
| NGINX-looking files with no Rift predicate confirmed | 2685 | n/a | Candidate-search hits that did not satisfy the local vulnerable-shape classifier. |

## Static Blockers

| Blocker | Files |
| --- | ---: |
| `internal` | 1 |

## Fetch Failures

| Reason | Count |
| --- | ---: |
| none | 0 |

## Interpretation

- `High-confidence vulnerable config-shape files` is the main exposure count
  for CVE-2026-42945/Rift-style configuration risk.
- `Publicish` means no obvious `internal`, `auth_basic`, deny-all ACL,
  allow/deny ACL, or `satisfy` directive was visible in that same location
  block. It is not proof of internet exposure.
- `File-level predicate` means the ingredients appear in the same file but
  were not proven to be in the same location block by the local parser.
- Actual exploitability still requires an affected NGINX version and a
  reachable request path. Reliable RCE also depends on target runtime
  layout and disclosure/bypass conditions.

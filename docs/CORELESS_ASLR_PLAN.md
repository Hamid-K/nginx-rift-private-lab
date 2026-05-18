# Coreless ASLR Bypass Research Plan

Started: 2026-05-18 00:35:00 CEST
Base commit: `33d22d1`
Branch: `research/coreless-aslr-bypass`

## Goal

Find a practical replacement for the readable crash-core primitive used by the current NGINX Rift lab chain.

Success requires at least one result in each category:

1. A same-worker NGINX memory disclosure candidate that can be exercised in Docker, or a practical coreless brute-force strategy that reaches exploitation in a bounded campaign.
2. A standard Ubuntu and/or standard nginx Docker-image local-file-read vector that leaks enough ASLR-relevant state for this exploit without non-standard permissions.

## Constraints

- Authorized local lab only.
- Do not use target-side shell, Docker exec, SSH, or debugger output as exploit oracle data.
- Docker exec and debuggers may be used only for source audit, instrumentation, and verification of hypotheses.
- Do not rely on readable crash cores for the new solution.
- Keep notes generic and reproducible.
- Prefer standard Ubuntu/nginx or official nginx image behavior when evaluating local-file-read vectors.

## Workstreams

### A. NGINX Source Leak Audit

- Audit the checked-out NGINX source used by the lab image.
- Prioritize response-producing paths in the same worker:
  - rewrite variables and script engine,
  - HTTP/2 request handling,
  - request body buffering,
  - range/header/body filters,
  - error pages and internal redirects,
  - proxy/FastCGI/uwsgi/scgi response parsing,
  - temp-file and sendfile paths.
- For each candidate, record source references, config requirements, request shape, expected leak class, and a Docker test.

### B. Coreless Brute Force

- Measure how many candidates are required when only remote-derived maps/config/build facts are available.
- Bound the campaign to practical limits: roughly 100 attempts when possible, or a time-boxed 1-2 hour campaign.
- Record worker restart behavior, service impact, candidate ordering, and success/failure.

### C. Standard Local-File-Read Disclosure Audit

- Evaluate default Ubuntu and standard nginx Docker image readable files from a web-app UID.
- Focus on disclosures that could expose:
  - nginx worker PID and maps,
  - nginx/libc binary paths and build IDs,
  - heap addresses or request-body/temp-file addresses,
  - process environment and auxv,
  - logs or status files that include pointers,
  - systemd/apport coredump metadata without requiring readable core dumps.
- Record default permissions and whether each vector provides base addresses, heap state, or final target selection.

## Current Hypothesis

Plain local-file-read can often recover process metadata and mapped-file bases when nginx and the web app share a UID and procfs permissions allow it. It probably does not reveal the live heap object contents needed by this exploit unless another disclosure exists. This branch tests that hypothesis instead of assuming it.

## Current Result

The original hypothesis was partly wrong for same-UID procfs configurations where `/proc/<nginx-worker>/mem` is readable at mapped offsets.

- Source audit did not find a direct NGINX response memory leak.
- Static known-offset brute force did not produce proof.
- Same-UID `/proc/<nginx-worker>/mem` through LFI did expose live heap/body contents and replaced the crash-core primitive in Docker.
- The successful coreless exploit uses live memory scanning plus a bounded final candidate campaign.

Remaining work before treating this as broadly real-world:

- Re-test on a real Ubuntu VM with default Yama/procfs policy.
- Re-test against official nginx image patterns with the vulnerable app running as nginx UID 101.
- Done 2026-05-19: add a clean `nginx_rifter.py` mode for proc-mem capability detection and coreless exploitation. The proc-mem method is now the default `nginx_rifter.py` exploit path; the prior core-guided implementation is preserved as `nginx_rifter_core_v2_1.py`.

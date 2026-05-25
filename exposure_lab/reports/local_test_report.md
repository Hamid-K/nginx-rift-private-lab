# Rift Local Exposure Lab Report

Generated: 2026-05-25T19:12:22.683424+00:00

## Scope

This report covers sanitized local Docker simulations generated from public
GitHub config-shape candidates. It does not identify source repositories,
owners, URLs, or paths.

A positive result means the generated local case triggered the Rift
memory-corruption primitive under the vulnerable ASAN/debug-palloc NGINX
image. It is not proof of deployment or full RCE for any public system.

## Corpus Summary

| Metric | Value |
| --- | ---: |
| Sanitized local cases | 129 |
| Unique sanitized semantic fingerprints | 80 |
| Raw GitHub search hits | 9040 |
| Deduplicated candidate references | 3820 |
| GitHub code-search API calls | 187 |

## Run Parameters

| Parameter | Value |
| --- | --- |
| Docker image | `rift-exposure-nginx:asan-amd64` |
| Parallel containers | 10 |
| Trigger payload length | 8192 plus signs |
| Cases tested | 129 |

## Summary

| Status | Count |
| --- | ---: |
| `asan_hit` | 23 |
| `no_trigger` | 106 |

## Trigger Breakdown

By preserved directive order:

| Directive order | ASAN hits | No trigger | Other |
| --- | ---: | ---: | ---: |
| `rewrite_before_set` | 23 | 8 | 0 |
| `set_before_rewrite` | 0 | 98 | 0 |

By rewrite flag:

| Rewrite flag | ASAN hits | No trigger | Other |
| --- | ---: | ---: | ---: |
| `break` | 0 | 50 | 0 |
| `last` | 0 | 18 | 0 |
| `none` | 23 | 8 | 0 |
| `permanent` | 0 | 26 | 0 |
| `redirect` | 0 | 4 | 0 |

## Status Meaning

- `asan_hit`: local generated route produced AddressSanitizer
  heap-buffer-overflow evidence in the vulnerable NGINX build.
- `no_trigger`: the static ingredients were present, but the preserved-order
  local route did not reach the vulnerable execution path under this
  trigger. Common reasons include `set` before `rewrite`, redirect-style
  rewrite flags, or a normal HTTP response path.
- `config_error` or `runner_error`: local harness failure rather than a
  vulnerability conclusion.

## Case Results

| Case | Status | HTTP result | Container status | Evidence |
| --- | --- | --- | --- | --- |
| `case_000001` | `no_trigger` | `HTTP/1.1 200 OK` | `running 0` | trigger returned HTTP/1.1 200 OK |
| `case_000002` | `no_trigger` | `HTTP/1.1 200 OK` | `running 0` | trigger returned HTTP/1.1 200 OK |
| `case_000003` | `no_trigger` | `HTTP/1.1 200 OK` | `running 0` | trigger returned HTTP/1.1 200 OK |
| `case_000004` | `no_trigger` | `HTTP/1.1 200 OK` | `running 0` | trigger returned HTTP/1.1 200 OK |
| `case_000005` | `no_trigger` | `HTTP/1.1 200 OK` | `running 0` | trigger returned HTTP/1.1 200 OK |
| `case_000006` | `no_trigger` | `HTTP/1.1 200 OK` | `running 0` | trigger returned HTTP/1.1 200 OK |
| `case_000007` | `no_trigger` | `HTTP/1.1 200 OK` | `running 0` | trigger returned HTTP/1.1 200 OK |
| `case_000008` | `no_trigger` | `HTTP/1.1 200 OK` | `running 0` | trigger returned HTTP/1.1 200 OK |
| `case_000009` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000010` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000011` | `no_trigger` | `HTTP/1.1 200 OK` | `running 0` | trigger returned HTTP/1.1 200 OK |
| `case_000012` | `asan_hit` | `no_response` | `exited 1` | AddressSanitizer output observed; heap-buffer-overflow observed; container exit/status=exited 1; trigger connection closed without HTTP response |
| `case_000013` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000014` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000015` | `no_trigger` | `HTTP/1.1 301 Moved Permanently` | `running 0` | trigger returned HTTP/1.1 301 Moved Permanently |
| `case_000016` | `asan_hit` | `no_response` | `exited 1` | AddressSanitizer output observed; heap-buffer-overflow observed; container exit/status=exited 1; trigger connection closed without HTTP response |
| `case_000017` | `asan_hit` | `no_response` | `exited 1` | AddressSanitizer output observed; heap-buffer-overflow observed; container exit/status=exited 1; trigger connection closed without HTTP response |
| `case_000018` | `asan_hit` | `no_response` | `exited 1` | AddressSanitizer output observed; heap-buffer-overflow observed; container exit/status=exited 1; trigger connection closed without HTTP response |
| `case_000019` | `asan_hit` | `no_response` | `exited 1` | AddressSanitizer output observed; heap-buffer-overflow observed; container exit/status=exited 1; trigger connection closed without HTTP response |
| `case_000020` | `asan_hit` | `no_response` | `exited 1` | AddressSanitizer output observed; heap-buffer-overflow observed; container exit/status=exited 1; trigger connection closed without HTTP response |
| `case_000021` | `asan_hit` | `no_response` | `exited 1` | AddressSanitizer output observed; heap-buffer-overflow observed; container exit/status=exited 1; trigger connection closed without HTTP response |
| `case_000022` | `asan_hit` | `no_response` | `exited 1` | AddressSanitizer output observed; heap-buffer-overflow observed; container exit/status=exited 1; trigger connection closed without HTTP response |
| `case_000023` | `asan_hit` | `no_response` | `exited 1` | AddressSanitizer output observed; heap-buffer-overflow observed; container exit/status=exited 1; trigger connection closed without HTTP response |
| `case_000024` | `asan_hit` | `no_response` | `exited 1` | AddressSanitizer output observed; heap-buffer-overflow observed; container exit/status=exited 1; trigger connection closed without HTTP response |
| `case_000025` | `asan_hit` | `no_response` | `exited 1` | AddressSanitizer output observed; heap-buffer-overflow observed; container exit/status=exited 1; trigger connection closed without HTTP response |
| `case_000026` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000027` | `asan_hit` | `no_response` | `exited 1` | AddressSanitizer output observed; heap-buffer-overflow observed; container exit/status=exited 1; trigger connection closed without HTTP response |
| `case_000028` | `asan_hit` | `no_response` | `exited 1` | AddressSanitizer output observed; heap-buffer-overflow observed; container exit/status=exited 1; trigger connection closed without HTTP response |
| `case_000029` | `no_trigger` | `HTTP/1.1 301 Moved Permanently` | `running 0` | trigger returned HTTP/1.1 301 Moved Permanently |
| `case_000030` | `no_trigger` | `HTTP/1.1 301 Moved Permanently` | `running 0` | trigger returned HTTP/1.1 301 Moved Permanently |
| `case_000031` | `no_trigger` | `HTTP/1.1 301 Moved Permanently` | `running 0` | trigger returned HTTP/1.1 301 Moved Permanently |
| `case_000032` | `no_trigger` | `HTTP/1.1 200 OK` | `running 0` | trigger returned HTTP/1.1 200 OK |
| `case_000033` | `no_trigger` | `HTTP/1.1 301 Moved Permanently` | `running 0` | trigger returned HTTP/1.1 301 Moved Permanently |
| `case_000034` | `no_trigger` | `HTTP/1.1 301 Moved Permanently` | `running 0` | trigger returned HTTP/1.1 301 Moved Permanently |
| `case_000035` | `no_trigger` | `HTTP/1.1 301 Moved Permanently` | `running 0` | trigger returned HTTP/1.1 301 Moved Permanently |
| `case_000036` | `no_trigger` | `HTTP/1.1 200 OK` | `running 0` | trigger returned HTTP/1.1 200 OK |
| `case_000037` | `no_trigger` | `HTTP/1.1 200 OK` | `running 0` | trigger returned HTTP/1.1 200 OK |
| `case_000038` | `no_trigger` | `HTTP/1.1 200 OK` | `running 0` | trigger returned HTTP/1.1 200 OK |
| `case_000039` | `no_trigger` | `HTTP/1.1 200 OK` | `running 0` | trigger returned HTTP/1.1 200 OK |
| `case_000040` | `no_trigger` | `HTTP/1.1 200 OK` | `running 0` | trigger returned HTTP/1.1 200 OK |
| `case_000041` | `no_trigger` | `HTTP/1.1 200 OK` | `running 0` | trigger returned HTTP/1.1 200 OK |
| `case_000042` | `no_trigger` | `HTTP/1.1 200 OK` | `running 0` | trigger returned HTTP/1.1 200 OK |
| `case_000043` | `no_trigger` | `HTTP/1.1 301 Moved Permanently` | `running 0` | trigger returned HTTP/1.1 301 Moved Permanently |
| `case_000044` | `no_trigger` | `HTTP/1.1 301 Moved Permanently` | `running 0` | trigger returned HTTP/1.1 301 Moved Permanently |
| `case_000045` | `no_trigger` | `HTTP/1.1 301 Moved Permanently` | `running 0` | trigger returned HTTP/1.1 301 Moved Permanently |
| `case_000046` | `asan_hit` | `no_response` | `exited 1` | AddressSanitizer output observed; heap-buffer-overflow observed; container exit/status=exited 1; trigger connection closed without HTTP response |
| `case_000047` | `no_trigger` | `HTTP/1.1 301 Moved Permanently` | `running 0` | trigger returned HTTP/1.1 301 Moved Permanently |
| `case_000048` | `no_trigger` | `HTTP/1.1 301 Moved Permanently` | `running 0` | trigger returned HTTP/1.1 301 Moved Permanently |
| `case_000049` | `no_trigger` | `HTTP/1.1 301 Moved Permanently` | `running 0` | trigger returned HTTP/1.1 301 Moved Permanently |
| `case_000050` | `no_trigger` | `HTTP/1.1 301 Moved Permanently` | `running 0` | trigger returned HTTP/1.1 301 Moved Permanently |
| `case_000051` | `asan_hit` | `no_response` | `exited 1` | AddressSanitizer output observed; heap-buffer-overflow observed; container exit/status=exited 1; trigger connection closed without HTTP response |
| `case_000052` | `asan_hit` | `no_response` | `exited 1` | AddressSanitizer output observed; heap-buffer-overflow observed; container exit/status=exited 1; trigger connection closed without HTTP response |
| `case_000053` | `asan_hit` | `no_response` | `exited 1` | AddressSanitizer output observed; heap-buffer-overflow observed; container exit/status=exited 1; trigger connection closed without HTTP response |
| `case_000054` | `no_trigger` | `HTTP/1.1 301 Moved Permanently` | `running 0` | trigger returned HTTP/1.1 301 Moved Permanently |
| `case_000055` | `no_trigger` | `HTTP/1.1 301 Moved Permanently` | `running 0` | trigger returned HTTP/1.1 301 Moved Permanently |
| `case_000056` | `no_trigger` | `HTTP/1.1 302 Moved Temporarily` | `running 0` | trigger returned HTTP/1.1 302 Moved Temporarily |
| `case_000057` | `no_trigger` | `HTTP/1.1 302 Moved Temporarily` | `running 0` | trigger returned HTTP/1.1 302 Moved Temporarily |
| `case_000058` | `no_trigger` | `HTTP/1.1 301 Moved Permanently` | `running 0` | trigger returned HTTP/1.1 301 Moved Permanently |
| `case_000059` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000060` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000061` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000062` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000063` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000064` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000065` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000066` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000067` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000068` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000069` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000070` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000071` | `no_trigger` | `HTTP/1.1 302 Moved Temporarily` | `running 0` | trigger returned HTTP/1.1 302 Moved Temporarily |
| `case_000072` | `no_trigger` | `HTTP/1.1 200 OK` | `running 0` | trigger returned HTTP/1.1 200 OK |
| `case_000073` | `no_trigger` | `HTTP/1.1 200 OK` | `running 0` | trigger returned HTTP/1.1 200 OK |
| `case_000074` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000075` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000076` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000077` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000078` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000079` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000080` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000081` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000082` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000083` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000084` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000085` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000086` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000087` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000088` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000089` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000090` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000091` | `no_trigger` | `HTTP/1.1 301 Moved Permanently` | `running 0` | trigger returned HTTP/1.1 301 Moved Permanently |
| `case_000092` | `no_trigger` | `HTTP/1.1 301 Moved Permanently` | `running 0` | trigger returned HTTP/1.1 301 Moved Permanently |
| `case_000093` | `no_trigger` | `HTTP/1.1 301 Moved Permanently` | `running 0` | trigger returned HTTP/1.1 301 Moved Permanently |
| `case_000094` | `no_trigger` | `HTTP/1.1 301 Moved Permanently` | `running 0` | trigger returned HTTP/1.1 301 Moved Permanently |
| `case_000095` | `no_trigger` | `HTTP/1.1 301 Moved Permanently` | `running 0` | trigger returned HTTP/1.1 301 Moved Permanently |
| `case_000096` | `no_trigger` | `HTTP/1.1 301 Moved Permanently` | `running 0` | trigger returned HTTP/1.1 301 Moved Permanently |
| `case_000097` | `no_trigger` | `HTTP/1.1 301 Moved Permanently` | `running 0` | trigger returned HTTP/1.1 301 Moved Permanently |
| `case_000098` | `no_trigger` | `HTTP/1.1 301 Moved Permanently` | `running 0` | trigger returned HTTP/1.1 301 Moved Permanently |
| `case_000099` | `no_trigger` | `HTTP/1.1 200 OK` | `running 0` | trigger returned HTTP/1.1 200 OK |
| `case_000100` | `no_trigger` | `HTTP/1.1 200 OK` | `running 0` | trigger returned HTTP/1.1 200 OK |
| `case_000101` | `no_trigger` | `HTTP/1.1 200 OK` | `running 0` | trigger returned HTTP/1.1 200 OK |
| `case_000102` | `no_trigger` | `HTTP/1.1 200 OK` | `running 0` | trigger returned HTTP/1.1 200 OK |
| `case_000103` | `no_trigger` | `HTTP/1.1 200 OK` | `running 0` | trigger returned HTTP/1.1 200 OK |
| `case_000104` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000105` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000106` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000107` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000108` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000109` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000110` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000111` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000112` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000113` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000114` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000115` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000116` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000117` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000118` | `no_trigger` | `HTTP/1.1 301 Moved Permanently` | `running 0` | trigger returned HTTP/1.1 301 Moved Permanently |
| `case_000119` | `asan_hit` | `no_response` | `exited 1` | AddressSanitizer output observed; heap-buffer-overflow observed; container exit/status=exited 1; trigger connection closed without HTTP response |
| `case_000120` | `asan_hit` | `no_response` | `exited 1` | AddressSanitizer output observed; heap-buffer-overflow observed; container exit/status=exited 1; trigger connection closed without HTTP response |
| `case_000121` | `no_trigger` | `HTTP/1.1 302 Moved Temporarily` | `running 0` | trigger returned HTTP/1.1 302 Moved Temporarily |
| `case_000122` | `asan_hit` | `no_response` | `exited 1` | AddressSanitizer output observed; heap-buffer-overflow observed; container exit/status=exited 1; trigger connection closed without HTTP response |
| `case_000123` | `asan_hit` | `no_response` | `exited 1` | AddressSanitizer output observed; heap-buffer-overflow observed; container exit/status=exited 1; trigger connection closed without HTTP response |
| `case_000124` | `asan_hit` | `no_response` | `exited 1` | AddressSanitizer output observed; heap-buffer-overflow observed; container exit/status=exited 1; trigger connection closed without HTTP response |
| `case_000125` | `asan_hit` | `no_response` | `exited 1` | AddressSanitizer output observed; heap-buffer-overflow observed; container exit/status=exited 1; trigger connection closed without HTTP response |
| `case_000126` | `no_trigger` | `HTTP/1.1 200 OK` | `running 0` | trigger returned HTTP/1.1 200 OK |
| `case_000127` | `no_trigger` | `HTTP/1.1 200 OK` | `running 0` | trigger returned HTTP/1.1 200 OK |
| `case_000128` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |
| `case_000129` | `no_trigger` | `HTTP/1.1 404 Not Found` | `running 0` | trigger returned HTTP/1.1 404 Not Found |

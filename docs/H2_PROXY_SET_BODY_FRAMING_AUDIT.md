# HTTP/2 `proxy_set_body` Framing Audit

Started: 2026-05-21
Branch: `research/poolslip-defensive-source-audit`

## Scope

This track validates a concrete source-fixed bug in NGINX HTTP/2 upstream
proxying. It is separate from the Poolslip/default-module target because it
requires a build with `--with-http_v2_module`.

The finding is a protocol-framing bug, not an exploit chain: with
`proxy_set_body $request_body` and `proxy_http_version 2`, the pre-fix code can
send a request body larger than the 24-bit HTTP/2 DATA frame length field as a
single DATA frame. The advertised frame length wraps, and the remaining body
bytes are sent as unframed stream data. A downstream HTTP/2 peer then parses
attacker-controlled body bytes as subsequent frame headers or payload.

## Source Lead

Commit `c24fb259d` (`Proxy: fix large body with proxy_set_body and HTTP/2`)
states that when `proxy_set_body` was used with HTTP/2 and the body exceeded
16 MiB, the 24-bit DATA frame size overflowed. The vulnerable comparison point
is the parent commit `2046b45aa`.

The fix removes the special one-frame body append in
`ngx_http_proxy_v2_create_request()` and sends the configured body through the
normal output path, which fragments DATA frames to the HTTP/2 frame and flow
control limits.

## Lab

Files:

- `env/nginx-h2-header.conf`
- `env/server.py`
- `tools/proxy_v2_set_body_probe.py`

Route:

- Client sends `POST /h2-set-body` with a large request body.
- NGINX uses:
  - `client_body_buffer_size 32m`
  - `client_body_in_single_buffer on`
  - `proxy_pass_request_body off`
  - `proxy_set_body $request_body`
  - `proxy_http_version 2`
- A local raw HTTP/2 capture upstream on `127.0.0.1:19326` records the upstream
  byte stream and reports frame lengths, parse status, and whether an oversized
  or truncated DATA frame stream was observed.

Images:

- Vulnerable: `nginx-h2-setbody-prepatch-amd64-asan`, built from
  `c24fb259d^` / `2046b45aa`, exposed on `127.0.0.1:19363`.
- Fixed control: `nginx-h2-header-1310-amd64-asan`, rebuilt from
  `release-1.31.0` after the fix, exposed on `127.0.0.1:19361`.

## Status

- [x] Identify source-fix lead.
- [x] Add a capture upstream that parses NGINX's proxied HTTP/2 byte stream.
- [x] Build vulnerable pre-fix image.
- [x] Compare against a fixed image.
- [x] Confirm boundary behavior at `16 MiB`, `16 MiB + 1`, and `17 MiB`.
- [ ] Add a minimal packet/transcript artifact if this track is extended.

## Results

Vulnerable pre-fix image:

```text
./tools/proxy_v2_set_body_probe.py --target 127.0.0.1:19363 --size 16777216
preface=yes received=16777378 frames=8 parse=truncated(type=65,len=4276545,remaining=3947554) data_frames=1 data_total=0 max_data=0 oversized_data=false data_lengths=0
verdict     vulnerable-framing
```

```text
./tools/proxy_v2_set_body_probe.py --target 127.0.0.1:19363 --size 16777217
preface=yes received=16777379 frames=8 parse=truncated(type=65,len=4276545,remaining=3947554) data_frames=1 data_total=1 max_data=1 oversized_data=false data_lengths=1
verdict     vulnerable-framing
```

```text
./tools/proxy_v2_set_body_probe.py --target 127.0.0.1:19363 --size 17825792
preface=yes received=17825954 frames=8 parse=truncated(type=65,len=4276545,remaining=3947554) data_frames=1 data_total=1048576 max_data=1048576 oversized_data=true data_lengths=1048576
verdict     vulnerable-framing
```

Fixed comparison image:

```text
./tools/proxy_v2_set_body_probe.py --target 127.0.0.1:19361 --size 16777216
preface=yes received=65724 frames=8 parse=ok data_frames=4 data_total=65535 max_data=16384 oversized_data=false data_lengths=16384,16384,16384,16383
verdict     fixed-framing
```

```text
./tools/proxy_v2_set_body_probe.py --target 127.0.0.1:19361 --size 17825792
preface=yes received=65724 frames=8 parse=ok data_frames=4 data_total=65535 max_data=16384 oversized_data=false data_lengths=16384,16384,16384,16383
verdict     fixed-framing
```

## Interpretation

At exactly `16 MiB`, the vulnerable DATA frame length wraps to zero. At
`16 MiB + 1`, it wraps to one. At `17 MiB`, it advertises a 1 MiB DATA frame,
which exceeds the normal 16 KiB DATA frame size and still leaves the remaining
body bytes as unframed data. This matches the upstream fix note and proves a
remote-triggered framing/injection bug in the pre-fix HTTP/2 upstream path.

The fixed build fragments the request body through the regular output chain,
so the capture upstream sees clean DATA frames no larger than `16384` bytes.

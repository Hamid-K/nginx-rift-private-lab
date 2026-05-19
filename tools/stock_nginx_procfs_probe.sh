#!/usr/bin/env bash
set -euo pipefail

image="${1:-nginx:stable}"

docker run --rm -i "$image" sh -s <<'SH'
set -eu

nginx >/tmp/nginx-start.log 2>&1
sleep 0.5

master="$(cat /var/run/nginx.pid)"
children="$(cat "/proc/$master/task/$master/children")"
worker="${children%% *}"
status_uid="$(awk '/^Uid:/ {print}' "/proc/$worker/status")"

echo "image: ${HOSTNAME}"
nginx -v 2>&1
echo "master pid: $master"
echo "worker pid: $worker"
echo "worker uid: $status_uid"
echo

echo "[same uid: nginx]"
same_maps="$(runuser -u nginx -- sh -c "head -1 /proc/$worker/maps" 2>&1)" || {
    echo "maps: denied"
    echo "$same_maps"
    exit 0
}
echo "maps: ok"
echo "maps first: $same_maps"

start_hex="${same_maps%%-*}"
start_dec="$(perl -e 'print hex(shift)' "$start_hex")"
same_mem="$(
    runuser -u nginx -- sh -c \
        "dd if=/proc/$worker/mem bs=1 skip=$start_dec count=4 iflag=skip_bytes,count_bytes 2>/tmp/proc_mem_same.err | od -An -tx1; rc=\$?; echo rc=\$rc; cat /tmp/proc_mem_same.err"
)" || true
echo "mem first bytes:"
echo "$same_mem"
echo

if id nobody >/dev/null 2>&1; then
    echo "[different uid: nobody]"
    diff_maps="$(runuser -u nobody -- sh -c "head -1 /proc/$worker/maps" 2>&1)" && diff_maps_rc=0 || diff_maps_rc=$?
    echo "maps rc: $diff_maps_rc"
    echo "$diff_maps"
    diff_mem="$(
        runuser -u nobody -- sh -c \
            "dd if=/proc/$worker/mem bs=1 skip=$start_dec count=4 iflag=skip_bytes,count_bytes 2>/tmp/proc_mem_diff.err | od -An -tx1; rc=\$?; echo rc=\$rc; cat /tmp/proc_mem_diff.err"
    )" || true
    echo "mem first bytes:"
    echo "$diff_mem"
fi
SH

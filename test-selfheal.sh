#!/bin/bash
# Verify TC eBPF self-heal: simulates a VyOS commit wiping the clsact qdisc,
# then a link flap, and checks the daemon re-attaches without duplicating filters.
# Usage: sudo ./test-selfheal.sh
set -e
cd "$(dirname "$0")"

cleanup() {
	[ -n "$FFIPID" ] && kill "$FFIPID" 2>/dev/null
	ip link del ffi-test 2>/dev/null
	true
}
trap cleanup EXIT

ip link del ffi-test 2>/dev/null || true
ip link add ffi-test type veth peer name ffi-peer
ip link set ffi-test up
ip link set ffi-peer up

./fastflowips -interface ffi-test -interval 2s -verbose >/tmp/ffi-selfheal.log 2>&1 &
FFIPID=$!
sleep 4

echo "=== 1. filters after start ==="
tc filter show dev ffi-test ingress

echo "=== 2. simulating VyOS commit: tc qdisc del dev ffi-test clsact ==="
tc qdisc del dev ffi-test clsact
sleep 5
echo "--- filters after self-heal (must show count_flows again) ---"
tc filter show dev ffi-test ingress
tc filter show dev ffi-test egress

echo "=== 3. link flap ==="
ip link set ffi-test down
sleep 1
ip link set ffi-test up
sleep 5
ING=$(tc filter show dev ffi-test ingress | grep -c count_flows_ingress || true)
EG=$(tc filter show dev ffi-test egress | grep -c count_flows_egress || true)
echo "--- filter count after flap: ingress=$ING egress=$EG (must be 1/1, no duplicates) ---"

echo "=== daemon log ==="
grep -E "missing|Re-attach|iteration" /tmp/ffi-selfheal.log || true

if [ "$ING" = 1 ] && [ "$EG" = 1 ] && grep -q "re-attached" /tmp/ffi-selfheal.log; then
	echo "PASS"
else
	echo "FAIL (full log: /tmp/ffi-selfheal.log)"
	exit 1
fi

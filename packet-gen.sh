#!/bin/bash

# packet-gen.sh - Simple packet generator
# Usage: ./packet-gen.sh <interface> [pps] [destination]

INTERFACE="$1"
PPS="${2:-1000}"
TARGET="${3:-192.0.2.1}"

[ -z "$INTERFACE" ] && { echo "Usage: $0 <interface> [pps] [destination]"; exit 1; }
[ "$EUID" -ne 0 ] && { echo "Need root"; exit 1; }

echo "Generating $PPS pps to $TARGET via $INTERFACE (Ctrl+C to stop)"

trap 'echo "Stopped"; exit 0' INT

while true; do
    ping -c 1 -W 0.01 -I "$INTERFACE" "$TARGET" &>/dev/null &
    sleep 0.01
done

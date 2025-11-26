#!/bin/bash
# test.sh - sanity test for FastFlowIPs metrics with and without network filters
# Usage: sudo ./test.sh <interface> ["networks (CIDR list)"] [pps]
# Example: sudo ./test.sh eth0 "10.0.0.0/24" 2000

set -euo pipefail

IFACE=${1:-}
FILTER_NETS=${2:-}
PPS=${3:-2000}
TARGET_IP=${TARGET_IP:-192.0.2.1}
INTERVAL=${INTERVAL:-2}
DURATION=${DURATION:-12}
PKT_SIZE_BYTES=${PKT_SIZE_BYTES:-128}  # approximate packet size for expected Mbps calc
TOLERANCE=${TOLERANCE:-0.20}
FASTFLOW_BINARY=./fastflowips
PACKET_GEN=./packet-gen.sh

calc_expected_mbps() {
    local pps="$1"
    awk -v p="$pps" -v sz="$PKT_SIZE_BYTES" 'BEGIN { printf("%.4f", (p * sz * 8) / 1000000.0) }'
}

EXPECTED_PPS_RX=${EXPECTED_PPS_RX:-$PPS}
EXPECTED_PPS_TX=${EXPECTED_PPS_TX:-$PPS}
EXPECTED_MBPS_RX=${EXPECTED_MBPS_RX:-$(calc_expected_mbps "$EXPECTED_PPS_RX")}
EXPECTED_MBPS_TX=${EXPECTED_MBPS_TX:-$(calc_expected_mbps "$EXPECTED_PPS_TX")}

if [[ -z "$IFACE" ]]; then
    echo "Usage: sudo $0 <interface> [\"networks\"] [pps]" >&2
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (needs tc + raw sockets)" >&2
    exit 1
fi

if [[ ! -x $PACKET_GEN ]]; then
    echo "Missing packet generator: $PACKET_GEN" >&2
    exit 1
fi

if [[ ! -x $FASTFLOW_BINARY ]]; then
    echo "Missing FastFlowIPs binary ($FASTFLOW_BINARY). Build it before running this script." >&2
    exit 1
fi

if ! ip link show "$IFACE" >/dev/null 2>&1; then
    echo "Interface '$IFACE' not found. Available interfaces:" >&2
    ip -o link show | awk -F': ' '{print "  - "$2}' >&2
    exit 1
fi

cleanup() {
    for pid in "${PIDS[@]:-}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    rm -f "${LOG_FILES[@]:-}"
}

compare_metric() {
    local label="$1"
    local measured="$2"
    local expected="$3"
    local tolerance="$4"

    printf "[+] %-7s measured: %s (expected ≈ %s)\n" "$label" "$measured" "$expected"
    if awk -v e="$expected" 'BEGIN {exit !(e>0)}'; then
        awk -v meas="$measured" -v exp="$expected" -v tol="$tolerance" 'BEGIN {
            if (exp > 0) {
                diff = (meas - exp) / exp * 100;
                printf("    Δ = %.2f%%\n", diff);
                if (diff/100 > tol || diff/100 < -tol)
                    printf("    [!] Outside ±%.0f%% tolerance\n", tol*100);
            }
        }'
    fi
}

extract_metrics() {
    local log_file="$1"
    awk '/srcIP/{header=NR; next}
         NR>header && $3 ~ /^[0-9.]+$/ {pps_rx=$3; pps_tx=$4; mbps_rx=$5; mbps_tx=$6}
         END { if (pps_rx!="") printf "%s %s %s %s", pps_rx, pps_tx, mbps_rx, mbps_tx }' "$log_file"
}

check_metrics() {
    local label="$1"
    local log_file="$2"
    local expected_pps_rx="$3"
    local expected_pps_tx="$4"
    local expected_mbps_rx="$5"
    local expected_mbps_tx="$6"

    local metrics
    metrics=$(extract_metrics "$log_file")
    if [[ -z "$metrics" ]]; then
        echo "[!] $label: unable to parse PPS/Mbps rows (log: $log_file)" >&2
        return
    fi

    read -r measured_pps_rx measured_pps_tx measured_mbps_rx measured_mbps_tx <<<"$metrics"

    compare_metric "PPS RX" "$measured_pps_rx" "$expected_pps_rx" "$TOLERANCE"
    compare_metric "PPS TX" "$measured_pps_tx" "$expected_pps_tx" "$TOLERANCE"
    compare_metric "Mbps RX" "$measured_mbps_rx" "$expected_mbps_rx" "$TOLERANCE"
    compare_metric "Mbps TX" "$measured_mbps_tx" "$expected_mbps_tx" "$TOLERANCE"
}

run_test_case() {
    local label="$1"
    local networks="$2"
    local target_ip="$3"
    local expected_pps_rx="$4"
    local expected_pps_tx="$5"
    local expected_mbps_rx="$6"
    local expected_mbps_tx="$7"
    local log_file
    log_file=$(mktemp)
    LOG_FILES+=("$log_file")

    echo "[+] Starting FastFlowIPs ($label)"
    local cmd=("$FASTFLOW_BINARY" -interface "$IFACE" -interval "${INTERVAL}s" -show-stats -ban-pps-rx 0 -ban-pps-tx 0)
    if [[ -n "$networks" ]]; then
        cmd+=( -networks "$networks" )
    fi
    "${cmd[@]}" >"$log_file" 2>&1 &
    local fastflow_pid=$!
    PIDS+=("$fastflow_pid")

    sleep 3
    if ! kill -0 "$fastflow_pid" >/dev/null 2>&1; then
        echo "[!] FastFlowIPs exited prematurely for $label. Log output:" >&2
        cat "$log_file" >&2
        exit 1
    fi

    echo "[+] Launching packet generator ($PPS pps to $target_ip)"
    "$PACKET_GEN" "$IFACE" "$PPS" "$target_ip" >/dev/null 2>&1 &
    local gen_pid=$!
    PIDS+=("$gen_pid")

    sleep "$DURATION"
    echo "[+] Stopping packet generator"
    kill "$gen_pid" >/dev/null 2>&1 || true
    sleep 3

    echo "[+] Stopping FastFlowIPs"
    kill "$fastflow_pid" >/dev/null 2>&1 || true
    wait "$fastflow_pid" 2>/dev/null || true

    echo "[+] Sample output for $label:"
    grep -E "(srcIP|ppsRX|mbpsRX)" -n "$log_file" | tail -n 40 || tail -n 40 "$log_file"

    check_metrics "$label" "$log_file" \
        "$expected_pps_rx" "$expected_pps_tx" \
        "$expected_mbps_rx" "$expected_mbps_tx"
    echo "[+] Full log saved at $log_file"
}

trap cleanup EXIT
PIDS=()
LOG_FILES=()

run_test_case "all traffic" "" "$TARGET_IP" \
    "$EXPECTED_PPS_RX" "$EXPECTED_PPS_TX" \
    "$EXPECTED_MBPS_RX" "$EXPECTED_MBPS_TX"

if [[ -n "$FILTER_NETS" ]]; then
    run_test_case "filtered ($FILTER_NETS)" "$FILTER_NETS" "$TARGET_IP" \
        "$EXPECTED_PPS_RX" "$EXPECTED_PPS_TX" \
        "$EXPECTED_MBPS_RX" "$EXPECTED_MBPS_TX"
else
    echo "[!] No networks provided, skipping filtered test"
fi

echo "[+] Tests complete"

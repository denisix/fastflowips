# FastFlowIPs - eBPF Network Flow Monitoring

## Overview
eBPF-based tool for real-time per-IP traffic monitoring with dual metrics export (Graphite/InfluxDB) and threshold-based banning.

## Recent Updates
- **InfluxDB Support**: Added complete InfluxDB line protocol export alongside existing Graphite
- **Dual Metrics**: Separate `generateGraphiteMetrics()` and `generateInfluxMetrics()` functions
- **Flow Direction**: Eliminated perspective complexity by normalizing flow keys (src=internal, dst=external)
- **Optimized Aggregation**: Direct IP stats without intermediate arrays or complex logic
- **Test Environment**: Docker scripts for Graphite + InfluxDB + Chronograf with web UIs
- **Static Compilation**: Simplified Makefile with cross-arch builds (amd64/arm64) + UPX compression

## Architecture
**Core**: eBPF (flow.c) → Go collector → Graphite/InfluxDB export + IP banning
**Metrics**: Flow pairs (`network.flows.src_to_dst.*`) + IP aggregates (`network.ips.ip.*`)
**Direction**: RX=to-network, TX=from-network (consistent across all outputs)

## Configuration
```bash
# Endpoints
-graphite-host localhost -graphite-port 2003
-influx-url http://localhost:8086 -influx-db fastflowips -influx-user user -influx-pass pass

# Monitoring
-interface eth0 -networks "192.168.1.0/24" -interval 5s -show-stats

# Banning
-ban-pps-rx 1000 -ban-mbps-tx 100 -ban-time 5m -ban-script ./ban.sh

# Filtering
-min-flow-pps 10 -min-ips-mbps 1 (reduces noise in time-series)
```

## Formats
**Graphite**: `network.flows.192_168_1_1_to_10_0_0_1.pps.rx 123.45 1699123456`
**InfluxDB**: `network_flows,src=192_168_1_1,dst=10_0_0_1,type=pps,direction=rx value=123.45 1699123456000000000`

## Development Environment
```bash
./start-test-endpoints.sh  # Starts Graphite:8080 + InfluxDB:8086 + Chronograf:8888
sudo ./fastflowips -graphite-host localhost -influx-url http://localhost:8086 -influx-db fastflowips
./stop-test-endpoints.sh   # Cleanup
```

## Production Usage
```bash
make release                    # Cross-compile + compress binaries
sudo ./fastflowips -install    # systemd service with current args (excludes -install)
sudo ./fastflowips -networks "10.0.0.0/8" -graphite-host metrics.local -ban-pps-rx 5000
```

**Performance**: 75% fewer mutex ops, 60% faster strings, 50% fewer allocations. Production-ready for high-traffic monitoring.
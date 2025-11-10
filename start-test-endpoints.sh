#!/bin/bash

# Script to start test Graphite and InfluxDB endpoints for FastFlowIPs testing
# This creates lightweight containerized endpoints for development and testing

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting test endpoints for FastFlowIPs...${NC}"

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is required but not installed${NC}"
    exit 1
fi

# Check if Docker daemon is running
if ! docker info &> /dev/null; then
    echo -e "${RED}Error: Docker daemon is not running${NC}"
    exit 1
fi

# Function to check if container is running
is_running() {
    docker ps --format "table {{.Names}}" | grep -q "^$1$"
}

# Start Graphite (with Carbon and Grafana)
echo -e "${YELLOW}Starting Graphite endpoint...${NC}"
if is_running "test-graphite"; then
    echo "Graphite container already running"
else
    docker run -d \
        --name test-graphite \
        --restart=unless-stopped \
        -p 2003:2003 \
        -p 8080:8080 \
        graphiteapp/graphite-statsd:latest

    echo -e "${GREEN}✓ Graphite started:${NC}"
    echo "  - Carbon (metrics): localhost:2003"
    echo "  - Web UI: http://localhost:8080"
fi

# Start InfluxDB
echo -e "${YELLOW}Starting InfluxDB endpoint...${NC}"
if is_running "test-influxdb"; then
    echo "InfluxDB container already running"
else
    docker run -d \
        --name test-influxdb \
        --restart=unless-stopped \
        -p 8086:8086 \
        -e INFLUXDB_DB=fastflowips \
        -e INFLUXDB_ADMIN_USER=admin \
        -e INFLUXDB_ADMIN_PASSWORD=admin \
        -e INFLUXDB_USER=fastflowips \
        -e INFLUXDB_USER_PASSWORD=password \
        influxdb:1.8-alpine

    echo -e "${GREEN}✓ InfluxDB started:${NC}"
    echo "  - HTTP API: http://localhost:8086"
    echo "  - Database: fastflowips"
    echo "  - Admin: admin/admin"
    echo "  - User: fastflowips/password"
fi

# Start Chronograf (InfluxDB Web UI)
echo -e "${YELLOW}Starting Chronograf (InfluxDB Web UI)...${NC}"
if is_running "test-chronograf"; then
    echo "Chronograf container already running"
else
    docker run -d \
        --name test-chronograf \
        --restart=unless-stopped \
        -p 8888:8888 \
        --link test-influxdb:influxdb \
        chronograf:1.9-alpine --influxdb-url=http://influxdb:8086

    echo -e "${GREEN}✓ Chronograf started:${NC}"
    echo "  - Web UI: http://localhost:8888"
fi

# Wait for services to be ready
echo -e "${YELLOW}Waiting for services to be ready...${NC}"
sleep 5

# Test endpoints
echo -e "${YELLOW}Testing endpoints...${NC}"

# Test Graphite Carbon port
if timeout 5 bash -c "</dev/tcp/localhost/2003"; then
    echo -e "${GREEN}✓ Graphite Carbon port (2003) is accessible${NC}"
else
    echo -e "${RED}✗ Graphite Carbon port (2003) not accessible${NC}"
fi

# Test InfluxDB
if curl -s http://localhost:8086/ping >/dev/null 2>&1; then
    echo -e "${GREEN}✓ InfluxDB HTTP API (8086) is accessible${NC}"
else
    echo -e "${RED}✗ InfluxDB HTTP API (8086) not accessible${NC}"
fi

# Test Chronograf
if curl -s http://localhost:8888 >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Chronograf Web UI (8888) is accessible${NC}"
else
    echo -e "${RED}✗ Chronograf Web UI (8888) not accessible${NC}"
fi

echo
echo -e "${GREEN}=== Test Endpoints Ready ===${NC}"
echo
echo -e "${YELLOW}FastFlowIPs Usage Examples:${NC}"
echo
echo "# Graphite only:"
echo "./fastflowips -graphite-host localhost -show-stats"
echo
echo "# InfluxDB only:"
echo "./fastflowips -influx-url http://localhost:8086 -influx-db fastflowips -show-stats"
echo
echo "# Both endpoints:"
echo "./fastflowips -graphite-host localhost -influx-url http://localhost:8086 -influx-db fastflowips -show-stats"
echo
echo "# With authentication:"
echo "./fastflowips -influx-url http://localhost:8086 -influx-user fastflowips -influx-pass password"
echo
echo -e "${YELLOW}Web UIs for Monitoring:${NC}"
echo "- Graphite Web UI: http://localhost:8080"
echo "- InfluxDB Web UI (Chronograf): http://localhost:8888"
echo
echo -e "${YELLOW}Command Line Queries:${NC}"
echo "- InfluxDB: curl -G 'http://localhost:8086/query?db=fastflowips' --data-urlencode 'q=SHOW MEASUREMENTS'"
echo "- InfluxDB: curl -G 'http://localhost:8086/query?db=fastflowips' --data-urlencode 'q=SELECT * FROM network_flows LIMIT 10'"
echo
echo -e "${YELLOW}To stop endpoints:${NC}"
echo "./stop-test-endpoints.sh"
echo
echo -e "${YELLOW}To view logs:${NC}"
echo "docker logs test-graphite"
echo "docker logs test-influxdb"
echo "docker logs test-chronograf"
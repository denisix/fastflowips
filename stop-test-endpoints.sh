#!/bin/bash

# Script to stop test Graphite and InfluxDB endpoints

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Stopping test endpoints...${NC}"

# Function to stop and remove container
stop_container() {
    local name=$1
    if docker ps -a --format "table {{.Names}}" | grep -q "^$name$"; then
        echo -e "${YELLOW}Stopping $name...${NC}"
        docker stop "$name" >/dev/null 2>&1 || true
        docker rm "$name" >/dev/null 2>&1 || true
        echo -e "${GREEN}✓ $name stopped and removed${NC}"
    else
        echo "$name container not found"
    fi
}

# Stop containers
stop_container "test-graphite"
stop_container "test-chronograf"
stop_container "test-influxdb"

echo -e "${GREEN}All test endpoints stopped${NC}"